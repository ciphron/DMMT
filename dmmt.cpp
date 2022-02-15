/* Distributed Mulit-Message Threshold (DMMT) */

#include "dmmt.h"

#include <gcrypt.h>
#include <NTL/GF2X.h>
#include <NTL/GF2EX.h>
#include <NTL/mat_GF2E.h>

using namespace NTL;

enum {
    TAG_DERIV_PARAM = 0x0ADA1815
};


struct dmmt {
    size_t key_size;
    size_t block_size;
    int algo;
};

struct dmmt_dom {
    dmmt_t *d;
    uint8_t *tag;
    unsigned int threshold;
    gcry_cipher_hd_t ctr_handle;
    GF2EX polynomial;
};


dmmt_stat_t enc_ecb_blk(dmmt_t *d, uint8_t *in, uint8_t *out);
void fill_block_with_int(dmmt_t *d, uint64_t v, uint8_t *out);
void xor_block_with_int(dmmt_t *d, uint64_t v, uint8_t *out);
void fill_GF2X_from_bytes(GF2X &f, const uint8_t *bytes, size_t num_bytes);
int conv_GF2X_to_bytes(const GF2X &f, long max_len, uint8_t *out);



/* ############################################################################
 * # DMMT system 
 * ############################################################################
 */

dmmt_t *dmmt_create(const char *block_cipher, size_t block_size,
                    size_t key_len_bits, dmmt_stat_t *status)
{

    int algo = GCRY_CIPHER_NONE;
    dmmt_t *d = NULL;

    if (!strcmp(block_cipher, "AES")) {
        if (block_size == 16 && key_len_bits == 128)
            algo = GCRY_CIPHER_AES128;
        else
            *status = DMMT_STAT_UNSUPPORTED_CIPHER_PARAMS;
    }
    else
        *status = DMMT_STAT_UNSUPPORTED_CIPHER;

    if (algo != GCRY_CIPHER_NONE) {
        d = (dmmt_t*)malloc(sizeof(dmmt_t));

        d->algo = algo;
        d->key_size = (key_len_bits + 7) / 8;
        d->block_size = block_size;

        /*
         * Modulus for GF(2^128) is set to x^128 + x^7 + x^2 + x + 1.
         * At the moment, only AES-128 is supported so this suffices .
         * However it is global. TODO: change this.
         */
        GF2X modulus;
        SetCoeff(modulus, 128);
        SetCoeff(modulus, 7);
        SetCoeff(modulus, 2);
        SetCoeff(modulus, 1);
        SetCoeff(modulus, 0);
        GF2E::init(modulus);


        *status = DMMT_STAT_OK;
    }
    else
        *status = DMMT_STAT_INTERNAL_ERROR;

    return d;
}

dmmt_dom_t *dmmt_new_dom_from_key(dmmt_t *d, const uint8_t *master_key,
                                  unsigned int threshold, dmmt_stat_t *stat)
{
    gcry_cipher_hd_t h_ecb;

    if (gcry_cipher_open(&h_ecb, d->algo, GCRY_CIPHER_MODE_ECB,
                         GCRY_CIPHER_SECURE) != 0) {
        *stat = DMMT_STAT_INTERNAL_ERROR;
        return NULL;
    }

    /* Temporary buffers and variables */
    uint8_t *ibuf = (uint8_t*)malloc(d->block_size);
    uint8_t *obuf = (uint8_t*)gcry_malloc_secure(d->block_size);
    GF2E coeff;
    GF2X coeff_poly;
    
    /* New Domain */
    dmmt_dom_t *dom = (dmmt_dom_t*)gcry_malloc_secure(sizeof(dmmt_dom_t));
    dom->d = d;
    dom->threshold = threshold;
    
    /* Generate Tag */
    uint8_t *tag = (uint8_t*)malloc(d->block_size);
    gcry_cipher_setkey(h_ecb, master_key, d->key_size);
    fill_block_with_int(d, TAG_DERIV_PARAM, ibuf);
    gcry_cipher_encrypt(h_ecb, tag, d->block_size, ibuf, d->block_size);
    dom->tag = tag;

    /* Copy tag to input buf */
    memcpy(ibuf, tag, d->block_size);

    /* Generate secret key */
    gcry_cipher_encrypt(h_ecb, obuf, d->block_size, ibuf, d->block_size);

    /* Setup cipher handle with secret key */
    gcry_cipher_open(&dom->ctr_handle, d->algo, GCRY_CIPHER_MODE_CTR,
                     GCRY_CIPHER_SECURE); 
    gcry_cipher_setkey(dom->ctr_handle, obuf, d->key_size);

    /* Set secret as constant term of polynomial */
    fill_GF2X_from_bytes(coeff_poly, obuf, d->block_size);
    conv(coeff, coeff_poly);
    SetCoeff(dom->polynomial, 0, coeff);
    
    /* Derive the coefficents using the block cipher */
    uint64_t i;
    for (i = 1; i < threshold; i++) {
        /* XOR in next counter value */
        xor_block_with_int(d, i ^ (i - 1), ibuf);

        gcry_cipher_encrypt(h_ecb, obuf, d->block_size, ibuf, d->block_size);
        fill_GF2X_from_bytes(coeff_poly, obuf, d->block_size);
        conv(coeff, coeff_poly);
        SetCoeff(dom->polynomial, i, coeff);
    }

    /* Cleanup */
    gcry_cipher_close(h_ecb);
    free(ibuf);
    gcry_free(obuf);

    *stat = DMMT_STAT_OK;

    return dom;
}


dmmt_dom_t *dmmt_new_dom_from_shares(dmmt_t *d, const uint8_t *tag,
                                     unsigned int threshold,
                                     const uint8_t * const *shares,
                                     size_t n_shares, dmmt_stat_t *stat)
{
    if (n_shares < threshold) {
        *stat = DMMT_STAT_BELOW_THRESHOLD;
        return NULL;
    }

    /* New Domain */
    dmmt_dom_t *dom = (dmmt_dom_t*)gcry_malloc_secure(sizeof(dmmt_dom_t));
    dom->d = d;
    dom->threshold = threshold;
    
    /* Copy Tag */
    uint8_t *tag_copy = (uint8_t*)malloc(d->block_size);
    memcpy(tag_copy, tag, d->block_size);
    dom->tag = tag_copy;

    GF2X f;
    GF2E x;
    GF2E y;
    GF2E coeff;
    
    vec_GF2E yvec;
    vec_GF2E row;

    mat_GF2E V;
    V.SetDims(threshold, threshold);

    yvec.SetLength(threshold);
    row.SetLength(threshold);

    for (size_t i = 0; i < threshold; i++) {
        const uint8_t *share = shares[i];
        size_t j;

        /* Read x */
        fill_GF2X_from_bytes(f, share, d->block_size);
        conv(x, f);

        /* Populate row of Vandermonde matrix */
        conv(coeff, 1);
        for (j = 0; j < threshold; j++) {
            row[j] = coeff;
            coeff *= x;
        }
        

        V[i] = row; /* Set row */
        
        /* Read y */
        fill_GF2X_from_bytes(f, share + d->block_size, d->block_size);
        conv(yvec[i], f);
    }

    mat_GF2E Vinv;
    inv(Vinv, V);
    vec_GF2E rvec = Vinv * yvec;

    for (size_t i = 0; i < threshold; i++)
        SetCoeff(dom->polynomial, i, rvec[i]);

    uint8_t *skey = (uint8_t*)gcry_malloc_secure(d->key_size);
    memset(skey, 0, d->block_size);
    conv_GF2X_to_bytes(rep(rvec[0]), d->block_size * 8, skey);

    /* Setup cipher handle with secret key */
    gcry_cipher_open(&dom->ctr_handle, d->algo, GCRY_CIPHER_MODE_CTR,
                     GCRY_CIPHER_SECURE); 
    gcry_cipher_setkey(dom->ctr_handle, skey, d->key_size);


    /* Cleanup */
    gcry_free(skey);


    *stat = DMMT_STAT_OK;

    return dom;
}

dmmt_stat_t dmmt_free(dmmt_t *d)
{
    if (d != NULL)
        free(d);

    return DMMT_STAT_OK;
}



/* ############################################################################
 * # Domain
 * ############################################################################
 */

dmmt_stat_t dmmt_dom_gen_share(dmmt_dom_t *dom, uint8_t *share_out)
{
    const dmmt_t *d = dom->d;
    uint8_t *buf = (uint8_t*)malloc(d->block_size);
    dmmt_stat_t stat = DMMT_STAT_INTERNAL_ERROR;

    /* Create random x to evaluate at (also first component of share) */
    GF2E x;
    GF2X coeff_poly;
    gcry_create_nonce(buf, d->block_size);
    fill_GF2X_from_bytes(coeff_poly, buf, d->block_size);
    conv(x, coeff_poly);

    /* Evaluate polynomial at x */
    GF2E y;
    eval(y, dom->polynomial, x);

    /* Write share */
    memset(share_out, 0, d->block_size * 2);
    int nb = conv_GF2X_to_bytes(rep(x), d->block_size * 8, share_out);
    if (nb > 0) {
        int nb = conv_GF2X_to_bytes(rep(y), d->block_size * 8,
                                    share_out + d->block_size);

        if (nb > 0) 
            stat = DMMT_STAT_OK;
    }

    /* Cleanup */
    free(buf);

    return DMMT_STAT_OK;
}

const uint8_t *dmmt_dom_tag(dmmt_dom_t *dom)
{
    return dom->tag;
}

/* NOT THREAD SAFE - one encryption per domain at one time */
dmmt_stat_t dmmt_dom_encrypt(dmmt_dom_t *dom, const uint8_t *in, size_t in_size, uint8_t *out, size_t out_size)
{
    const dmmt_t *d = dom->d;

    /* IV */
    if (out_size < d->block_size)
        return DMMT_STAT_UNDERSIZED_BUFFER;

    gcry_create_nonce(out, d->block_size);
    gcry_cipher_setctr(dom->ctr_handle, out, d->block_size);
    
    /* Encrypt (skip over IV in the output buffer) */
    if (gcry_cipher_encrypt(dom->ctr_handle, out + d->block_size, out_size - d->block_size, in, in_size) != 0)
        return DMMT_STAT_INTERNAL_ERROR;

    return DMMT_STAT_OK;
}

/* NOT THREAD SAFE - one decryption per domain at one time */
dmmt_stat_t dmmt_dom_decrypt(dmmt_dom_t *dom, const uint8_t *in, size_t in_size, uint8_t *out, size_t out_size)
{
    const dmmt_t *d = dom->d;

    /* IV */
    if (in_size < d->block_size)
        return DMMT_STAT_UNDERSIZED_BUFFER;

    gcry_cipher_setctr(dom->ctr_handle, in, d->block_size);
    
    /* Decrypt (skip over IV in the input buffer) */
    if (gcry_cipher_decrypt(dom->ctr_handle, out, out_size, in + d->block_size, in_size - d->block_size) != 0)
        return DMMT_STAT_INTERNAL_ERROR;
    
    return DMMT_STAT_OK;
}


dmmt_stat_t dmmt_dom_free(dmmt_dom_t *dom)
{
    if (dom != NULL) {
        gcry_cipher_close(dom->ctr_handle);
        free(dom->tag);
        gcry_free(dom);
    }

    return DMMT_STAT_OK;
}



/* ############################################################################
 * # Utilities
 * ############################################################################
 */


inline void fill_block_with_int(dmmt_t *d, uint64_t v, uint8_t *out)
{
    const size_t sz = (d->block_size < sizeof(v)) ? d->block_size : sizeof(v);
    size_t i;

    for (i = 1; i <= sz; i++) {
        out[d->block_size - i] = v & 0xFF;
        v >>= 8;
    }

    for (; i <= d->block_size; i++)
        out[d->block_size - i] = 0;
}

inline void xor_block_with_int(dmmt_t *d, uint64_t v, uint8_t *out)
{
    const size_t sz = (d->block_size < sizeof(v)) ? d->block_size : sizeof(v);

    for (size_t i = 1; i <= sz; i++) {
        out[d->block_size - i] ^= v & 0xFF;
        v >>= 8;
    }
}

inline void fill_GF2X_from_bytes(GF2X &f, const uint8_t *bytes, size_t num_bytes)
{
    size_t bitn = 0;

    for (size_t i = 0; i < num_bytes; i++) {
        uint8_t b = bytes[i];

        for (size_t j = 0; j < 8; j++) {
            SetCoeff(f, bitn++, b & 0x01);
            b >>= 1;
        }
    }
}

/** Returns the number of BITS written */
inline int conv_GF2X_to_bytes(const GF2X &f, long max_len, uint8_t *out)
{
    size_t i;
    size_t j;
    size_t bitn = 0;
    const long lenf = deg(f) + 1;
    const long len = (lenf < max_len) ? lenf : max_len;

    if (len < 0)
        return -1;

    const size_t count = (size_t)len;
    const size_t nbytes = count / 8;
    uint8_t b;
    
    for (i = 0; i < nbytes; i++) {
        b = 0;

        for (j = 0; j < 8; j++) {
            b |= rep(coeff(f, bitn++)) << j;
        }

        out[i] = b;
    }

    if (bitn < count) {
        j = 0;
        b = 0;
        do {
            b |= rep(coeff(f, bitn++)) << j++;
        }
        while (bitn < count);
        out[i] = b;
    }
    
    return (int)count; // number of bits
}
