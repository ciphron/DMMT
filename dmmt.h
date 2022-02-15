#ifndef DMMT_H
#define DMMT_H

/*
 * We call this system Distributed Multi-Message Threshold (DMMT).
 * We define a domain as associated with a tag, a symmetric key
 * and a threshold value.
 * Ciphertexts generated with the key belong to the "domain".
 * A domain "owner" is someone that knows its symmetric key.
 * They can then create ciphertexts.
 * A domain "owner" can also create "shares" (which can be bundled as ciphertexts). If a user learns
 * t shares where t is the thresold of a domain, he can compute
 * the symmetric key, and then become an "owner" of the domain.
 *
 * The main application is mind is that one releases a share with
 * every ciphertext. So if one gets hold of an appropriate number
 * of ciphertexts associated with the domain, he can then
 * decrypt all these ciphertexts, and create new ones if needed.
 */

#include "types.h"

struct dmmt;
typedef struct dmmt dmmt_t;
typedef struct dmmt_dom dmmt_dom_t;

dmmt_t *dmmt_create(const char *block_cipher, size_t block_size,
                    size_t key_len_bits, dmmt_stat_t *status);

dmmt_dom_t *dmmt_new_dom_from_key(dmmt_t *d, const uint8_t *master_key, unsigned int threshold, dmmt_stat_t *status);

dmmt_dom_t *dmmt_new_dom_from_shares(dmmt_t *d, const uint8_t *tag, unsigned int threshold, const uint8_t * const *shares, size_t n_shares, dmmt_stat_t *status);

dmmt_stat_t dmmt_gen_tag(dmmt_t *d, const uint8_t *master_key, uint8_t *tag_out);

dmmt_stat_t dmmt_free(dmmt_t *d);


/* Domain */

dmmt_stat_t dmmt_dom_gen_share(dmmt_dom_t *dom, uint8_t *share_out);

const uint8_t *dmmt_dom_tag(dmmt_dom_t *dom);

dmmt_stat_t dmmt_dom_encrypt(dmmt_dom_t *dom, const uint8_t *in, size_t in_size, uint8_t *out, size_t out_size);

dmmt_stat_t dmmt_dom_decrypt(dmmt_dom_t *dom, const uint8_t *in, size_t in_size, uint8_t *out, size_t out_size);

dmmt_stat_t dmmt_dom_free(dmmt_dom_t *dom);


#endif
