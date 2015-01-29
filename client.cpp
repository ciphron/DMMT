/*
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <gcrypt.h>

#include "dmmt.h"

#include <streambuf>
#include <iostream>



int main(int argc, char *argv[])
{
    dmmt_stat_t status;

    unsigned int thres = 10; // just an example
    unsigned int block_size = 16;
    dmmt_t *d = dmmt_create("AES", 16, 128, &status);

    uint8_t *key = (uint8_t*)gcry_random_bytes_secure(16, GCRY_STRONG_RANDOM);

    uint8_t ciphertext[128];
    uint8_t decrypted[128];
    const char *plaintext = "hello";


    dmmt_dom_t *dom = dmmt_new_dom_from_key(d, key, thres, &status);

    printf("Plaintext string is %s\n", plaintext);

    dmmt_dom_encrypt(dom, (const uint8_t*)plaintext, strlen(plaintext), ciphertext, 128);


    uint8_t **shares = (uint8_t**)malloc(thres * sizeof(uint8_t*));
    unsigned int i;
    for (i = 0; i < thres; i++) {
        uint8_t *share = (uint8_t*)malloc(block_size * 2);

        dmmt_dom_gen_share(dom, share);
        shares[i] = share;
    }

    std::cout << "Shares generated" << std::endl;

    dmmt_dom_t *dom2 = dmmt_new_dom_from_shares(d, dmmt_dom_tag(dom), thres, shares, thres, &status);

    dmmt_dom_decrypt(dom2, ciphertext, strlen(plaintext) + 16, decrypted, 128);

    decrypted[strlen(plaintext)] = 0;

    printf("Decrypted string is %s\n", (const char*)decrypted);

    gcry_free(key);

    dmmt_dom_free(dom);
    dmmt_dom_free(dom2);
    dmmt_free(d);

    for (i = 0; i < thres; i++)
        free(shares[i]);

    return 0;
}
