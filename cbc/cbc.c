#include "cbc.h"
#include "speck.h"
#include "rand.h"  
#include <string.h> 

//random IV
static void generate_iv(byte iv[NBYTES]) {
    random_bytes(iv, NBYTES);
}

// CBC encryption
void cbc_enc(const byte k[2 * NBYTES], const byte* m, byte* c, size_t mlen) {
    byte iv[NBYTES], prev_cipher[NBYTES], block[NBYTES];
    generate_iv(iv);
    memcpy(c, iv, NBYTES); //  first block
    memcpy(prev_cipher, iv, NBYTES);

    for (size_t i = 0; i < mlen; i += NBYTES) {
        //XOR
        for (size_t j = 0; j < NBYTES; j++) {
            block[j] = m[i + j] ^ prev_cipher[j];
        }
        speck_enc(k, block, c + NBYTES + i); // encrypt the xored block using SPECK

        // Update next block
        memcpy(prev_cipher, c + NBYTES + i, NBYTES);
    }
}

//decryption
void cbc_dec(const byte k[2 * NBYTES], byte* m, const byte* c, size_t mlen) {
    byte prev_cipher[NBYTES], decrypted[NBYTES];
    memcpy(prev_cipher, c, NBYTES);
    for (size_t i = 0; i < mlen - NBYTES; i += NBYTES) {
        speck_dec(k, decrypted, c + NBYTES + i);

        
        for (size_t j = 0; j < NBYTES; j++) {
            m[i + j] = decrypted[j] ^ prev_cipher[j];
        }
        memcpy(prev_cipher, c + NBYTES + i, NBYTES);
    }
}
