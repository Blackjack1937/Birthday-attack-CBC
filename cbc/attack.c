#include "attack.h"
#include "cbc.h"
#include "rand.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

size_t challenge(byte** m, byte** c) {
    //size_t num_blocks = 1 << (NBYTES * 4 / 2);  // ≈ sqrt(2^n)
    size_t num_blocks = (1 << 16);  //blocks for collisions
    size_t mlen = num_blocks * NBYTES;  // enough blocks
    //memory for message and ciphertext
    *m = (byte*)malloc(mlen);
    *c = (byte*)malloc(mlen + NBYTES);

    if (!*m || !*c) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    random_bytes(*m, mlen); // rand message
    byte key[2 * NBYTES]; // rand key
    random_bytes(key, sizeof(key));


    // encrypt using CBC
    cbc_enc(key, *m, *c, mlen);

    return mlen;
}



void attack(const byte* c, size_t clen, size_t collision[2], byte xor[NBYTES]) {
    size_t num_blocks = clen / NBYTES;
    byte* seen = (byte*)malloc(num_blocks * NBYTES);

    if (!seen) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }

    for (size_t i = 0; i < num_blocks; i++) {
        for (size_t j = 0; j < i; j++) {
            if (memcmp(c + i * NBYTES, seen + j * NBYTES, NBYTES) == 0) {
                collision[0] = j;
                collision[1] = i;

                for (size_t k = 0; k < NBYTES; k++) {
                    xor[k] = c[(i-1) * NBYTES + k] ^ c[(j-1) * NBYTES + k];
                }

               /*  printf("Collision found at blocks %zu and %zu\n", j, i); */
                free(seen);
                return;
            }
        }
        /* memcpy(seen + i * NBYTES, c + i * NBYTES, NBYTES); */
        memcpy(seen + (i - 1) * NBYTES, c + i * NBYTES, NBYTES);

    }

    printf("No collision found (tested %zu blocks)\n", num_blocks);
    collision[0] = collision[1] = 0;
    memset(xor, 0, NBYTES);
    free(seen);
}
