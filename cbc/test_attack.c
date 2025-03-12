#include "attack.h"
#include <stdio.h>
#include <stdlib.h>

void print_hex(const char* label, const byte* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

int main() {
    byte *m, *c;
    size_t mlen = challenge(&m, &c);
    size_t collision[2];
    byte xor[NBYTES];

    printf("Generated message of %zu bytes\n", mlen);

    attack(c, mlen + NBYTES, collision, xor);

    if (collision[0] != collision[1]) {
        printf("Collision found at blocks %zu and %zu\n", collision[0], collision[1]);
        print_hex("P_i ⊕ P_j", xor, NBYTES);
    } else {
        printf("No collision found.\n");
    }

    free(m);
    free(c);
    return 0;
}
