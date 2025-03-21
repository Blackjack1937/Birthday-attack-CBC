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
    int num_attempts;
    printf("Testing birthday attack with BLOCKSIZE = %d bits\n", BLOCKSIZE);
    printf("Enter number of attempts: ");
    if (scanf("%d", &num_attempts) != 1 || num_attempts <= 0) {
        fprintf(stderr, "Invalid number of attempts.\n");
        return 1;
    }

    int collisions = 0;

    for (int attempt = 1; attempt <= num_attempts; attempt++) {
        printf("\nAttempt %d:\n", attempt);

        byte *m, *c;
        size_t mlen = challenge(&m, &c);
        size_t collision[2];
        byte xor[NBYTES];

        printf("Generated message of %zu bytes\n", mlen);

        attack(c, mlen + NBYTES, collision, xor);

        if (collision[0] != collision[1]) {
            printf("Collision found at blocks %zu and %zu\n", collision[0], collision[1]);
            print_hex("P_i ⊕ P_j", xor, NBYTES);
            collisions++;
        } else {
            printf("No collision found.\n");
        }

        free(m);
        free(c);
    }

    printf("\nTotal collisions found: %d out of %d attempts\n", collisions, num_attempts);
    return 0;
}
