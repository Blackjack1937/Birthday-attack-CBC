#include <stdio.h>
#include <stdlib.h>
#include <string.h>  
#include "cbc.h"
#include "speck.h"
#include "rand.h"


#define MSG_LEN 32

void print_hex(const char* label, const byte* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

int main() {
    byte key[2 * NBYTES];
    byte plaintext[MSG_LEN], ciphertext[MSG_LEN + NBYTES], decrypted[MSG_LEN];

    // gen random key and plaintext
    random_bytes(key, sizeof(key)); 
    random_bytes(plaintext, sizeof(plaintext)); // test non-determinism
    /* byte plaintext[] = {
        0xfc, 0xe4, 0x30, 0x50, 0xa3, 0xd1, 0xde, 0x32,
        0x86, 0x18, 0x56, 0x77, 0xcb, 0x5b, 0xb9, 0x55,
        0x87, 0xf6, 0x8c, 0xab, 0x57, 0xb6, 0x94, 0x5c,
        0xd6, 0xe9, 0xea, 0x3b, 0x4c, 0x8d, 0xed, 0xb5
    }; */
    

    cbc_enc(key, plaintext, ciphertext, MSG_LEN);
    cbc_dec(key, decrypted, ciphertext, MSG_LEN + NBYTES);

    // Print results
    print_hex("Key", key, sizeof(key));
    print_hex("Plaintext", plaintext, sizeof(plaintext));
    print_hex("Ciphertext", ciphertext, sizeof(plaintext) + NBYTES);
    print_hex("Decrypted", decrypted, sizeof(plaintext));

    // check if correct
    if (memcmp(plaintext, decrypted, sizeof(plaintext)) == 0) {
        printf("✅ CBC encryption and decryption are correct!\n");
    } else {
        printf("❌ CBC decryption failed!\n");
    }

    return 0;
}
