#include "attack.h"
#include "cbc.h"
#include "rand.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


size_t challenge(byte** m, byte** c) {
    size_t num_blocks;
#if BLOCKSIZE == 32
    num_blocks = (1 << 16);  // 65536 blocks
#elif BLOCKSIZE == 48
    num_blocks = (1 << 24);  // 16777216 
#elif BLOCKSIZE == 64
    num_blocks = (1 << 24); 
#else
    num_blocks = (1 << 16); 
#endif

    size_t mlen = num_blocks * NBYTES;  
    *m = (byte*)malloc(mlen);
    *c = (byte*)malloc(mlen + NBYTES);

    if (!*m || !*c) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }

    random_bytes(*m, mlen);         //random message
    byte key[2 * NBYTES];  
    random_bytes(key, sizeof(key));
    cbc_enc(key, *m, *c, mlen);
    return mlen;
}

#if BLOCKSIZE == 32
    #define TABLE_SIZE 65537
#elif BLOCKSIZE == 48
    #define TABLE_SIZE 2097151  
#elif BLOCKSIZE == 64
    #define TABLE_SIZE 16777259
#else
    #define TABLE_SIZE 65537
#endif

typedef struct node {
    size_t index;            
    byte block[NBYTES];      
    struct node* next;       
} node;


static unsigned long hash_block(const byte* block) {
    unsigned long h = 0;
    for (size_t i = 0; i < NBYTES; i++) {
        h = h * 31 + block[i];
    }
    return h % TABLE_SIZE;
}

void attack(const byte* c, size_t clen, size_t collision[2], byte xor[NBYTES]) {
    size_t num_blocks = clen / NBYTES;
    node** table = (node**)malloc(TABLE_SIZE * sizeof(node*));
    if (!table) {
        fprintf(stderr, "Memory allocation failed for hash table\n");
        exit(1);
    }
    for (size_t i = 0; i < TABLE_SIZE; i++) {
        table[i] = NULL;
    }
    for (size_t i = 0; i < num_blocks; i++) {
        const byte* curr_block = c + i * NBYTES;
        unsigned long h = hash_block(curr_block);
        node* curr = table[h];
        while (curr != NULL) {
            if (memcmp(curr->block, curr_block, NBYTES) == 0) {
                collision[0] = curr->index;
                collision[1] = i;


                if (i > 0 && curr->index > 0) {
                    for (size_t k = 0; k < NBYTES; k++) {
                        xor[k] = c[(i - 1) * NBYTES + k] ^ c[(curr->index - 1) * NBYTES + k];
                    }
                } else {
                    memset(xor, 0, NBYTES);
                }
      
                

                for (size_t j = 0; j < TABLE_SIZE; j++) {
                    node* temp = table[j];
                    while (temp) {
                        node* next = temp->next;
                        free(temp);
                        temp = next;
                    }
                }
                free(table);
                return;
            }


            curr = curr->next;
        }

     
        

        node* new_node = (node*)malloc(sizeof(node));
        if (!new_node) {
            fprintf(stderr, "Memory allocation failed in hash table node\n");
            exit(1);
        }
        new_node->index = i;
        memcpy(new_node->block, curr_block, NBYTES);
        new_node->next = table[h];
        table[h] = new_node;
    }

    
    for (size_t j = 0; j < TABLE_SIZE; j++) {
        node* temp = table[j];
        while (temp) {
            node* next = temp->next;
            free(temp);
            temp = next;
        }
    }
    free(table);
    printf("No collision found (tested %zu blocks)\n", num_blocks);
    collision[0] = collision[1] = 0;
    memset(xor, 0, NBYTES);
}
