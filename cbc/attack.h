#ifndef ATTACK_H
#define ATTACK_H

#include <stdint.h>
#include <stddef.h>
#include "cbc.h" 

#define MAX_BLOCKS 65536 
typedef uint8_t byte;
size_t challenge(byte** m, byte** c);

void attack(const byte* c, size_t clen, size_t collision[2], byte xor[NBYTES]);

#endif 
