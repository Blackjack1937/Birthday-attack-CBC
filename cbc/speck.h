#ifndef SPECK_H
#define SPECK_H

#include <stdio.h>
#include <stdint.h>

#ifndef BLOCKSIZE
#define BLOCKSIZE 32
#endif

#define NBYTES (BLOCKSIZE/8)
#define byte uint8_t

void speck_enc(const byte k[2*NBYTES], const byte m[NBYTES], byte c[NBYTES]);
void speck_dec(const byte k[2*NBYTES], byte m[NBYTES], const byte c[NBYTES]);

#endif // SPECK_H
