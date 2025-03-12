#ifndef CBC_H
#define CBC_H

#include <stdint.h>
#include <stddef.h>

#ifndef NBYTES
#define NBYTES (BLOCKSIZE / 8)
#endif

typedef uint8_t byte;


void cbc_enc(const byte k[2 * NBYTES], const byte* m, byte* c, size_t mlen);
void cbc_dec(const byte k[2 * NBYTES], byte* m, const byte* c, size_t mlen);

#endif 
