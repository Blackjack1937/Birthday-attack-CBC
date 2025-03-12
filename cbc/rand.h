#ifndef RAND_H
#define RAND_H

#include <stdint.h>
#include <stdio.h>

void random_init(uint64_t seed[4]);
void random_bytes(uint8_t* c, size_t len);

#endif // RAND_H
