#include <stdio.h>
#include "rand.h"
#include "speck.h"

#define PRINTBYTES(before, array, length, after) \
    { printf(before); for (size_t i=0; i<(length); i++) printf("%0x ",array[i]); printf(after); }

int main() {
    size_t i;
    printf("Block size: 8*%d = %d; Key size: 16*%d = %d\n",NBYTES,NBYTES<<3,NBYTES,NBYTES<<4);
   
    byte k[2*NBYTES];
    byte m[NBYTES];
    byte c[NBYTES];
    byte d[NBYTES];

    random_bytes(k, 2*NBYTES);
    random_bytes(m, NBYTES);

    PRINTBYTES("Key: k = ",k,2*NBYTES,"\n");
    PRINTBYTES("Message block:    m = ", m, NBYTES, "\n");

    speck_enc(k,m,c);
    
    PRINTBYTES("Ciphertext block: c = ",c, NBYTES, "\n");

    speck_dec(k,d,c);
    
    PRINTBYTES("Decrypted block:  d = ", d, NBYTES, "\n");

    return 0;

}
