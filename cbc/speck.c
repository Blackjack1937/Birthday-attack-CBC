#include "speck.h"

#if BLOCKSIZE == 32
    #define ALPHA 7
    #define BETA 2
    #define ROUND 22
    #define halfblock uint16_t
    #define MASK 0xffff
#elif BLOCKSIZE == 48
    #define ALPHA 8
    #define BETA 3
    #define ROUND 23
    #define halfblock uint32_t
    #define MASK 0xffffff
#else // BLOCKSIZE == 64 
    #define ALPHA 8
    #define BETA 3
    #define ROUND 27
    #define halfblock uint32_t
    #define MASK 0xffffffff

#endif

#define WORDSIZE (BLOCKSIZE/2)


#define ROTL(x,n) (((x << n) ^ (x >> (WORDSIZE-n)))&MASK)
#define ROTR(x,n) (((x >> n) ^ (x << (WORDSIZE-n)))&MASK)
#define R(x,y,k) (x=ROTR(x,ALPHA), x+=y, x&=MASK, x^=k, y=ROTL(y,BETA), y^=x)
#define D(x,y,k) (y^=x, y=ROTR(y,BETA)&MASK, x^=k, x-=y, x&=MASK, x=ROTL(x,ALPHA)&MASK)

void byte2halfblock(halfblock *dest, const byte *orig, int start)
{    
    *dest = 0;
    for (int j=NBYTES/2-1; j>=0; j--) 
    {
        *dest <<= 8;
        *dest |= (halfblock)orig[start+j];
    }
}

void halfblocks2bytes(byte* dest, halfblock* orig, int start)
{
    for (int i=0; i < NBYTES/2; i++)
    {
        dest[i] = orig[0] & 0xff;
        orig[0] >>= 8;
        dest[i+NBYTES/2] = orig[1] & 0xff;
        orig[1] >>= 8;
    }
}

void key_schedule(const byte k[2*NBYTES], halfblock rk[ROUND])
{
    halfblock l[4];
    byte2halfblock(rk, k, 0);
    byte2halfblock(l, k, NBYTES/2);
    byte2halfblock(l+1, k, NBYTES);
    byte2halfblock(l+2, k, 3*NBYTES/2);
    for (int i=0; i < ROUND-1; i++) {
        rk[i+1] = rk[i];
        R(l[0],rk[i+1],i);
        l[3] = l[0];
        for(int j=0; j<3;j++) l[j] = l[j+1];
    }
}

void speck_enc(const byte k[2*NBYTES], const byte m[NBYTES], byte c[NBYTES])
{
    halfblock cc[2] = {0, 0};
    byte2halfblock(cc, m, 0);
    byte2halfblock(cc+1, m, NBYTES/2);
    halfblock rk[ROUND];
    key_schedule(k, rk);
    for (int i=0; i < ROUND; i++) 
        R(cc[1],cc[0],rk[i]);
    halfblocks2bytes(c, cc, 0);
    return;
}

void speck_dec(const byte k[2*NBYTES], byte m[NBYTES], const byte c[NBYTES])
{
    halfblock mm[2] = {0, 0};
    byte2halfblock(mm, c, 0);
    byte2halfblock(mm+1, c, NBYTES/2);
    halfblock rk[ROUND];
    key_schedule(k, rk);
    for (int i=ROUND-1; i >=0; i--) 
        D(mm[1],mm[0],rk[i]);
    halfblocks2bytes(m, mm, 0);
    return;
}
