#pragma once

/*****************************\
* Christiaan Rakowski
* Crypto Collection
*
* Special Math Libary
\*****************************/

#include <math.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned long long	ulong;
typedef unsigned int		uint;
typedef unsigned short		ushort;
typedef unsigned char		uchar;
typedef unsigned char		byte;

#define BIT(b) (1<<b)
#define TOGGLEBIT(x, b) (x^=BIT(b))

#define ROLL(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))
#define ROLR(value, bits) (((value) >> (bits)) | ((value) << (32 - (bits))))
//#define ROLL(value, bits) _asm { rol value, bits }
//#define ROLR(value, bits) _asm { ror value, bits }

#define MAX(a,b) ((a>b)?a:b)
#define MAX3(a,b,c) ((MAX(a,b)>c)?MAX(a,b):c)

#define MIN(a,b) ((a<b)?a:b)
#define MIN3(a,b,c) ((MIN(a,b)<c)?MIN(a,b):c)

//#define xorswap(x, y) ( x^=y; y^=x; x^=y; )
//#define xorswap(x, y) _asm { xor x, y; xor y, x; xor x, y; }
void swap(ulong* a, ulong* b);
ulong gcd(ulong a, ulong b);
ulong crandom(void);
ulong generatePrime(void);
ulong totient(ulong p, ulong q);
ulong ipow(ulong base, ulong exp);
int mod(int a, int n);
ulong invm(ulong e, ulong n);

#ifdef __cplusplus
}
#endif
