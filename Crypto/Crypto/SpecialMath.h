#pragma once

#include <math.h>

/*****************************\
* Christiaan Rakowski
* Crypto Collection
\*****************************/

typedef unsigned long	ulong;
typedef unsigned int	uint;
typedef unsigned short	ushort;
typedef unsigned char	byte;

#define BIT(b) (1<<b)
#define TOGGLEBIT(x, b) (x^=BIT(b))

#define MAX(a,b) ((a>b)?a:b)
#define MAX3(a,b,c) ((MAX(a,b)>c)?MAX(a,b):c)

#define MIN(a,b) ((a<b)?a:b)
#define MIN3(a,b,c) ((MIN(a,b)<c)?MIN(a,b):c)

void swap(ulong* a, ulong* b);
ulong gcd(ulong a, ulong b);
ulong generatePrime();
ulong totient(ulong p, ulong q);
ulong ipow(ulong base, ulong exp);
ulong crandom();
ulong invm(ulong a, ulong n);