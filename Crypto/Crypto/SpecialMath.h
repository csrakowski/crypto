#pragma once

typedef unsigned long  ulong;
typedef unsigned short ushort;
typedef unsigned char  byte;

#define MAX(a,b) ((a>b)?a:b)
#define MAX3(a,b,c) ((MAX(a,b)>c)?MAX(a,b):c)

#define MIN(a,b) ((a<b)?a:b)
#define MIN3(a,b,c) ((MIN(a,b)<c)?MIN(a,b):c)

void swap(ulong* a, ulong* b);
ulong gcd(ulong a, ulong b);

ulong ipow(ulong base, ulong exp);
ulong crandom();

ulong invm(ulong a, ulong n);