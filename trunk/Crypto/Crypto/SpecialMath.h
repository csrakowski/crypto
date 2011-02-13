#pragma once

typedef unsigned long  ulong;
typedef unsigned short ushort;
typedef unsigned char  byte;

#define MAX(a,b) ((a>b)?a:b)
#define MIN(a,b) ((a<b)?a:b)

ulong ipow(ulong base, ulong exp);
ulong crandom();
