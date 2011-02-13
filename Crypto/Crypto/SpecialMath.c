#include "SpecialMath.h"
#include <stdlib.h>

ulong ipow(ulong base, ulong exp)
{
    ulong result = 1;
    while (exp)
    {
        if (exp & 1)
            result *= base;
        exp >>= 1;
        base *= base;
    }
    return result;
}

ulong crandom()
{
	ulong* seed = (ulong*)malloc(sizeof(ulong));
	srand((*seed+1)*rand());
	free(seed);
	return ((ulong)rand());
}