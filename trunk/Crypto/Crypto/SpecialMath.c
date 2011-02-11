#include "SpecialMath.h"

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