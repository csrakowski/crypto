#include "SpecialMath.h"
#include <stdlib.h>
#include <time.h>
#include <limits.h>

void swap(ulong* a, ulong* b)
{
	ulong t;
	t = *a;
	*a = *b;
	*b = t;
}

ulong gcd(ulong a, ulong b)
{
	if(a == 0) return b;
	if(b == 0) return a;
	return gcd(b, (a%b));
}

ulong crandom(void)
{
	ulong* seed = (ulong*)malloc(sizeof(ulong));
	ulong* seed2 = (ulong*)malloc(sizeof(ulong));
	srand( (uint)((time(0)*(*seed+1)*rand())+(1^*seed2)) );
	*seed = rand();
	free(seed);
	free(seed2);
	return ((ulong)rand());
	//return ((ulong)((rand()<<(sizeof(uint)>>1))|rand()));
}

ulong generatePrime(void)
{
	ulong prime, i;

	while(1)
	{
		prime = crandom();
		if(prime%2==0) prime++;

		for(i=2;i<=(prime>>1);i++)
		{
			if((prime%i)==0) 
			{
				i=-1; break;
			}
		}
		if(i != -1) break;
	}
	return prime;
}


ulong totient(ulong p, ulong q)
{
	return ((p-1)*(q-1));
}

ulong ipow(ulong base, ulong exp)
{
	//if(exp == 0) return 1;
	//if(base== 0) return 0;
	//for(exp; exp>1; exp--)
	//{
	//	base*=base;
	//}
	//return base;

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

 /****************
  * Calculate the multiplicative inverse X of A mod N
  * That is: Find the solution x for
  *              1 = (a*x) mod n
  */
ulong invm(ulong a, ulong n)
{
	int x;
	for(x=0; x<ULONG_MAX; x++)	//BRUTEFORCE!!!
	{
		if(((a*x)%n) == 1)
		{
			return x;
		}
	}
	return -1;
}