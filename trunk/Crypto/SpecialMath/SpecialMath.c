
/*****************************\
* Christiaan Rakowski
* Crypto Collection
*
* Special Math Libary
\*****************************/

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
	//if(a == 0) return b;
	//if(b == 0) return a;
	//return gcd(b, (a%b));

    ulong c;
    if(a<b) swap(&a, &b);
    while(1)
    {
  		c = a%b;
  		if(c==0) return b;
  		a = b;
  		b = c;
    }
}

ulong crandom(void)
{
	ulong* seed = (ulong*)malloc(sizeof(ulong));
	ulong* seed2 = (ulong*)malloc(sizeof(ulong));
	srand( (uint)((time(0)*(*seed+(ulong)seed)*rand())+(sizeof(ulong)^*seed2)) );
	*seed = rand();
	*seed2 = (ulong)seed;
	free(seed);
	free(seed2);
	//return ((ulong)rand());	// Too small
	return (((ulong)((rand()<<(sizeof(uint)<<2))|rand()))& UINT_MAX);		// Decent size, decent speed
	//return ((ulong)((rand()<<(sizeof(ulong)<<3))|(rand()<<(sizeof(ulong)<<2))|(rand()<<(sizeof(ulong)<<1))|rand()));		// Slow, and not too much better than 2d one on 32 bit
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

int mod(int a, int n)
{
	if(a>=0)
	{
		return (a%n);
	}
	else
	{
		while(a < 0)
		{
			a = n+a;	
		}
		return a;
	}
}

 /****************
  * Calculate the multiplicative inverse X of A mod N
  * That is: Find the solution x for
  *              1 = (a*x) mod n
  */
ulong invm(ulong e, ulong n)
{
	ulong d;
	for(d=0;;d++)	//BRUTEFORCE!!!
	{
		if(((e*d)%n) == 1)
		{
			return d;
		}
	}
	return -1;
}
