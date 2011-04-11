#pragma once

/*****************************\
* Christiaan Rakowski
* Crypto Collection
*
* RSA Encryption
* Safety:	RSA is very scalable, the bigger the prime numbers are the stronger the encryption will be, thus making RSA a very secure choice.
* FunFact:	Bruce Schneier knows Alice and Bob's shared secret. http://www.schneierfacts.com/fact/18
* Note: Core algorithm there, stuck on the size of the primes. 16^16 is 64 bit max already. Will implement a big number libary later.
\*****************************/


#include "../SpecialMath/SpecialMath.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    ulong n;	    /* modulus */
    ulong e;	    /* exponent */
} RSA_public_key;

typedef struct {
    ulong n;	    /* public modulus */
    ulong e;	    /* public exponent */
    ulong d;	    /* exponent */
    ulong p;	    /* prime  p. */
    ulong q;	    /* prime  q. */
} RSA_private_key;

void test_keys(RSA_private_key *sk);
void generate(RSA_private_key *sk);
int  check_private_key( RSA_private_key *sk );

void encrypt( ulong* output, ulong* input, RSA_public_key* key);
void decrypt( ulong* output, ulong* input, RSA_private_key* key);

#ifdef __cplusplus
}
#endif
