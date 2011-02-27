#pragma once

#include "SpecialMath.h"

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

void encrypt( ulong* output, uchar* input, RSA_public_key* key);
void decrypt( uchar* output, ulong* input, RSA_private_key* key);

#ifdef __cplusplus
}
#endif
