
/*****************************\
* Christiaan Rakowski
* Crypto Collection
*
* RSA Encryption
\*****************************/

#include "RSA.h"
#include <stdio.h>
#include <stdlib.h>
#include "../SpecialMath/SpecialMath.h"

/****************
 * Public key operation. Encrypt INPUT with PKEY and put result into OUTPUT.
 *
 *	c = m^e mod n
 *
 * Where c is OUTPUT, m is INPUT and e,n are elements of PKEY.
 */
void encrypt(ulong* output, ulong* input, RSA_public_key *key )
{
	ulong meh = (ipow(*input, key->e));
#ifdef _DEBUG
	printf("meh: %ld\n", meh);
#endif
	*output = (meh % key->n);
}

/****************
 * Secret key operation. Encrypt INPUT with SKEY and put result into OUTPUT.
 *
 *	m = c^d mod n
 *
 * Where m is OUTPUT, c is INPUT and d,n are elements of PKEY.
 *
 * FIXME: We should better use the Chinese Remainder Theorem
 */
void decrypt(ulong* output, ulong* input, RSA_private_key *key )
{
	ulong meh = (ipow(*input, key->d));
#ifdef _DEBUG
	printf("meh: %ld\n", meh);
#endif
	*output = (uchar)(meh % key->n);
}

void test_keys( RSA_private_key *sk )
{
    RSA_public_key pk;
    ulong test, out1 = 0, out2 = 0;

    pk.n = sk->n;
    pk.e = sk->e;
		
	test = crandom();

    encrypt( &out1, &test, &pk );
    decrypt( &out2, &out1, sk );
    if(test != out2) printf("RSA operation: pub, priv failed\n");
    decrypt( &out1, &test, sk );
    encrypt( &out2, &out1, &pk );
    if(test != out2) printf("RSA operation: priv, pub failed\n");
}

/****************
 * Generate a key pair with a key of size NBITS
 * Returns: 2 structures filles with all needed values
 */
void generate( RSA_private_key *sk )
{
    ulong p, q; /* the two primes */
    ulong d;    /* the private key */
    ulong n;    /* the pub key */
    ulong e;    /* the exponent */
    ulong phi;  /* helper: (p-a)(q-1) */
    ulong g;

    /* select two primes */
    p = 61;//generatePrime();
    q = 53;//generatePrime();
    if( p > q ) swap(&p, &q); /* p shall be smaller than q (for calc of u)*/

    /* calculate Euler totient: phi = (p-1)(q-1) */
	phi = totient(p, q);
	g = gcd((p-1), (q-1));
    /* multiply them to make the private key */
	n = p*q;
    /* find a pub exponent  */
	
	e = 17; /* start with 17 */
    while(gcd(e, phi) != 1)
	{
		//printf("%d\n", e);
		e+=2;
	}
    /* calculate the priv key d = e^1 mod phi */
	d = invm(e, phi);

#ifdef _DEBUG
	printf("  p= %ld\n", p );
	printf("  q= %ld\n", q );
	printf("phi= %ld\n", phi );
	printf("  g= %ld\n", g );
	printf("  n= %ld\n", n );
	printf("  e= %ld\n", e );
	printf("  d= %ld\n", d );
#endif

    sk->n = n;
    sk->e = e;
    sk->p = p;
    sk->q = q;
    sk->d = d;

    /* now we can test our keys (this should never fail!) */
    test_keys(sk);
}

/****************
 * Test wether the private key is valid.
 * Returns: true if this is a valid key.
 */
int check_priv_key( RSA_private_key *sk )
{
    int rc;
	ulong temp = sk->p * sk->q;
	rc = (temp==sk->n);
    return !rc;
}

int main(int argc, char *argv[])
{
	ulong in = 1, out, result;
	RSA_private_key privkey;
	RSA_public_key pubkey;
	
	generate(&privkey);
	pubkey.n = privkey.n;
	pubkey.e = privkey.e;

	printf("Input: %ld\n", in);
	encrypt(&out, &in, &pubkey);	
	printf("Output: %ld\n", out);
	decrypt(&result, &out, &privkey);
	printf("Result: %ld\n", result);

	return 0;
}