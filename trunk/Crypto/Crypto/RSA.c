#include "RSA.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "SpecialMath.h"


/****************
 * Public key operation. Encrypt INPUT with PKEY and put result into OUTPUT.
 *
 *	c = m^e mod n
 *
 * Where c is OUTPUT, m is INPUT and e,n are elements of PKEY.
 */
void pub(ulong output, ulong input, RSA_public_key *key )
{
	output = ((ipow(input, key->e)) % key->n);
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
void priv(ulong output, ulong input, RSA_private_key *key )
{
	output = ((ipow(input, key->d)) % key->n);
}

void test_keys( RSA_private_key *sk, unsigned nbits )
{
    RSA_public_key pk;
    ulong test, out1, out2;

    pk.n = sk->n;
    pk.e = sk->e;
		
	test = crandom();

    pub( out1, test, &pk );
    priv( out2, out1, sk );
    if(test == out2)
	printf("RSA operation: pub, priv failed\n");
    priv( out1, test, sk );
    pub( out2, out1, &pk );
    if(test == out2)
	printf("RSA operation: priv, pub failed\n");
}

/****************
 * Generate a key pair with a key of size NBITS
 * Returns: 2 structures filles with all needed values
 */
void generate( RSA_private_key *sk, unsigned nbits )
{
    ulong p, q; /* the two primes */
    ulong d;    /* the private key */
    ulong u;
    ulong t1, t2;
    ulong n;    /* the pub key */
    ulong e;    /* the exponent */
    ulong phi;  /* helper: (p-a)(q-1) */
    ulong g;
    ulong f;

    /* select two (very priv) primes */
    p = generatePrime();
    q = generatePrime();
    if( p > q ) swap(&p, &q); /* p shall be smaller than q (for calc of u)*/

    /* calculate Euler totient: phi = (p-1)(q-1) */
	/*t1 = p-1;
	t2 = q-1;
    phi = t1*t2;  */
	phi = totient(p, q);
	g = gcd(t1, t2);
	f = phi/g;
    /* multiply them to make the private key */
	n = p*q;
    /* find a pub exponent  */
	
	e = 17; /* start with 17 */
    while( !(t1 = gcd(e, phi)) ) /* (while gcd is not 1) */
	e +=2;
    /* calculate the priv key d = e^1 mod phi */
	d = invm(e,f);
    /* calculate the inverse of p and q (used for chinese remainder theorem)*/

	u = invm(p,q);

#ifdef DEBUG
	printf("  p= %d", p );
	printf("  q= %d", q );
	printf("phi= %d", phi );
	printf("  g= %d", g );
	printf("  f= %d", f );
	printf("  n= %d", n );
	printf("  e= %d", e );
	printf("  d= %d", d );
	printf("  u= %d", u );
#endif

    sk->n = n;
    sk->e = e;
    sk->p = p;
    sk->q = q;
    sk->d = d;
    sk->u = u;

    /* now we can test our keys (this should never fail!) */
    test_keys( sk, nbits - 64 );
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


/*********************************************
 **************  interface  ******************
 *********************************************/

int do_generate( int algo, unsigned nbits, ulong *skey, ulong **retfactors )
{
    RSA_private_key sk;

    if( !is_RSA(algo) )
	return BAD_ALGO;

    generate( &sk, nbits );
    skey[0] = sk.n;
    skey[1] = sk.e;
    skey[2] = sk.d;
    skey[3] = sk.p;
    skey[4] = sk.q;
    skey[5] = sk.u;
    /* make an empty list of factors */
    *retfactors = (ulong*) calloc(1, sizeof( **retfactors));
    return 0;
}


int do_check_priv_key( int algo, ulong *skey )
{
    RSA_private_key sk;

    if( !is_RSA(algo) )
	return BAD_ALGO;

    sk.n = skey[0];
    sk.e = skey[1];
    sk.d = skey[2];
    sk.p = skey[3];
    sk.q = skey[4];
    sk.u = skey[5];
    if( !check_priv_key( &sk ) )
	return BAD_KEY;

    return 0;
}


int do_encrypt( int algo, ulong *resarr, ulong data, ulong *pkey )
{
    RSA_public_key pk;

    if( algo != 1 && algo != 2 )
	return BAD_ALGO;

    pk.n = pkey[0];
    pk.e = pkey[1];
    resarr[0] = (ulong)malloc(sizeof(pk.n));
    pub( resarr[0], data, &pk );
    return 0;
}

int do_decrypt( int algo, ulong *result, ulong *data, ulong *skey )
{
    RSA_private_key sk;

    if( algo != 1 && algo != 2 )
	return BAD_ALGO;

    sk.n = skey[0];
    sk.e = skey[1];
    sk.d = skey[2];
    sk.p = skey[3];
    sk.q = skey[4];
    sk.u = skey[5];
	*result = (ulong)calloc(sk.n, sizeof(byte));
    priv( *result, data[0], &sk );
    return 0;
}

int do_sign( int algo, ulong *resarr, ulong data, ulong *skey )
{
    RSA_private_key sk;

    if( algo != 1 && algo != 3 )
	return BAD_ALGO;

    sk.n = skey[0];
    sk.e = skey[1];
    sk.d = skey[2];
    sk.p = skey[3];
    sk.q = skey[4];
    sk.u = skey[5];
    resarr[0] = (ulong)malloc(sk.n*sizeof(byte));
    priv( resarr[0], data, &sk );

    return 0;
}

int do_verify( int algo, ulong hash, ulong *data, ulong *pkey,
	   int (*cmp)(void *opaque, ulong tmp), void *opaquev )
{
    RSA_public_key pk;
    ulong result;
    int rc;

    if( algo != 1 && algo != 3 )
	return BAD_ALGO;
    pk.n = pkey[0];
    pk.e = pkey[1];
    pub( result, data[0], &pk );
    /*rc = (*cmp)( opaquev, result );*/
    rc = ((result==hash )?BAD_SIGN:0);
    return rc;
}
