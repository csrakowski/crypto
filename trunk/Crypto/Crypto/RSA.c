#include "RSA.h"

#include <stdio.h>
#include <stdlib.h>
#include "SpecialMath.h"


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
	*output = (meh % key->n);
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
    if(test == out2)
	printf("RSA operation: pub, priv failed\n");
    decrypt( &out1, &test, sk );
    encrypt( &out2, &out1, &pk );
    if(test == out2)
	printf("RSA operation: priv, pub failed\n");
}

/****************
 * Generate a key pair with a key of size NBITS
 * Returns: 2 structures filles with all needed values
 */
void generate( RSA_private_key *sk )
{
    ulong p, q; /* the two primes */
    ulong d;    /* the private key */
    ulong u;
    ulong n;    /* the pub key */
    ulong e;    /* the exponent */
    ulong phi;  /* helper: (p-a)(q-1) */
    ulong g;
    ulong f;

    /* select two primes */
    p = generatePrime();
    q = generatePrime();
    if( p > q ) swap(&p, &q); /* p shall be smaller than q (for calc of u)*/

    /* calculate Euler totient: phi = (p-1)(q-1) */
	phi = totient(p, q);
	g = gcd((p-1), (q-1));
	f = phi/g;
    /* multiply them to make the private key */
	n = p*q;
    /* find a pub exponent  */
	
	e = 593; /* start with 17 */
    while(gcd(e, phi) != 1)
	{
		//printf("%d\n", e);
		e+=2;
	}
    /* calculate the priv key d = e^1 mod phi */
	d = invm(e, phi);
    /* calculate the inverse of p and q (used for chinese remainder theorem)*/
	u = invm(p,q);

#ifdef _DEBUG
	printf("  p= %ld\n", p );
	printf("  q= %ld\n", q );
	printf("phi= %ld\n", phi );
	printf("  g= %ld\n", g );
	printf("  f= %ld\n", f );
	printf("  n= %ld\n", n );
	printf("  e= %ld\n", e );
	printf("  d= %ld\n", d );
	printf("  u= %ld\n", u );
#endif

    sk->n = n;
    sk->e = e;
    sk->p = p;
    sk->q = q;
    sk->d = d;
    sk->u = u;

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

/*

stap	handeling	berekening	opmerking
1	Alice kiest twee priemgetallen p en q	p = 17 en q = 11	in werkelijkheid zijn deze getallen zeer groot
2	berekening n = p x q	n = 17 x 11 = 187	n is haar eerste publieke sleutel
3	bepaling van e	e= 7	e en (p - 1) x (q - 1) moeten relatief priem zijn.
Het getal e is haar tweede publieke sleutel
4	Bob stuurt de letter X
Voor X kiezen we 88
(ASCII-tabel)
De boodschap M = 88	De encryptie (cijfertekst) wordt berekend met:
C = Me (mod n) wordt:
C= 887 (mod 187)	Bob zoekt dus eerst de beide publieke sleutels van Alice
5	bepaling van de waarde van C	C = 894432 (mod 187)
C= 11 (mod 187)	Hiervoor kun je de applet gebruiken
6	Alice ontvangt het bericht en bepaalt haar decryptiesleutel d	e x d = 1 (mod (p – 1) x (q – 1)
7 x d = 1 (mod 160)
dus d = 23	De waarde van d, de inverse kan bepaald worden met het uitgebreide Algoritme van Euclides
7	Alice ontcijfert het bericht	M = Cd (mod n)
M = 1123 (mod 187)
M = 88 (mod 187)	1123 = 1116 x 118 x 114 x 112 x 11
Zie het 
modulorekenen
8	Alice ziet de letter terug	88 is X	
*/