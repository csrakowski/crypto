#pragma once

#include "SpecialMath.h"
/*
The RSA algorithm involves three steps: key generation, encryption and decryption.

[edit]Key generation
RSA involves a public key and a private key. The public key can be known to everyone and is used for encrypting messages. Messages encrypted with the public key can only be decrypted using the private key. The keys for the RSA algorithm are generated the following way:
Choose two distinct prime numbers p and q.
For security purposes, the integers p and q should be chosen at random, and should be of similar bit-length. Prime integers can be efficiently found using a primality test.
Compute n = pq.
n is used as the modulus for both the public and private keys
Compute φ(n) = (p – 1)(q – 1), where φ is Euler's totient function.
Choose an integer e such that 1 < e < φ(n) and gcd(e,φ(n)) = 1, i.e. e and φ(n) are coprime.
e is released as the public key exponent.
e having a short bit-length and small Hamming weight results in more efficient encryption - most commonly 0x10001 = 65537. However, small values of e (such as 3) have been shown to be less secure in some settings.[4]
Determine d = e–1 mod φ(n); i.e. d is the multiplicative inverse of e mod φ(n).
This is often computed using the extended Euclidean algorithm.
d is kept as the private key exponent.
The public key consists of the modulus n and the public (or encryption) exponent e. The private key consists of the private (or decryption) exponent d which must be kept secret.

Notes:
An alternative, used by PKCS#1, is to choose d matching de ≡ 1 mod λ with λ = lcm(p − 1,q − 1), where lcm is the least common multiple. Using λ instead of φ(n) allows more choices for d. λ can also be defined using the Carmichael function, λ(n).
The ANSI X9.31 standard prescribes, IEEE 1363 describes, and PKCS#1 allows, that p and q match additional requirements: be strong primes, and be different enough that Fermat factorization fails.


[edit]Encryption
Alice transmits her public key (n,e) to Bob and keeps the private key secret. Bob then wishes to send message M to Alice.
He first turns M into an integer 0 < m < n by using an agreed-upon reversible protocol known as a padding scheme. He then computes the ciphertext c corresponding to
c = me(mod n).
This can be done quickly using the method of exponentiation by squaring. Bob then transmits c to Alice.


[edit]Decryption
Alice can recover m from c by using her private key exponent d via computing
m = cd(mod n).
Given m, she can recover the original message M by reversing the padding scheme.
(In practice, there are more efficient methods of calculating cd using the pre computed values below.)


[edit]A worked example
Here is an example of RSA encryption and decryption. The parameters used here are artificially small, but one can also use OpenSSL to generate and examine a real keypair.
Choose two distinct prime numbers, such as
p = 61 and q = 53.
Compute n = pq giving
n = 61(53) = 3233.
Compute the totient of the product as φ(n) = (p − 1)(q − 1) giving
φ(3233) = (61 − 1)(53 − 1) = 3120.
Choose any number 1 < e < 3120 that is coprime to 3120. Choosing a prime number for e leaves us only to check that e is not a divisor of 3120.
Let e = 17.
Compute d, the modular multiplicative inverse of e(mod φ(n)) yielding
d = 2753.
The public key is (n = 3233, e = 17). For a padded plaintext message m, the encryption function is m17(mod 3233).
The private key is (n = 3233, d = 2753). For an encrypted ciphertext c, the decryption function is c2753(mod 3233).
For instance, in order to encrypt m = 65, we calculate
c = 6517(mod 3233) = 2790.
To decrypt c = 2790, we calculate
m = 27902753(mod 3233) = 65.
Both of these calculations can be computed efficiently using the square-and-multiply algorithm for modular exponentiation. In real life situations the primes selected would be much larger; in our example it would be relatively trivial to factor n, 3233, obtained from the freely available public key back to the primes p and q. Given e, also from the public key, we could then compute d and so acquire the private key.
*/

#ifdef __cplusplus
extern "C" {
#endif

const char * const gnupgext_version = "RSA ($Revision: 1.10 $)";

#define is_RSA(a) ((a)>=1 && (a)<=3)

#define BAD_ALGO  4
#define BAD_KEY   7
#define BAD_SIGN  8

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
    ulong u;	    /* inverse of p mod q. */
} RSA_private_key;

void test_keys(RSA_private_key *sk);
void generate(RSA_private_key *sk);
int  check_private_key( RSA_private_key *sk );

void pub( ulong* output, ulong* input, RSA_public_key* key);
void priv( ulong* output, ulong* input, RSA_private_key* key);

#ifdef __cplusplus
}
#endif
