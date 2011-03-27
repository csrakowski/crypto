#include "3DES.h"

/*****************************\
* Christiaan Rakowski
* Crypto Collection
\*****************************/

void encryptDES()
{
	//TODO
}

void decryptDES()
{
	//TODO
}

void encrypt3DES()
{
	encryptDES();	//k3
	decryptDES();	//k2
	encryptDES();	//k1
}

void decrypt3DES()
{
	decryptDES();	//k1
	encryptDES();	//k2
	decryptDES();	//k3
}


/*
Triple DES uses a "key bundle" which comprises three DES keys, K1, K2 and K3, each of 56 bits (excluding parity bits). The encryption algorithm is:
	ciphertext = EK3(DK2(EK1(plaintext)))

I.e., DES encrypt with K1, DES decrypt with K2, then DES encrypt with K3.

Decryption is the reverse:
	plaintext = DK1(EK2(DK3(ciphertext)))
I.e., decrypt with K3, encrypt with K2, then decrypt with K1.

Each triple encryption encrypts one block of 64 bits of data.

In each case the middle operation is the reverse of the first and last.
This improves the strength of the algorithm when using keying option 2, and provides backward compatibility with DES with keying option 3.


The standards define three keying options:
Keying option 1: All three keys are independent.
Keying option 2: K1 and K2 are independent, and K3 = K1.
Keying option 3: All three keys are identical, i.e. K1 = K2 = K3.

Keying option 1 is the strongest, with 3 × 56 = 168 independent key bits.

Keying option 2 provides less security, with 2 × 56 = 112 key bits.
This option is stronger than simply DES encrypting twice, e.g. with K1 and K2, because it protects against meet-in-the-middle attacks.

Keying option 3 is equivalent to DES, with only 56 key bits.
This option provides backward compatibility with DES, because the first and second DES operations cancel out.
It is no longer recommended by the National Institute of Standards and Technology (NIST),[6] and is not supported by ISO/IEC 18033-3.
*/