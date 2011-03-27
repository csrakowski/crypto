#include "Crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*****************************\
* Christiaan Rakowski
* Crypto Collection
\*****************************/

#define METHOD TRIPLEDES


int main(int argc, char *argv[])
{
	// Ceasar Cipher
	// Safety:	Easily Bruteforcable with only 25 possibilites, can be done on paper using language facts: http://www.oxforddictionaries.com/page/oecfactslanguage/the-oec-facts-about-the-language
	// FunFact:	It's often misquoted, but when Bruce Schneier killed Julius Caesar for promoting weak cryptography he actually said, "Et tu, Bruce?" http://www.schneierfacts.com/fact/807
#if METHOD == CEASAR
	char buf[255];
	sprintf_s(buf, "MYMESSAGE");
	printf("Plain: %s\n", buf);
	CeasarCipher(buf, 7);
	printf("Ciphered: %s\n", buf);
	CeasarCipher(buf, -7);
	printf("Deciphered: %s\n", buf);
#endif

	// Vigenere Cipher
	// Safety:	Bruteforcing is possible, but will take some time if key and message are of decent size.
	// FunFact:	A Vigenere cipher with the Key "BRUCESCHNEIER" is in fact unbreakable. http://www.schneierfacts.com/fact/40 
#if METHOD == VIGENERE	
	char buf[255];
	sprintf_s(buf, "M1Y2M3E4S5S6A7G8E9");
	printf("Plain: %s\n", buf);
	VigenereEncipher(buf, "BRUCESCHNEIER");
	printf("Ciphered: %s\n", buf);	
	VigenereDecipher(buf, "BRUCESCHNEIER");
	printf("Deciphered: %s\n", buf);
#endif

	// RSA Encryption - Core algorithm there, stuck on the size of the primes. 16^16 is 64 bit max already :'(
	// Safety:	RSA is very scalable, the bigger the prime numbers are the stronger the encryption will be, thus making RSA a very secure choice.
	// FunFact:	Bruce Schneier knows Alice and Bob's shared secret. http://www.schneierfacts.com/fact/18
#if METHOD == RSA
	RSA_private_key privkey;
	RSA_public_key pubkey;
	
	generate(&privkey);
	pubkey.n = privkey.n;
	pubkey.e = privkey.e;

	ulong in = 1;
	ulong out;
	ulong result;
	printf("Input: %ld\n", in);
	encrypt(&out, &in, &pubkey);	
	printf("Output: %ld\n", out);
	decrypt(&result, &out, &privkey);
	printf("Result: %ld\n", result);
#endif

	// 3DES (Triple DES) Encryption
	// Safety	Due to the key size it's not as secure as you can get with RSA, but it is still a valid choice
	// FunFact	Bruce Schneier PGP signs his grocery lists so that he can detect if someone has tampered with his milk. http://www.schneierfacts.com/fact/76
	//			There was no DES fun fact, so I'll leave the PGP one.
#if METHOD == TRIPLEDES
	
#endif

	// MD5 Hash
	// Safety:	Can be "reversed" using rainbowtables, which are widely available and even generating them yourself is no big deal.
	//			Also several studies have proven collisions in MD5 making unsalted MD5 a very unwise choice for sensitive data like passwords.
	// FunFact:	Bruce Schneier can calculate MD5 hashes in his head. For any length of data. In constant time. Drunk. http://www.schneierfacts.com/fact/1028
#if METHOD == MD5
	MD5TestSuite();
#endif
	
	// SHA-1 Hash
	// Safety:	Like with MD5 rainbow tables are widely available and collisions have been proven. Using SHA-1 is unwise for sensitive data.
	// FunFact:	SHA = "Schneier has access" SHA2 = "Schneier has access - and a spare too" http://www.schneierfacts.com/fact/867
#if METHOD == SHA1
	SHA1TestSuite();
#endif
	return 0;
}