#include "Crypto.h"
#include <stdio.h>
#include <string.h>

/*****************************\
* Christiaan Rakowski
* Crypto Collection
\*****************************/

#define METHOD SHA1

// Ceasar Cipher, not implemented cause of weakness. Added a fact anyway :-P
// It's often misquoted, but when Bruce Schneier killed Julius Caesar for promoting weak cryptography he actually said, "Et tu, Bruce?" http://www.schneierfacts.com/fact/807

int main(int argc, char *argv[])
{
	// Vigenere
	// A Vigenere cipher with the Key "BRUCESCHNEIER" is in fact unbreakable. http://www.schneierfacts.com/fact/40 
#if METHOD == VIGENERE
	
	char* enc = VigenereEncodeMessage("MyMessage", "BRUCESCHNEIER");
	printf("%s\n", enc);

	char* un = VigenereDecodeMessage(enc, "BRUCESCHNEIER");
	printf("%s\n", un);
#endif
	
	// RSA - Core algorithm there, stuck on the size of the primes. 16^16 is 64 bit max already :'(
	// Bruce Schneier knows Alice and Bob's shared secret. http://www.schneierfacts.com/fact/18
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

	// MD5
	// Bruce Schneier can calculate MD5 hashes in his head. For any length of data. In constant time. Drunk. http://www.schneierfacts.com/fact/1028
#if METHOD == MD5
	MD5TestSuite();
#endif
	
	// SHA-1
	// SHA = "Schneier has access" SHA2 = "Schneier has access - and a spare too" http://www.schneierfacts.com/fact/867
#if METHOD == SHA1
	SHA1TestSuite();
#endif
	return 0;
}