#include "Crypto.h"
#include <stdio.h>
#include <string.h>

/*****************************\
* Christiaan Rakowski
* Crypto Collection
\*****************************/

#define METHOD RSA

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

	// RSA
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
	printf("Input: %d\n", in);
	encrypt(&out, &in, &pubkey);	
	printf("Output: %d\n", out);
	decrypt(&result, &out, &privkey);
	printf("Result: %d\n", result);
#endif

	// MD5
	// Bruce Schneier can calculate MD5 hashes in his head. For any length of data. In constant time. Drunk. http://www.schneierfacts.com/fact/1028
#if METHOD == MD5
	MD5_CTX hash;
	int i;
	for (i = 1; i < argc; i++)
	{
		if (strcmp (argv[i], "-s") == 0)
		{
			MDString(argv[i] + 3, &hash);
			MDPrint(&hash);
		}
		else if (strcmp (argv[i], "-x") == 0)
		{
			MDTestSuite();
		}
		else if (strcmp (argv[i], "-f") == 0)
		{
			MDFile(argv[i] + 3, &hash);
			MDPrint(&hash);
		}
	}
#endif

	// SHA-1
	// SHA = "Schneier has access" SHA2 = "Schneier has access - and a spare too" http://www.schneierfacts.com/fact/867
#if METHOD == SHA

#endif
	return 0;
}