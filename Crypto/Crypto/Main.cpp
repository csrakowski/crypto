#include "Crypto.h"
#include <stdio.h>
#include <string.h>

/*****************************\
* Christiaan Rakowski
* Crypto Collection
\*****************************/

int main(int argc, char *argv[])
{
	// Vigenere

	//char* enc = VigenereEncodeMessage("MyMessage", "privatekey");
	//printf("%s\n", enc);

	//char* un = VigenereDecodeMessage(enc, "privatekey");
	//printf("%s\n", un);

	// RSA

	//RSA_private_key privkey;
	//RSA_public_key pubkey;

	//generate(&privkey);
	//pubkey.n = privkey.n;
	//pubkey.e = privkey.e;

	//ulong in = 0xABCDEF;
	//ulong out;
	//ulong result;
	//printf("Input: %lX\n", in);
	//encrypt(&out, &in, &pubkey);	
	//printf("Output: %lX\n", out);
	//decrypt(&result, &out, &privkey);
	//printf("Result: %lX\n", result);

	// MD5

	/*MD5_CTX hash;
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
	}*/

	// SHA-1


	return 0;
}