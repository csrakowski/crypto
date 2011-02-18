#include "Crypto.h"
#include <stdio.h>
#include <string.h>

/*****************************\
* Christiaan Rakowski
* Crypto Collection
\*****************************/

int main(int argc, char *argv[])
{
	//char* enc = VigenereEncodeMessage("MyMessage", "privatekey");
	//printf("%s\n", enc);

	//char* un = VigenereDecodeMessage(enc, "privatekey");
	//printf("%s\n", un);

	/*int i;
	for(i=0; i<100; i++)
	{
	ulong r = generatePrime();
	printf("%ld\n", r);
	}*/

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

	/* For each command line argument in turn:
	** filename          -- prints message digest and name of file
	** -sstring          -- prints message digest and contents of string
	** -t                -- prints time trial statistics for 1M characters
	** -x                -- execute a standard suite of test data
	** (no args)         -- writes messages digest of stdin onto stdout
	*/

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
	return 0;
}