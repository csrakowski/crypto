#include "Crypto.h"
#include <stdio.h>

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

	RSA_private_key privkey;
	RSA_public_key pubkey;

	generate(&privkey);
	test_keys(&privkey);
	pubkey.n = privkey.n;
	pubkey.e = privkey.e;

	ulong in = 0xABCDEF;
	ulong out;
	ulong result;
	printf("Input: %X\n", in);
	priv(&out, &in, &privkey);
	printf("Output: %X\n", out);
	pub(&result, &out, &pubkey);
	printf("Result: %X\n", result);

	return 0;
}