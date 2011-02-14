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

	//int i;
	//for(i=0; i<100; i++)
	//{
	//	ulong r = crandom();
	//	printf("%d", r);
	//}

	RSA_private_key privkey;
	RSA_public_key pubkey;

	generate(&privkey, 8);
	test_keys(&privkey, 8);
	pubkey.n = privkey.n;
	pubkey.e = privkey.e;


	return 0;
}