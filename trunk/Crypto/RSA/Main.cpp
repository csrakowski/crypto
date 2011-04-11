#include "RSA.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*****************************\
* Christiaan Rakowski
* Crypto Collection
\*****************************/

int main(int argc, char *argv[])
{
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

	return 0;
}