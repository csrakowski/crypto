#include "Crypto.h"
#include <stdio.h>

/*****************************\
* Christiaan Rakowski
* Crypto Collection
\*****************************/

int main(int argc, char *argv[])
{
	char* enc = VigenereEncodeMessage("MyMessage", "privatekey");
	printf("%s\n", enc);

	char* un = VigenereDecodeMessage(enc, "privatekey");
	printf("%s\n", un);
	return 0;
}