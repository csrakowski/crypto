#include "Ceasar.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*****************************\
* Christiaan Rakowski
* Crypto Collection
\*****************************/

int main(int argc, char *argv[])
{	
	char buf[255];
	sprintf_s(buf, "MYMESSAGE");
	printf("Plain: %s\n", buf);
	CeasarCipher(buf, 7);
	printf("Ciphered: %s\n", buf);
	CeasarCipher(buf, -7);
	printf("Deciphered: %s\n", buf);

	return 0;
}