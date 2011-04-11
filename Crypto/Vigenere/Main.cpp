#include "Vigenere.h"
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
	printf("Plain: %s\n", buf);
	VigenereEncipher(buf, "BRUCESCHNEIER");
	printf("Ciphered: %s\n", buf);	
	VigenereDecipher(buf, "BRUCESCHNEIER");
	printf("Deciphered: %s\n", buf);

	return 0;
}