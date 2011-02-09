#include "Crypto.h"
#include <stdio.h>

/*****************************\
* Christiaan Rakowski
* Crypto Collection
\*****************************/

int main(int argc, char *argv[])
{
	char* enc;

	enc = VigenereMessage("MyMessage", "LOL");
	printf("%s", enc);
	return 0;
}