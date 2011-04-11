
/*****************************\
* Christiaan Rakowski
* Crypto Collection
*
* Ceasar Cipher
\*****************************/

#include "Ceasar.h"
#include "../Crypto/SpecialMath.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void CeasarCipher(char* message, int shift)
{
	uint i, j;
	uint len = strlen(message);
	
	for(j=0; j < len; j++)
	{
		if(isalpha(message[j]))
		{
			message[j] = toupper(message[j]);
			for(i=0; i < 26; i++)
			{
				if(message[j] == alphabet[i])
				{
					message[j] = alphabet[mod(i+shift, 26)];
					break;
				}
			}
		}
	}
}

int main(int argc, char *argv[])
{
	int i, shifts;

	if(argc < 3)
	{
		printf("Invalid input, usage Ceasar <shifts> <message>\n");
		return 1;
	}
	
	shifts = atoi(argv[1]);
	for(i=2; i<argc; i++)
	{
		CeasarCipher(argv[i], shifts);
		printf("%s ", argv[i]);
	}

	return 0;

	/*char buf[255];
	sprintf_s(buf, "%s", "MYMESSAGE");
	printf("Plain: %s\n", buf);
	CeasarCipher(buf, 7);
	printf("Ciphered: %s\n", buf);
	CeasarCipher(buf, -7);
	printf("Deciphered: %s\n", buf);*/
}
