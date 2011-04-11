
/*****************************\
* Christiaan Rakowski
* Crypto Collection
*
* Ceasar Cipher
\*****************************/

#include "Ceasar.h"
#include "../Crypto/SpecialMath.h"
#include <ctype.h>
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
