
/*****************************\
* Christiaan Rakowski
* Crypto Collection
*
* Vigenere Cipher
\*****************************/

#include "Vigenere.h"
#include "../Crypto/SpecialMath.h"
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

void VigenereEncipher(char* message, char* key)
{
	uint i, j;
	uint across = 0, down = 0;
	uint len = strlen(message)+1;
	uint keylen = strlen(key);
	
	for(j = 0; j < len; j++)
	{
		if(isalpha(message[j]) && isalpha(key[(j%keylen)]))
		{
			for(i = 0; i < 26; i++)
			{
				if((toupper(message[j]) == table[0][i]))
				{
					across = i;
					break;
				}
			}
			for(i = 0; i < 26; i++)
			{
				if((toupper(key[(j%keylen)]) == table[i][0]))
				{
					down = i;
					break;
				}
			}
			message[j] = table[down][across];
		}
	}
}

void VigenereDecipher(char* message, char* key)
{
	uint i, j;
	uint across = 0, down = 0;
	uint len = strlen(message)+1;
	uint keylen = strlen(key);

	for(j = 0; j < len; j++)
	{
		if(isalpha(message[j]) && isalpha(key[(j%keylen)]))
		{
			for(i = 0; i < 26; i++)
			{
				if((toupper(key[(j%keylen)]) == table[0][i]))
				{
					across = i;
					break;
				}
			}
			for(i = 0; i < 26; i++)
			{
				if((toupper(message[j]) == table[i][across]))
				{
					down = i;
					break;
				}
			}
			message[j] = table[down][0];
		}
	}
}
