#include "Vigenere.h"
#include "SpecialMath.h"
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

/*****************************\
* Christiaan Rakowski
* Crypto Collection
\*****************************/

void VigenereEncodeMessage(char* encMessage, char* message, char* key)
{
	uint i, j;
	uint across = 0, down = 0;
	uint len = strlen(message)+1;
	uint keylen = strlen(key);
	strcpy_s(encMessage, len, message);
	
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
			encMessage[j] = table[down][across];
		}
	}
}

void VigenereDecodeMessage(char* message, char* encMessage, char* key)
{
	uint i, j;
	uint across = 0, down = 0;
	uint len = strlen(encMessage)+1;
	uint keylen = strlen(key);
	strcpy_s(message, len, encMessage);

	for(j = 0; j < len; j++)
	{
		if(isalpha(encMessage[j]) && isalpha(key[(j%keylen)]))
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
				if((toupper(encMessage[j]) == table[i][across]))
				{
					down = i;
					break;
				}
			}
			message[j] = table[down][0];
		}
	}
}
