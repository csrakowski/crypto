
/*****************************\
* Christiaan Rakowski
* Crypto Collection
*
* Vigenere Cipher
\*****************************/

#include "Vigenere.h"
#include "../SpecialMath/SpecialMath.h"
#include <stdlib.h>
#include <stdio.h>
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

int main(int argc, char *argv[])
{
	int i = 0;

	if(argc < 4)
	{
		i = 1;
	}
	
	if(i == 0)
	{
		if(argv[1] == "-e")
		{
			for(i=3; i<argc; i++)
			{
				VigenereEncipher(argv[i], argv[2]);
				printf("%s ", argv[i]);
			}
			return 0;
		}
		else if(argv[1] == "-d")
		{
			for(i=3; i<argc; i++)
			{
				VigenereDecipher(argv[i], argv[2]);
				printf("%s ", argv[i]);				
			}
			return 0;
		}
	}

	printf("Invalid input, usage Vigenere <-d or -e> <password> <message>\n");
	return 1;



	//char buf[255];
	//printf("Plain: %s\n", buf);
	//VigenereEncipher(buf, "BRUCESCHNEIER");
	//printf("Ciphered: %s\n", buf);	
	//VigenereDecipher(buf, "BRUCESCHNEIER");
	//printf("Deciphered: %s\n", buf);

	return 0;
}
