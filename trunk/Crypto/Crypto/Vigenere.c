#include "Vigenere.h"
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

/*****************************\
* Christiaan Rakowski
* Crypto Collection
\*****************************/

char* VigenereEncodeMessage(char* message, char* key)
{
	unsigned int across, down, i, j;
	char* encMessage = (char*)malloc(strlen(message)*sizeof(char));
	strcpy_s(encMessage,strlen(message),message);

	for(j = 0; j < strlen(encMessage); j++)
	{
		for(i = 0; i < 26; i++)
		{
			if( !(isalpha(message[j])))
			{
				across = 30;
				break;
			}

			if( ( toupper(message[j]) == table[0][i]))
			{
				across = i;
				break;
			}
		}
		
		for(i = 0; i < 26; i++)
		{	
			if( !(isalpha(message[j])))
			{
				down = 30;
				break;
			}
				
			if( ( toupper(key[j]) == table[i][0]))
			{
				down = i;
				break;
			}
		}
		
		if(across != 30 && down != 30)
			encMessage[j] = table[down][across];
	}
	return encMessage;
}

char* VigenereDecodeMessage(char* message, char* key)
{
	unsigned int across, down, i, j;
	char* unMessage = (char*)malloc(strlen(message)*sizeof(char));
	strcpy_s(unMessage,strlen(message),message);

	for(j = 0; j < strlen(message); j++)
	{
		for(i = 0; i < 26; i++)
		{
			if( !(isalpha(key[j])))
			{
				across = 30;
				break;
			}
			
			if( ( toupper(key[j]) == table[0][i]))
			{
				across = i;
				break;
			}
		}
		
		for(i = 0; i < 26; i++)
		{
			if( !(isalpha(message[j])))
			{
				down = 30;
				break;
			}
			
			if( ( toupper(message[j]) == table[i][across]))
			{
				down = i;
				break;
			}
		}
		
		if(down != 30)
			unMessage[j] = table[down][0];
	}
	return unMessage;
}