#include "Vigenere.h"
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

char* VigenereMessage(char* message, char* key)
{
	char* encMessage;
	//strcpy(encMessage, message);
	int err = strcpy_s(encMessage,strlen(message), message);

	int across;
	int down;
	int i;
	int j;

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