#pragma once

/*****************************\
* Christiaan Rakowski
* Crypto Collection
*
* Vigenere Cipher
* Safety:	Bruteforcing is possible, but will take some time if key and message are of decent size.
* FunFact:	A Vigenere cipher with the Key "BRUCESCHNEIER" is in fact unbreakable. http://www.schneierfacts.com/fact/40 
\*****************************/

#include "VigenereTable.h"

#ifdef __cplusplus
extern "C" {
#endif

void VigenereEncipher(char* message, char* key);
void VigenereDecipher(char* message, char* key);

#ifdef __cplusplus
}
#endif
