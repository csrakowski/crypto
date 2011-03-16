#pragma once

/*****************************\
* Christiaan Rakowski
* Crypto Collection
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