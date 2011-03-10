#pragma once

/*****************************\
* Christiaan Rakowski
* Crypto Collection
\*****************************/
#include "VigenereTable.h"

#ifdef __cplusplus
extern "C" {
#endif

char* VigenereEncodeMessage(char* message, char* key);
char* VigenereDecodeMessage(char* message, char* key);

#ifdef __cplusplus
}
#endif
