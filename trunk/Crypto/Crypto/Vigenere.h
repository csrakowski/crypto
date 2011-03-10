#pragma once

/*****************************\
* Christiaan Rakowski
* Crypto Collection
\*****************************/
#include "VigenereTable.h"

#ifdef __cplusplus
extern "C" {
#endif

void VigenereEncodeMessage(char* encMessage, char* message, char* key);
void VigenereDecodeMessage(char* message, char* encMessage, char* key);

#ifdef __cplusplus
}
#endif
