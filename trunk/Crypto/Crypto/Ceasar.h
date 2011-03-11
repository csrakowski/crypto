#pragma once

/*****************************\
* Christiaan Rakowski
* Crypto Collection
\*****************************/

#ifdef __cplusplus
extern "C" {
#endif

const static char alphabet[] = { 'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z' };

void CeasarCipher(char* message, int shift);

#ifdef __cplusplus
}
#endif
