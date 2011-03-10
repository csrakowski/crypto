#pragma once

/*****************************\
* Christiaan Rakowski
* Crypto Collection
\*****************************/

#include "SpecialMath.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Data structure for SHA1 computation */
typedef struct {
    uint state[5];
    uint count[2];
    byte buffer[64];
	byte digest[20];
} SHA1_CTX;

void SHA1Init(SHA1_CTX* context);
void SHA1Update(SHA1_CTX* context, uchar* data, uint len);
void SHA1Final(SHA1_CTX* context);

void SHA1Print (SHA1_CTX* context);
void SHA1String(char* inString, SHA1_CTX* context);
void SHA1File(char* filename, SHA1_CTX* context);
void SHA1TestSuite(void);

#ifdef __cplusplus
}
#endif
