#pragma once

/*****************************\
* Christiaan Rakowski
* Crypto Collection
* Derived work: Origional work by nguyenduc@icu.ac.kr http://code.google.com/p/libmcrypto/
*
* SHA-1 Hash
* Safety:	Like with MD5 rainbow tables are widely available and collisions have been proven. Using SHA-1 is unwise for sensitive data.
* FunFact:	SHA = "Schneier has access" SHA2 = "Schneier has access - and a spare too" http://www.schneierfacts.com/fact/867
\*****************************/

#include "../Crypto/SpecialMath.h"

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
