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
  uint i[2];			/* number of _bits_ handled mod 2^64 */
  uint buf[5];			/* scratch buffer */
  byte in[64];			/* input buffer */
  byte digest[16];		/* actual digest after MD5Final call */
} SHA_CTX;

// Padding for SHAFinal
static unsigned char PADDING2[64] = {
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

void SHAInit(SHA_CTX* shaContext);
void SHAUpdate(SHA_CTX* shaContext, uchar* inBuf, uint inLen);
void SHAFinal(SHA_CTX* shaContext);
void SHATransform(uint* buf, uint* in);

void SHAPrint (SHA_CTX* mdContext);
void SHAString(char* inString, SHA_CTX* shaContext);
void SHAFile(char* filename, SHA_CTX* shaContext);
void SHATestSuite();

#ifdef __cplusplus
}
#endif
