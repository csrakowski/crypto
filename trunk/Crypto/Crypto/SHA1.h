#pragma once

/*****************************\
* Christiaan Rakowski
* Crypto Collection
\*****************************/

#include "SpecialMath.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Data structure for MD5 (Message Digest) computation */
typedef struct {
  ulong i[2];           /* number of _bits_ handled mod 2^64 */
  ulong buf[4];         /* scratch buffer */
  byte in[64];          /* input buffer */
  byte digest[16];		/* actual digest after MD5Final call */
} MD5_CTX;

// Padding for MDFinal
static unsigned char PADDING[64] = {
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

void MD5Init(MD5_CTX* mdContext);
void MD5Update(MD5_CTX* mdContext, uchar* inBuf, uint inLen);
void MD5Final(MD5_CTX* mdContext);
void Transform(ulong* buf, ulong* in);

void MDPrint (MD5_CTX* mdContext);
void MDString(char* inString, MD5_CTX* mdContext);
void MDFile(char* filename, MD5_CTX* mdContext);
void MDTestSuite();

#ifdef __cplusplus
}
#endif
