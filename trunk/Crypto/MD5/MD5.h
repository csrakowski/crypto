#pragma once

/*****************************\
* Christiaan Rakowski
* Crypto Collection
* Derived work (sorta, refactored some things and changed layout) - See license below
*
* MD5 Hash
* Safety:	Can be "reversed" using rainbowtables, which are widely available and even generating them yourself is no big deal.
*			Also several studies have proven collisions in MD5 making unsalted MD5 a very unwise choice for sensitive data like passwords.
* FunFact:	Bruce Schneier can calculate MD5 hashes in his head. For any length of data. In constant time. Drunk. http://www.schneierfacts.com/fact/1028
\*****************************/

/*
 **********************************************************************
 ** md5.h -- Header file for implementation of MD5                   **
 ** RSA Data Security, Inc. MD5 Message Digest Algorithm             **
 ** Created: 2/17/90 RLR                                             **
 ** Revised: 12/27/90 SRD,AJ,BSK,JT Reference C version              **
 ** Revised (for MD5): RLR 4/27/91                                   **
 **   -- G modified to have y&~z instead of y&z                      **
 **   -- FF, GG, HH modified to add in last register done            **
 **   -- Access pattern: round 2 works mod 5, round 3 works mod 3    **
 **   -- distinct additive constant for each step                    **
 **   -- round 4 added, working mod 7                                **
 **********************************************************************
 */

/*
 **********************************************************************
 ** Copyright (C) 1990, RSA Data Security, Inc. All rights reserved. **
 **                                                                  **
 ** License to copy and use this software is granted provided that   **
 ** it is identified as the "RSA Data Security, Inc. MD5 Message     **
 ** Digest Algorithm" in all material mentioning or referencing this **
 ** software or this function.                                       **
 **                                                                  **
 ** License is also granted to make and use derivative works         **
 ** provided that such works are identified as "derived from the RSA **
 ** Data Security, Inc. MD5 Message Digest Algorithm" in all         **
 ** material mentioning or referencing the derived work.             **
 **                                                                  **
 ** RSA Data Security, Inc. makes no representations concerning      **
 ** either the merchantability of this software or the suitability   **
 ** of this software for any particular purpose.  It is provided "as **
 ** is" without express or implied warranty of any kind.             **
 **                                                                  **
 ** These notices must be retained in any copies of any part of this **
 ** documentation and/or software.                                   **
 **********************************************************************
 */

#include "../SpecialMath/SpecialMath.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Data structure for MD5 (Message Digest) computation */
typedef struct {
  uint i[2];			/* number of _bits_ handled mod 2^64 */
  uint buf[4];			/* scratch buffer */
  byte in[64];			/* input buffer */
  byte digest[16];		/* actual digest after MD5Final call */
} MD5_CTX;

void MD5Init(MD5_CTX* mdContext);
void MD5Update(MD5_CTX* mdContext, uchar* inBuf, uint inLen);
void MD5Final(MD5_CTX* mdContext);

void MD5Print (MD5_CTX* mdContext);
void MD5String(char* inString, MD5_CTX* mdContext);
void MD5File(char* filename, MD5_CTX* mdContext);
void MD5TestSuite();

#ifdef __cplusplus
}
#endif
