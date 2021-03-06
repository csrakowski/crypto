
/*****************************\
* Christiaan Rakowski
* Crypto Collection
* Derived work (sorta, refactored some things and changed layout) - See license below
*
* MD5 Hash
\*****************************/

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

#include <stdio.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include "MD5.h"
#include "../SpecialMath/SpecialMath.h"

/* F, G and H are basic MD5 functions: selection, majority, parity */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4 */
/* Rotation is separate from addition to prevent recomputation */
#define FF(a, b, c, d, x, s, ac) \
	{	(a) += F ((b), (c), (d)) + (x) + (uint)(ac); \
		(a) = ROLL ((a), (s)); \
		(a) += (b); \
	}
#define GG(a, b, c, d, x, s, ac) \
	{	(a) += G ((b), (c), (d)) + (x) + (uint)(ac); \
		(a) = ROLL ((a), (s)); \
		(a) += (b); \
	}
#define HH(a, b, c, d, x, s, ac) \
	{	(a) += H ((b), (c), (d)) + (x) + (uint)(ac); \
		(a) = ROLL ((a), (s)); \
		(a) += (b); \
	}
#define II(a, b, c, d, x, s, ac) \
	{	(a) += I ((b), (c), (d)) + (x) + (uint)(ac); \
		(a) = ROLL ((a), (s)); \
		(a) += (b); \
	}

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

/* Basic MD5 step. Transform buf based on in. */
void MD5Transform(uint* buf, uint* in)
{
	uint	a = buf[0],
			b = buf[1],
			c = buf[2],
			d = buf[3];

	/* Round 1 */
#define S11 7
#define S12 12
#define S13 17
#define S14 22
	FF ( a, b, c, d, in[ 0], S11, 3614090360); /* 1 */
	FF ( d, a, b, c, in[ 1], S12, 3905402710); /* 2 */
	FF ( c, d, a, b, in[ 2], S13,  606105819); /* 3 */
	FF ( b, c, d, a, in[ 3], S14, 3250441966); /* 4 */
	FF ( a, b, c, d, in[ 4], S11, 4118548399); /* 5 */
	FF ( d, a, b, c, in[ 5], S12, 1200080426); /* 6 */
	FF ( c, d, a, b, in[ 6], S13, 2821735955); /* 7 */
	FF ( b, c, d, a, in[ 7], S14, 4249261313); /* 8 */
	FF ( a, b, c, d, in[ 8], S11, 1770035416); /* 9 */
	FF ( d, a, b, c, in[ 9], S12, 2336552879); /* 10 */
	FF ( c, d, a, b, in[10], S13, 4294925233); /* 11 */
	FF ( b, c, d, a, in[11], S14, 2304563134); /* 12 */
	FF ( a, b, c, d, in[12], S11, 1804603682); /* 13 */
	FF ( d, a, b, c, in[13], S12, 4254626195); /* 14 */
	FF ( c, d, a, b, in[14], S13, 2792965006); /* 15 */
	FF ( b, c, d, a, in[15], S14, 1236535329); /* 16 */

	/* Round 2 */
#define S21 5
#define S22 9
#define S23 14
#define S24 20
	GG ( a, b, c, d, in[ 1], S21, 4129170786); /* 17 */
	GG ( d, a, b, c, in[ 6], S22, 3225465664); /* 18 */
	GG ( c, d, a, b, in[11], S23,  643717713); /* 19 */
	GG ( b, c, d, a, in[ 0], S24, 3921069994); /* 20 */
	GG ( a, b, c, d, in[ 5], S21, 3593408605); /* 21 */
	GG ( d, a, b, c, in[10], S22,   38016083); /* 22 */
	GG ( c, d, a, b, in[15], S23, 3634488961); /* 23 */
	GG ( b, c, d, a, in[ 4], S24, 3889429448); /* 24 */
	GG ( a, b, c, d, in[ 9], S21,  568446438); /* 25 */
	GG ( d, a, b, c, in[14], S22, 3275163606); /* 26 */
	GG ( c, d, a, b, in[ 3], S23, 4107603335); /* 27 */
	GG ( b, c, d, a, in[ 8], S24, 1163531501); /* 28 */
	GG ( a, b, c, d, in[13], S21, 2850285829); /* 29 */
	GG ( d, a, b, c, in[ 2], S22, 4243563512); /* 30 */
	GG ( c, d, a, b, in[ 7], S23, 1735328473); /* 31 */
	GG ( b, c, d, a, in[12], S24, 2368359562); /* 32 */

	/* Round 3 */
#define S31 4
#define S32 11
#define S33 16
#define S34 23
	HH ( a, b, c, d, in[ 5], S31, 4294588738); /* 33 */
	HH ( d, a, b, c, in[ 8], S32, 2272392833); /* 34 */
	HH ( c, d, a, b, in[11], S33, 1839030562); /* 35 */
	HH ( b, c, d, a, in[14], S34, 4259657740); /* 36 */
	HH ( a, b, c, d, in[ 1], S31, 2763975236); /* 37 */
	HH ( d, a, b, c, in[ 4], S32, 1272893353); /* 38 */
	HH ( c, d, a, b, in[ 7], S33, 4139469664); /* 39 */
	HH ( b, c, d, a, in[10], S34, 3200236656); /* 40 */
	HH ( a, b, c, d, in[13], S31,  681279174); /* 41 */
	HH ( d, a, b, c, in[ 0], S32, 3936430074); /* 42 */
	HH ( c, d, a, b, in[ 3], S33, 3572445317); /* 43 */
	HH ( b, c, d, a, in[ 6], S34,   76029189); /* 44 */
	HH ( a, b, c, d, in[ 9], S31, 3654602809); /* 45 */
	HH ( d, a, b, c, in[12], S32, 3873151461); /* 46 */
	HH ( c, d, a, b, in[15], S33,  530742520); /* 47 */
	HH ( b, c, d, a, in[ 2], S34, 3299628645); /* 48 */

	/* Round 4 */
#define S41 6
#define S42 10
#define S43 15
#define S44 21
	II ( a, b, c, d, in[ 0], S41, 4096336452); /* 49 */
	II ( d, a, b, c, in[ 7], S42, 1126891415); /* 50 */
	II ( c, d, a, b, in[14], S43, 2878612391); /* 51 */
	II ( b, c, d, a, in[ 5], S44, 4237533241); /* 52 */
	II ( a, b, c, d, in[12], S41, 1700485571); /* 53 */
	II ( d, a, b, c, in[ 3], S42, 2399980690); /* 54 */
	II ( c, d, a, b, in[10], S43, 4293915773); /* 55 */
	II ( b, c, d, a, in[ 1], S44, 2240044497); /* 56 */
	II ( a, b, c, d, in[ 8], S41, 1873313359); /* 57 */
	II ( d, a, b, c, in[15], S42, 4264355552); /* 58 */
	II ( c, d, a, b, in[ 6], S43, 2734768916); /* 59 */
	II ( b, c, d, a, in[13], S44, 1309151649); /* 60 */
	II ( a, b, c, d, in[ 4], S41, 4149444226); /* 61 */
	II ( d, a, b, c, in[11], S42, 3174756917); /* 62 */
	II ( c, d, a, b, in[ 2], S43,  718787259); /* 63 */
	II ( b, c, d, a, in[ 9], S44, 3951481745); /* 64 */

	buf[0] += a;
	buf[1] += b;
	buf[2] += c;
	buf[3] += d;
}

void MD5Init (MD5_CTX* mdContext)
{
	mdContext->i[0] = mdContext->i[1] = (uint)0;
	// Load magic initialization constants.
	mdContext->buf[0] = (uint)0x67452301;
	mdContext->buf[1] = (uint)0xefcdab89;
	mdContext->buf[2] = (uint)0x98badcfe;
	mdContext->buf[3] = (uint)0x10325476;
}

void MD5Update(MD5_CTX*  mdContext, uchar* inBuf, uint inLen)
{
	uint in[16];
	int mdi;
	unsigned int i, ii;

	/* compute number of bytes mod 64 */
	mdi = (int)((mdContext->i[0] >> 3) & 0x3F);

	/* update number of bits */
	if ((mdContext->i[0] + ((uint)inLen << 3)) < mdContext->i[0])
	{
		mdContext->i[1]++;
	}
	mdContext->i[0] += ((uint)inLen << 3);
	mdContext->i[1] += ((uint)inLen >> 29);

	while (inLen--)
	{
		/* add new character to buffer, increment mdi */
		mdContext->in[mdi++] = *inBuf++;

		/* transform if necessary */
		if (mdi == 0x40) // 0x40 = 64 (max size of mdContext->in[])
		{
			for (i = 0, ii = 0; i < 16; i++, ii += 4)
			{
				in[i] = (((uint)mdContext->in[ii+3]) << 24) | (((uint)mdContext->in[ii+2]) << 16) | (((uint)mdContext->in[ii+1]) << 8) | ((uint)mdContext->in[ii]);
			}
			MD5Transform (mdContext->buf, in);
			mdi = 0;
		}
	}
}

void MD5Final (MD5_CTX* mdContext)
{
	uint in[16];
	int mdi;
	uint i, ii;
	uint padLen;

	/* save number of bits */
	in[14] = mdContext->i[0];
	in[15] = mdContext->i[1];

	/* compute number of bytes mod 64 */
	mdi = (int)((mdContext->i[0] >> 3) & 0x3F);

	/* pad out to 56 mod 64 */
	padLen = (mdi < 56) ? (56 - mdi) : (120 - mdi);
	MD5Update (mdContext, PADDING, padLen);

	/* append length in bits and transform */
	for (i = 0, ii = 0; i < 14; i++, ii += 4)
	{
		in[i] = (((uint)mdContext->in[ii+3]) << 24) | (((uint)mdContext->in[ii+2]) << 16) | (((uint)mdContext->in[ii+1]) << 8) | ((uint)mdContext->in[ii]);
	}
	MD5Transform (mdContext->buf, in);
	
	/* store buffer in digest */
	for (i = 0, ii = 0; i < 4; i++, ii += 4)
	{
		mdContext->digest[ii] =	  (byte)(mdContext->buf[i] & 0xFF);
		mdContext->digest[ii+1] = (byte)((mdContext->buf[i] >> 8) & 0xFF);
		mdContext->digest[ii+2] = (byte)((mdContext->buf[i] >> 16) & 0xFF);
		mdContext->digest[ii+3] = (byte)((mdContext->buf[i] >> 24) & 0xFF);
	}
}

/* Prints message digest buffer in mdContext as 32 hexadecimal digits.
Order is from low-order byte to high-order byte of digest.
Each byte is printed with high-order hexadecimal digit first.
*/
void MD5Print(MD5_CTX* mdContext)
{
	int i;
	for (i = 0; i < 16; i++)
		printf ("%02x", mdContext->digest[i]);
	printf("\n");
}

/* Computes the message digest for string inString.
Prints out message digest, a space, the string (in quotes) and a
carriage return.
*/
void MD5String(char* inString, MD5_CTX* mdContext)
{
	MD5Init(mdContext);
	MD5Update(mdContext, (uchar*)inString, strlen(inString));
	MD5Final(mdContext);
}

/* Computes the message digest for a specified file.
Prints out message digest, a space, the file name, and a carriage
return.
*/
void MD5File(char* filename, MD5_CTX* mdContext)
{
	int bytes;
	byte data[1024];

	FILE *inFile;
	if(fopen_s(&inFile, filename, "rb"))
	{
		printf("%s can't be opened.\n", filename);
		return;
	}

	MD5Init (mdContext);
	while ((bytes = fread (data, 1, 1024, inFile)) != 0)
	{
		MD5Update (mdContext, data, bytes);
	}
	MD5Final (mdContext);
	fclose (inFile);
}

/* Runs a standard suite of test data.
*/
void MD5TestSuite()
{
	MD5_CTX mdContext;
	printf("MD5 test suite results:\n\n");

	MD5String("", &mdContext);
	MD5Print(&mdContext);
	printf("d41d8cd98f00b204e9800998ecf8427e\n\n");

	MD5String("a", &mdContext);
	MD5Print(&mdContext);
	printf("0cc175b9c0f1b6a831c399e269772661\n\n");

	MD5String("abc", &mdContext);
	MD5Print(&mdContext);
	printf("900150983cd24fb0d6963f7d28e17f72\n\n");

	MD5String("message digest", &mdContext);
	MD5Print(&mdContext);
	printf("f96b697d7cb7938d525a2f31aaf161d0\n\n");

	MD5String("abcdefghijklmnopqrstuvwxyz", &mdContext);
	MD5Print(&mdContext);
	printf("c3fcd3d76192e4007dfb496cca67e13b\n\n");

	MD5String("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", &mdContext);
	MD5Print(&mdContext);
	printf("d174ab98d277d9f5a5611c2c9f419d9f\n\n");

	MD5String("12345678901234567890123456789012345678901234567890123456789012345678901234567890", &mdContext);
	MD5Print(&mdContext);
	printf("57edf4a22be3c955ac49da2e2107b67a\n\n");
}

int main(int argc, char *argv[])
{
	int i = 0;

	if(argc < 3)
	{
		i = 1;
	}
	
	if(i == 0)
	{
		MD5_CTX ctx;
		if(strcmp(argv[1], "-f") == 0)
		{
			MD5File(argv[2], &ctx);
			MD5Print(&ctx);
			return 0;
		}
		else if(strcmp(argv[1], "-s") == 0)
		{
			char* buf;
			for(i=2; i<argc; i++)
			{
				buf = argv[i];
				buf += strlen(argv[i]);
			}
			MD5String(buf, &ctx);
			MD5Print(&ctx);
			return 0;
		}
	}

	printf("Invalid input, usage MD5 <-f or -s> <file or string>\n");
	return 1;
}