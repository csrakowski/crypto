﻿//Note 1: All variables are unsigned 32 bits and wrap modulo 232 when calculating
//Note 2: All constants in this pseudo code are in big endian. 
//        Within each word, the most significant byte is stored in the leftmost byte position
//
//Initialize variables:
//h0 = 0x67452301
//h1 = 0xEFCDAB89
//h2 = 0x98BADCFE
//h3 = 0x10325476
//h4 = 0xC3D2E1F0
//
//Pre-processing:
//append the bit '1' to the message
//append 0 ≤ k < 512 bits '0', so that the resulting message length (in bits)
//   is congruent to 448 ≡ −64 (mod 512)
//append length of message (before pre-processing), in bits, as 64-bit big-endian integer
//
//Process the message in successive 512-bit chunks:
//break message into 512-bit chunks
//for each chunk
//    break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
//
//    Extend the sixteen 32-bit words into eighty 32-bit words:
//    for i from 16 to 79
//        w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1
//
//    Initialize hash value for this chunk:
//    a = h0
//    b = h1
//    c = h2
//    d = h3
//    e = h4
//
//    Main loop:
//    [27]
//    for i from 0 to 79
//        if 0 ≤ i ≤ 19 then
//            f = (b and c) or ((not b) and d)
//            k = 0x5A827999
//        else if 20 ≤ i ≤ 39
//            f = b xor c xor d
//            k = 0x6ED9EBA1
//        else if 40 ≤ i ≤ 59
//            f = (b and c) or (b and d) or (c and d) 
//            k = 0x8F1BBCDC
//        else if 60 ≤ i ≤ 79
//            f = b xor c xor d
//            k = 0xCA62C1D6
//
//        temp = (a leftrotate 5) + f + e + k + w[i]
//        e = d
//        d = c
//        c = b leftrotate 30
//        b = a
//        a = temp
//
//    Add this chunk's hash to result so far:
//    h0 = h0 + a
//    h1 = h1 + b 
//    h2 = h2 + c
//    h3 = h3 + d
//    h4 = h4 + e
//
//Produce the final hash value (big-endian):
//digest = hash = h0 append h1 append h2 append h3 append h4
//The constant values used are chosen as nothing up my sleeve numbers: the four round constants k are 230 times the square roots of 2, 3, 5 and 10. The first four starting values for h0 through h3 are the same as the MD5 algorithm, and the fifth (for h4) is similar.
//Instead of the formulation from the original FIPS PUB 180-1 shown, the following equivalent expressions may be used to compute f in the main loop above:
//(0  ≤ i ≤ 19): f = d xor (b and (c xor d))                (alternative 1)
//(0  ≤ i ≤ 19): f = (b and c) xor ((not b) and d)          (alternative 2)
//(0  ≤ i ≤ 19): f = (b and c) + ((not b) and d)            (alternative 3)
//(0  ≤ i ≤ 19): f = vec_sel(d, c, b)                       (alternative 4)
// 
//(40 ≤ i ≤ 59): f = (b and c) or (d and (b or c))          (alternative 1)
//(40 ≤ i ≤ 59): f = (b and c) or (d and (b xor c))         (alternative 2)
//(40 ≤ i ≤ 59): f = (b and c) + (d and (b xor c))          (alternative 3)
//(40 ≤ i ≤ 59): f = (b and c) xor (b and d) xor (c and d)  (alternative 4)
//Max Locktyukhin has also shown[28] that for the rounds 32–79 the computation of:
//      w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1
//can be replaced with:
//      w[i] = (w[i-6] xor w[i-16] xor w[i-28] xor w[i-32]) leftrotate 2
//This transformation keeps all operands 64-bit aligned and, by removing the dependency of w[i] on w[i-3], allows efficient SIMD implementation with a vector length of 4 such as x86 SSE instructions.


#include "SHA1.h"
#include <stdio.h>
#include <string.h>
#include "SpecialMath.h"

/* F, G and H are basic MD5 functions: selection, majority, parity */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z))) 

/* ROTATE_LEFT rotates x left n bits */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4 */
/* Rotation is separate from addition to prevent recomputation */
#define FF(a, b, c, d, x, s, ac) \
	{	(a) += F ((b), (c), (d)) + (x) + (ulong)(ac); \
		(a) = ROTATE_LEFT ((a), (s)); \
		(a) += (b); \
	}
#define GG(a, b, c, d, x, s, ac) \
	{	(a) += G ((b), (c), (d)) + (x) + (ulong)(ac); \
		(a) = ROTATE_LEFT ((a), (s)); \
		(a) += (b); \
	}
#define HH(a, b, c, d, x, s, ac) \
	{	(a) += H ((b), (c), (d)) + (x) + (ulong)(ac); \
		(a) = ROTATE_LEFT ((a), (s)); \
		(a) += (b); \
	}
#define II(a, b, c, d, x, s, ac) \
	{	(a) += I ((b), (c), (d)) + (x) + (ulong)(ac); \
		(a) = ROTATE_LEFT ((a), (s)); \
		(a) += (b); \
	}

void SHAInit (SHA_CTX* shaContext)
{
	shaContext->i[0] = shaContext->i[1] = (ulong)0;
	// Load magic initialization constants.
	shaContext->buf[0] = (ulong)0x67452301;
	shaContext->buf[1] = (ulong)0xefcdab89;
	shaContext->buf[2] = (ulong)0x98badcfe;
	shaContext->buf[3] = (ulong)0x10325476;
}

void SHAUpdate(SHA_CTX*  shaContext, uchar* inBuf, uint inLen)
{
	ulong in[16];
	int SHAi;
	unsigned int i, ii;

	/* compute number of bytes mod 64 */
	SHAi = (int)((shaContext->i[0] >> 3) & 0x3F);

	/* update number of bits */
	if ((shaContext->i[0] + ((ulong)inLen << 3)) < shaContext->i[0])
	{
		shaContext->i[1]++;
	}
	shaContext->i[0] += ((ulong)inLen << 3);
	shaContext->i[1] += ((ulong)inLen >> 29);

	while (inLen--)
	{
		/* add new character to buffer, increment SHAi */
		shaContext->in[SHAi++] = *inBuf++;

		/* transform if necessary */
		if (SHAi == 0x40) // 0x40 = 64 (max size of shaContext->in[])
		{
			for (i = 0, ii = 0; i < 16; i++, ii += 4)
			{
				in[i] = (((ulong)shaContext->in[ii+3]) << 24) | (((ulong)shaContext->in[ii+2]) << 16) | (((ulong)shaContext->in[ii+1]) << 8) | ((ulong)shaContext->in[ii]);
			}
			SHATransform (shaContext->buf, in);
			SHAi = 0;
		}
	}
}

void SHAFinal (SHA_CTX* shaContext)
{
	ulong in[16];
	int SHAi;
	uint i, ii;
	uint padLen;

	/* save number of bits */
	in[14] = shaContext->i[0];
	in[15] = shaContext->i[1];

	/* compute number of bytes mod 64 */
	SHAi = (int)((shaContext->i[0] >> 3) & 0x3F);

	/* pad out to 56 mod 64 */
	padLen = (SHAi < 56) ? (56 - SHAi) : (120 - SHAi);
	SHAUpdate (shaContext, PADDING2, padLen);

	/* append length in bits and transform */
	for (i = 0, ii = 0; i < 14; i++, ii += 4)
	{
		in[i] = (((ulong)shaContext->in[ii+3]) << 24) | (((ulong)shaContext->in[ii+2]) << 16) | (((ulong)shaContext->in[ii+1]) << 8) | ((ulong)shaContext->in[ii]);
	}
	SHATransform (shaContext->buf, in);
	
	/* store buffer in digest */
	for (i = 0, ii = 0; i < 4; i++, ii += 4)
	{
		shaContext->digest[ii] =	(byte)(shaContext->buf[i] & 0xFF);
		shaContext->digest[ii+1] =	(byte)((shaContext->buf[i] >> 8) & 0xFF);
		shaContext->digest[ii+2] =	(byte)((shaContext->buf[i] >> 16) & 0xFF);
		shaContext->digest[ii+3] =	(byte)((shaContext->buf[i] >> 24) & 0xFF);
	}
}

/* Basic SHA step. Transform buf based on in. */
static void SHATransform(ulong* buf, ulong* in)
{
	ulong	a = buf[0],
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

/* Prints message digest buffer in shaContext as 32 hexadecimal digits.
Order is from low-order byte to high-order byte of digest.
Each byte is printed with high-order hexadecimal digit first.
*/
void SHAPrint(SHA_CTX* shaContext)
{
	int i;
	for (i = 0; i < 16; i++)
		printf ("%02x", shaContext->digest[i]);
	printf("\n");
}

/* Computes the message digest for string inString.
Prints out message digest, a space, the string (in quotes) and a
carriage return.
*/
void SHAString(char* inString, SHA_CTX* shaContext)
{
	SHAInit(shaContext);
	SHAUpdate(shaContext, (uchar*)inString, strlen(inString));
	SHAFinal(shaContext);
}

/* Computes the message digest for a specified file.
Prints out message digest, a space, the file name, and a carriage
return.
*/
void SHAFile(char* filename, SHA_CTX* shaContext)
{
	int bytes;
	byte data[1024];

	FILE *inFile;
	if(fopen_s(&inFile, filename, "rb"))
	{
		printf("%s can't be opened.\n", filename);
		return;
	}

	SHAInit (shaContext);
	while ((bytes = fread (data, 1, 1024, inFile)) != 0)
	{
		SHAUpdate (shaContext, data, bytes);
	}
	SHAFinal (shaContext);
	fclose (inFile);
}

/* Runs a standard suite of test data.
*/
void SHATestSuite()
{
	SHA_CTX shaContext;
	printf("SHA test suite results:\n\n");
	SHAString("", &shaContext);
	SHAPrint(&shaContext);
	SHAString("a", &shaContext);
	SHAPrint(&shaContext);
	SHAString("abc", &shaContext);
	SHAPrint(&shaContext);
	SHAString("message digest", &shaContext);
	SHAPrint(&shaContext);
	SHAString("abcdefghijklmnopqrstuvwxyz", &shaContext);
	SHAPrint(&shaContext);
	SHAString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", &shaContext);
	SHAPrint(&shaContext);
	SHAString("12345678901234567890123456789012345678901234567890123456789012345678901234567890", &shaContext);
	SHAPrint(&shaContext);
}
