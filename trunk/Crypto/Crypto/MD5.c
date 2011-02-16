/*
 **********************************************************************
 ** md5.c                                                            **
 ** RSA Data Security, Inc. MD5 Message Digest Algorithm             **
 ** Created: 2/17/90 RLR                                             **
 ** Revised: 1/91 SRD,AJ,BSK,JT Reference C Version                  **
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

/* -- include the following line if the md5.h header file is separate -- */
#include "MD5.h"

/* forward declaration */
static void Transform ();

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
  {(a) += F ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) \
  {(a) += G ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) \
  {(a) += H ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) \
  {(a) += I ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }

void MD5Init (MD5_CTX* mdContext)
{
  mdContext->i[0] = mdContext->i[1] = (UINT4)0;

  /* Load magic initialization constants.
   */
  mdContext->buf[0] = (UINT4)0x67452301;
  mdContext->buf[1] = (UINT4)0xefcdab89;
  mdContext->buf[2] = (UINT4)0x98badcfe;
  mdContext->buf[3] = (UINT4)0x10325476;
}

void MD5Update(MD5_CTX*  mdContext, unsigned char* inBuf, unsigned int inLen)
{
  UINT4 in[16];
  int mdi;
  unsigned int i, ii;

  /* compute number of bytes mod 64 */
  mdi = (int)((mdContext->i[0] >> 3) & 0x3F);

  /* update number of bits */
  if ((mdContext->i[0] + ((UINT4)inLen << 3)) < mdContext->i[0])
    mdContext->i[1]++;
  mdContext->i[0] += ((UINT4)inLen << 3);
  mdContext->i[1] += ((UINT4)inLen >> 29);

  while (inLen--) {
    /* add new character to buffer, increment mdi */
    mdContext->in[mdi++] = *inBuf++;

    /* transform if necessary */
    if (mdi == 0x40) {
      for (i = 0, ii = 0; i < 16; i++, ii += 4)
        in[i] = (((UINT4)mdContext->in[ii+3]) << 24) |
                (((UINT4)mdContext->in[ii+2]) << 16) |
                (((UINT4)mdContext->in[ii+1]) << 8) |
                ((UINT4)mdContext->in[ii]);
      Transform (mdContext->buf, in);
      mdi = 0;
    }
  }
}

void MD5Final (MD5_CTX* mdContext)
{
  UINT4 in[16];
  int mdi;
  unsigned int i, ii;
  unsigned int padLen;

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
    in[i] = (((UINT4)mdContext->in[ii+3]) << 24) |
            (((UINT4)mdContext->in[ii+2]) << 16) |
            (((UINT4)mdContext->in[ii+1]) << 8) |
            ((UINT4)mdContext->in[ii]);
  Transform (mdContext->buf, in);

  /* store buffer in digest */
  for (i = 0, ii = 0; i < 4; i++, ii += 4) {
    mdContext->digest[ii] = (unsigned char)(mdContext->buf[i] & 0xFF);
    mdContext->digest[ii+1] =
      (unsigned char)((mdContext->buf[i] >> 8) & 0xFF);
    mdContext->digest[ii+2] =
      (unsigned char)((mdContext->buf[i] >> 16) & 0xFF);
    mdContext->digest[ii+3] =
      (unsigned char)((mdContext->buf[i] >> 24) & 0xFF);
  }
}

/* Basic MD5 step. Transform buf based on in.
 */
static void Transform(UINT4* buf, UINT4* in)
{
  UINT4 a = buf[0], b = buf[1], c = buf[2], d = buf[3];

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

/*
 **********************************************************************
 ** End of md5.c                                                     **
 ******************************* (cut) ********************************
 */

//#include "MD5.h"
//#include "SpecialMath.h"
//
//void MD5Hash(char* hash, uint input)
//{
//	uint k[64];
//
//	uint r[] = {7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
//				5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
//				4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
//				6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21 };
//
//	int i;
//	for(i=0;i<64;i++)
//	{
//	    k[i] = floor(abs(sin((double)i + 1))*(2^32));
//	}
//
//	uint h0 = 0x67452301;
//	uint h1 = 0xEFCDAB89;
//	uint h2 = 0x98BADCFE;
//	uint h3 = 0x10325476;
//	
//	uint stuff = input;
//	stuff<<=1;
//	stuff|=1;
//}


////Note: All variables are unsigned 32 bits and wrap modulo 2^32 when calculating
//var int[64] r, k
////r specifies the per-round shift amounts
//r[ 0..15] := {7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22}
//r[16..31] := {5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20}
//r[32..47] := {4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23}
//r[48..63] := {6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21}
////Use binary integer part of the sines of integers (Radians) as constants:
//for i from 0 to 63
//    k[i] := floor(abs(sin(i + 1)) × (2 pow 32))
////Initialize variables:
//var int h0 := 0x67452301
//var int h1 := 0xEFCDAB89
//var int h2 := 0x98BADCFE
//var int h3 := 0x10325476
////Pre-processing:
//append "1" bit to message
//append "0" bits until message length in bits = 448 (mod 512)
//append bit /* bit, not byte */ length of unpadded message as 64-bit little-endian integer to message
////Process the message in successive 512-bit chunks:
//for each 512-bit chunk of message
//    break chunk into sixteen 32-bit little-endian words w[j], 0 = j = 15
//    //Initialize hash value for this chunk:
//    var int a := h0
//    var int b := h1
//    var int c := h2
//    var int d := h3
//    //Main loop:
//    for i from 0 to 63
//        if 0 = i = 15 then
//            f := (b and c) or ((not b) and d)
//            g := i
//        else if 16 = i = 31
//            f := (d and b) or ((not d) and c)
//            g := (5×i + 1) mod 16
//        else if 32 = i = 47
//            f := b xor c xor d
//            g := (3×i + 5) mod 16
//        else if 48 = i = 63
//            f := c xor (b or (not d))
//            g := (7×i) mod 16
//        temp := d
//        d := c
//        c := b
//        b := b + leftrotate((a + f + k[i] + w[g]) , r[i])
//        a := temp
//    //Add this chunk's hash to result so far:
//    h0 := h0 + a
//    h1 := h1 + b
//    h2 := h2 + c
//    h3 := h3 + d
//var char digest[16] := h0 append h1 append h2 append h3 //(expressed as little-endian)
//  //leftrotate function definition
//  leftrotate (x, c)
//      return (x << c) or (x >> (32-c));
//Note: Instead of the formulation from the original RFC 1321 shown, the following may be used for improved efficiency (useful if assembly language is being used - otherwise, the compiler will generally optimize the above code. Since each computation is dependent on another in these formulations, this is often slower than the above method where the nand/and can be parallelised):
//(0  = i = 15): f := d xor (b and (c xor d))
//(16 = i = 31): f := c xor (d and (b xor c))


/* MD5
 converted to C++ class by Frank Thilo (thilo@unix-ag.org)
 for bzflag (http://www.bzflag.org)

   based on:

   md5.h and md5.c
   reference implemantion of RFC 1321

   Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.

*/
//
///* interface header */
//#include "md5.h"
//
///* system implementation headers */
//#include <stdio.h>
//
//
//// Constants for MD5Transform routine.
//#define S11 7
//#define S12 12
//#define S13 17
//#define S14 22
//#define S21 5
//#define S22 9
//#define S23 14
//#define S24 20
//#define S31 4
//#define S32 11
//#define S33 16
//#define S34 23
//#define S41 6
//#define S42 10
//#define S43 15
//#define S44 21
//
/////////////////////////////////////////////////
//
//// F, G, H and I are basic MD5 functions.
//inline MD5::uint4 MD5::F(uint4 x, uint4 y, uint4 z) {
//  return x&y | ~x&z;
//}
//
//inline MD5::uint4 MD5::G(uint4 x, uint4 y, uint4 z) {
//  return x&z | y&~z;
//}
//
//inline MD5::uint4 MD5::H(uint4 x, uint4 y, uint4 z) {
//  return x^y^z;
//}
//
//inline MD5::uint4 MD5::I(uint4 x, uint4 y, uint4 z) {
//  return y ^ (x | ~z);
//}
//
//// rotate_left rotates x left n bits.
//inline MD5::uint4 MD5::rotate_left(uint4 x, int n) {
//  return (x << n) | (x >> (32-n));
//}
//
//// FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
//// Rotation is separate from addition to prevent recomputation.
//inline void MD5::FF(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) {
//  a = rotate_left(a+ F(b,c,d) + x + ac, s) + b;
//}
//
//inline void MD5::GG(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) {
//  a = rotate_left(a + G(b,c,d) + x + ac, s) + b;
//}
//
//inline void MD5::HH(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) {
//  a = rotate_left(a + H(b,c,d) + x + ac, s) + b;
//}
//
//inline void MD5::II(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) {
//  a = rotate_left(a + I(b,c,d) + x + ac, s) + b;
//}
//
////////////////////////////////////////////////
//
//// default ctor, just initailize
//MD5::MD5()
//{
//  init();
//}
//
////////////////////////////////////////////////
//
//// nifty shortcut ctor, compute MD5 for string and finalize it right away
//MD5::MD5(const std::string &text)
//{
//  init();
//  update(text.c_str(), text.length());
//  finalize();
//}
//
////////////////////////////////
//
//void MD5::init()
//{
//  finalized=false;
//
//  count[0] = 0;
//  count[1] = 0;
//
//  // load magic initialization constants.
//  state[0] = 0x67452301;
//  state[1] = 0xefcdab89;
//  state[2] = 0x98badcfe;
//  state[3] = 0x10325476;
//}
//
////////////////////////////////
//
//// decodes input (unsigned char) into output (uint4). Assumes len is a multiple of 4.
//void MD5::decode(uint4 output[], const uint1 input[], size_type len)
//{
//  for (unsigned int i = 0, j = 0; j < len; i++, j += 4)
//    output[i] = ((uint4)input[j]) | (((uint4)input[j+1]) << 8) |
//      (((uint4)input[j+2]) << 16) | (((uint4)input[j+3]) << 24);
//}
//
////////////////////////////////
//
//// encodes input (uint4) into output (unsigned char). Assumes len is
//// a multiple of 4.
//void MD5::encode(uint1 output[], const uint4 input[], size_type len)
//{
//  for (size_type i = 0, j = 0; j < len; i++, j += 4) {
//    output[j] = input[i] & 0xff;
//    output[j+1] = (input[i] >> 8) & 0xff;
//    output[j+2] = (input[i] >> 16) & 0xff;
//    output[j+3] = (input[i] >> 24) & 0xff;
//  }
//}
//
////////////////////////////////
//
//// apply MD5 algo on a block
//void MD5::transform(const uint1 block[blocksize])
//{
//  uint4 a = state[0], b = state[1], c = state[2], d = state[3], x[16];
//  decode (x, block, blocksize);
//
//  /* Round 1 */
//  FF (a, b, c, d, x[ 0], S11, 0xd76aa478); /* 1 */
//  FF (d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2 */
//  FF (c, d, a, b, x[ 2], S13, 0x242070db); /* 3 */
//  FF (b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4 */
//  FF (a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5 */
//  FF (d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6 */
//  FF (c, d, a, b, x[ 6], S13, 0xa8304613); /* 7 */
//  FF (b, c, d, a, x[ 7], S14, 0xfd469501); /* 8 */
//  FF (a, b, c, d, x[ 8], S11, 0x698098d8); /* 9 */
//  FF (d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10 */
//  FF (c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
//  FF (b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
//  FF (a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
//  FF (d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
//  FF (c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
//  FF (b, c, d, a, x[15], S14, 0x49b40821); /* 16 */
//
//  /* Round 2 */
//  GG (a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17 */
//  GG (d, a, b, c, x[ 6], S22, 0xc040b340); /* 18 */
//  GG (c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
//  GG (b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20 */
//  GG (a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21 */
//  GG (d, a, b, c, x[10], S22,  0x2441453); /* 22 */
//  GG (c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
//  GG (b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24 */
//  GG (a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25 */
//  GG (d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
//  GG (c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27 */
//  GG (b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28 */
//  GG (a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
//  GG (d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30 */
//  GG (c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31 */
//  GG (b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */
//
//  /* Round 3 */
//  HH (a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */
//  HH (d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */
//  HH (c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
//  HH (b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
//  HH (a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */
//  HH (d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */
//  HH (c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */
//  HH (b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
//  HH (a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
//  HH (d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */
//  HH (c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */
//  HH (b, c, d, a, x[ 6], S34,  0x4881d05); /* 44 */
//  HH (a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */
//  HH (d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
//  HH (c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
//  HH (b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */
//
//  /* Round 4 */
//  II (a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */
//  II (d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */
//  II (c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
//  II (b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */
//  II (a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
//  II (d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */
//  II (c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
//  II (b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */
//  II (a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */
//  II (d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
//  II (c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */
//  II (b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
//  II (a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */
//  II (d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
//  II (c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */
//  II (b, c, d, a, x[ 9], S44, 0xeb86d391); /* 64 */
//
//  state[0] += a;
//  state[1] += b;
//  state[2] += c;
//  state[3] += d;
//
//  // Zeroize sensitive information.
//  memset(x, 0, sizeof x);
//}
//
////////////////////////////////
//
//// MD5 block update operation. Continues an MD5 message-digest
//// operation, processing another message block
//void MD5::update(const unsigned char input[], size_type length)
//{
//  // compute number of bytes mod 64
//  size_type index = count[0] / 8 % blocksize;
//
//  // Update number of bits
//  if ((count[0] += (length << 3)) < (length << 3))
//    count[1]++;
//  count[1] += (length >> 29);
//
//  // number of bytes we need to fill in buffer
//  size_type firstpart = 64 - index;
//
//  size_type i;
//
//  // transform as many times as possible.
//  if (length >= firstpart)
//  {
//    // fill buffer first, transform
//    memcpy(&buffer[index], input, firstpart);
//    transform(buffer);
//
//    // transform chunks of blocksize (64 bytes)
//    for (i = firstpart; i + blocksize <= length; i += blocksize)
//      transform(&input[i]);
//
//    index = 0;
//  }
//  else
//    i = 0;
//
//  // buffer remaining input
//  memcpy(&buffer[index], &input[i], length-i);
//}
//
////////////////////////////////
//
//// for convenience provide a verson with signed char
//void MD5::update(const char input[], size_type length)
//{
//  update((const unsigned char*)input, length);
//}
//
////////////////////////////////
//
//// MD5 finalization. Ends an MD5 message-digest operation, writing the
//// the message digest and zeroizing the context.
//MD5& MD5::finalize()
//{
//  static unsigned char padding[64] = {
//    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
//  };
//
//  if (!finalized) {
//    // Save number of bits
//    unsigned char bits[8];
//    encode(bits, count, 8);
//
//    // pad out to 56 mod 64.
//    size_type index = count[0] / 8 % 64;
//    size_type padLen = (index < 56) ? (56 - index) : (120 - index);
//    update(padding, padLen);
//
//    // Append length (before padding)
//    update(bits, 8);
//
//    // Store state in digest
//    encode(digest, state, 16);
//
//    // Zeroize sensitive information.
//    memset(buffer, 0, sizeof buffer);
//    memset(count, 0, sizeof count);
//
//    finalized=true;
//  }
//
//  return *this;
//}
//
////////////////////////////////
//
//// return hex representation of digest as string
//std::string MD5::hexdigest() const
//{
//  if (!finalized)
//    return "";
//
//  char buf[33];
//  for (int i=0; i<16; i++)
//    sprintf(buf+i*2, "%02x", digest[i]);
//  buf[32]=0;
//
//  return std::string(buf);
//}
//
////////////////////////////////
//
//std::ostream& operator<<(std::ostream& out, MD5 md5)
//{
//  return out << md5.hexdigest();
//}
//
////////////////////////////////
//
//std::string md5(const std::string str)
//{
//    MD5 md5 = MD5(str);
//
//    return md5.hexdigest();
//}
