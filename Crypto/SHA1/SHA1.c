/*****************************\
* Christiaan Rakowski
* Crypto Collection
*
* SHA-1 Hash
\*****************************/

#include "SHA1.h"
#include <stdio.h>
#include <string.h>
#include "../SpecialMath/SpecialMath.h"

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
#define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xFF00FF00)|(rol(block->l[i],8)&0x00FF00FF))

#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15]^block->l[(i+2)&15]^block->l[i&15],1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);

typedef union {
    byte c[64];
    uint l[16];
} CHAR64LONG16;

/* Hash a single 512-bit block. This is the core of the algorithm. */
void SHA1Transform(uint state[5], byte buffer[64])
{
    uint a, b, c, d, e;
    
    CHAR64LONG16* block;
    
    block = (CHAR64LONG16*)buffer;

    /* Copy context->state[] to working vars */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    /* 4 rounds of 20 operations each. Loop unrolled. */
    R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
    R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
    R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
    R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
    R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
    R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
    R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
    R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
    R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
    R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
    R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
    R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
    R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
    R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
    R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
    R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
    R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
    R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
    R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
    R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);
    
    /* Add the working vars back into context.state[] */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    
    /* Wipe variables */
    a = b = c = d = e = 0;
}

void SHA1Init (SHA1_CTX* context)
{
	// Load magic initialization constants.
	//The constant values used are chosen as nothing up my sleeve numbers: the four round constants k are 230 times the square roots of 2, 3, 5 and 10.
	//The first four starting values for h0 through h3 are the same as the MD5 algorithm, and the fifth (for h4) is similar.
	context->state[0] = 0x67452301;
	context->state[1] = 0xEFCDAB89;
	context->state[2] = 0x98BADCFE;
	context->state[3] = 0x10325476;
	context->state[4] = 0xC3D2E1F0;
	context->count[0] = context->count[1] = 0;
}

void SHA1Update(SHA1_CTX* context, uchar* data, uint len)
{
	uint i, j;

    j = (context->count[0] >> 3) & 63;
    
    if ((context->count[0] += len << 3) < (len << 3)) context->count[1]++;
    context->count[1] += (len >> 29);
    
    if ((j + len) > 63) {
        memcpy(&context->buffer[j], data, (i = 64-j));
        SHA1Transform(context->state, context->buffer);
        
        for ( ; i + 63 < len; i += 64) {
            SHA1Transform(context->state, &data[i]);
        }
        j = 0;
    }
    else i = 0;
    
    memcpy(&context->buffer[j], &data[i], len - i);
}

void SHA1Final(SHA1_CTX* context)
{
	uint i, j;
    byte finalcount[8];

    for (i = 0; i < 8; i++) {
        finalcount[i] = (byte)((context->count[(i >= 4 ? 0 : 1)]
         >> ((3-(i & 3)) * 8) ) & 255);  /* Endian independent */
    }
    
    SHA1Update(context, (byte*)"\200", 1);
    
    while ((context->count[0] & 504) != 448) {
        SHA1Update(context, (byte*)"\0", 1);
    }
    
    SHA1Update(context, finalcount, 8);  /* Should cause a SHA1Transform() */
    for (i = 0; i < 20; i++) {
        context->digest[i] = (byte)((context->state[i>>2] >> ((3-(i & 3)) * 8) ) & 255);
    }
    
    /* Wipe variables */
    i = j = 0;
    memset(context->buffer, 0, 64);
    memset(context->state, 0, 20);
    memset(context->count, 0, 8);
    memset(&finalcount, 0, 8);
}

/* Prints message digest buffer in context as 32 hexadecimal digits.
Order is from low-order byte to high-order byte of digest.
Each byte is printed with high-order hexadecimal digit first.
*/
void SHA1Print(SHA1_CTX* context)
{
	int i;
	for (i = 0; i < 20; i++)
		printf ("%02x", context->digest[i]);
	printf("\n");
}

/* Computes the message digest for string inString.
Prints out message digest, a space, the string (in quotes) and a
carriage return.
*/
void SHA1String(char* inString, SHA1_CTX* context)
{
	SHA1Init(context);
	SHA1Update(context, (uchar*)inString, strlen(inString));
	SHA1Final(context);
}

/* Computes the message digest for a specified file.
Prints out message digest, a space, the file name, and a carriage
return.
*/
void SHA1File(char* filename, SHA1_CTX* context)
{
	int bytes;
	byte data[1024];

	FILE *inFile;
	if(fopen_s(&inFile, filename, "rb"))
	{
		printf("%s can't be opened.\n", filename);
		return;
	}

	SHA1Init(context);
	while ((bytes = fread (data, 1, 1024, inFile)) != 0)
	{
		SHA1Update (context, data, bytes);
	}
	SHA1Final(context);
	fclose (inFile);
}

/* Runs a standard suite of test data.
*/
void SHA1TestSuite()
{
	SHA1_CTX context;
	printf("SHA test suite results:\n\n");

	SHA1String("", &context);
	SHA1Print(&context);
	printf("da39a3ee5e6b4b0d3255bfef95601890afd80709\n\n");

	SHA1String("a", &context);
	SHA1Print(&context);
	printf("86f7e437faa5a7fce15d1ddcb9eaeaea377667b8\n\n");

	SHA1String("abc", &context);
	SHA1Print(&context);
	printf("a9993e364706816aba3e25717850c26c9cd0d89d\n\n");

	SHA1String("message digest", &context);
	SHA1Print(&context);
	printf("c12252ceda8be8994d5fa0290a47231c1d16aae3\n\n");

	SHA1String("abcdefghijklmnopqrstuvwxyz", &context);
	SHA1Print(&context);
	printf("32d10c7b8cf96570ca04ce37f2a19d84240d3a89\n\n");

	SHA1String("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", &context);
	SHA1Print(&context);
	printf("761c457bf73b14d27e9e9265c46f4b4dda11f940\n\n");

	SHA1String("12345678901234567890123456789012345678901234567890123456789012345678901234567890", &context);
	SHA1Print(&context);
	printf("50abf5706a150990a08b2c5ea40fa0e585554732\n\n");	
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
		SHA1_CTX ctx;
		if(strcmp(argv[1], "-f") == 0)
		{
			SHA1File(argv[2], &ctx);
			SHA1Print(&ctx);
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
			SHA1String(buf, &ctx);
			SHA1Print(&ctx);
			return 0;
		}
	}

	printf("Invalid input, usage SHA1 <-f or -s> <file or string>\n");
	return 1;
}
