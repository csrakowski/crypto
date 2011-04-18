
/*****************************\
* Christiaan Rakowski
* Crypto Collection
*
* 3DES (Triple DES) Encryption
\*****************************/

#include "3DES.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../SpecialMath/SpecialMath.h"

void createDESKey(DES_KEY* key)
{
	int i,j;

	//for (j=0; j<56; j++)		/* convert pc1 to bits of key */
	//{
	//	l=pc1[j]-1;				/* integer bit location */
	//	m = l & 07;				/* find bit */
	//	pc1m[j]=(key[l>>3] &	/* find which key byte l is in */
	//		bytebit[m])			/* and which bit of that byte */
	//		? 1 : 0;			/* and store 1-bit result */
	//}
	for(i=0; i<56; i++)
	{
		key->kPlus |= ((key->k>>(56-pc1[i]))&1)<<(56-i);
	}

	key->c[0] = ((key->kPlus>>28)&0xFFFFFFF);
	key->d[0] = ((key->kPlus)&0xFFFFFFF);
	
	//for (i=0; i<16; i++) {          /* key chunk for each iteration */
	//	memset(ks,0,8);         /* Clear key schedule */
	//	for (j=0; j<56; j++)    /* rotate pc1 the right amount */
	//		pcr[j] = pc1m[(l=j+totrot[i])<(j<28? 28 : 56) ? l: l-28];
	//	/* rotate left and right halves independently */
	//	for (j=0; j<48; j++){   /* select bits individually */
	//		/* check bit that goes to ks[j] */
	//		if (pcr[pc2[j]-1]){
	//			/* mask it in if it's there */
	//			l= j % 6;
	//			ks[j/6] |= bytebit[l] >> 2;
	//		}
	//	}
	//	/* Now convert to odd/even interleaved form for use in F */
	//	k[2*i] = ((word32)ks[0] << 24)
	//		| ((word32)ks[2] << 16)
	//		| ((word32)ks[4] << 8)
	//		| ((word32)ks[6]);
	//	k[2*i+1] = ((word32)ks[1] << 24)
	//		| ((word32)ks[3] << 16)
	//		| ((word32)ks[5] << 8)
	//		| ((word32)ks[7]);
	//}	
	for(i=1; i<=16; i++)
	{
		key->c[i] = ROLL(key->c[i-1], rolls[i-1]);
		key->d[i] = ROLL(key->d[i-1], rolls[i-1]);

		for(j=0; j<48; j++)
		{
			int val = pc2[j];
			if(val < 28)
			{
				key->k2[i] |= (((key->c[i]>>(28-val))&1)<<(28-i));
				//key->k2[i] |= (key->c[i]&(1<<(28-val)));				
			}
			else
			{
				key->k2[i] |= (((key->c[i]>>(28-(val-28)))&1)<<(28-i));
			}
		}
	}
}

void create3DESKey(TDES_KEY* key)
{
	createDESKey(&key->k1);
	createDESKey(&key->k2);
	createDESKey(&key->k3);
}

void f(uint* out, uint* R, ulong* k)
{
	ulong E;
	uint preout;
	int i;

	//Expand R and xor key with Expanded R
	for(i=0; i<48; i++)
	{
		E |= (((*k>>(48-i))&1)^((*R>>(32-ei[i]))&1)<<(48-i));
	}

	/*
	We now have 48 bits, or eight groups of six bits.
	We now do something strange with each group of six bits: we use them as addresses in tables called "S boxes".
	Each group of six bits will give us an address in a different S box.
	Located at that address will be a 4 bit number.

	This 4 bit number will replace the original 6 bits.
	The net result is that the eight groups of 6 bits are transformed into eight groups of 4 bits (the 4-bit outputs from the S boxes) for 32 bits total.
	Write the previous result, which is 48 bits, in the form:

	Kn + E(Rn-1) =B1B2B3B4B5B6B7B8,
	where each Bi is a group of six bits. We now calculate

	S1(B1)S2(B2)S3(B3)S4(B4)S5(B5)S6(B6)S7(B7)S8(B8)
	where Si(Bi) referres to the output of the i-th S box.

	To repeat, each of the functions S1, S2,..., S8, takes a 6-bit block as input and yields a 4-bit block as output.

	If S1 is the function defined in this table and B is a block of 6 bits, then S1(B) is determined as follows:
	The first and last bits of B represent in base 2 a number in the decimal range 0 to 3 (or binary 00 to 11).
	Let that number be i. The middle 4 bits of B represent in base 2 a number in the decimal range 0 to 15 (binary 0000 to 1111).
	Let that number be j. Look up in the table the number in the i-th row and j-th column.
	It is a number in the range 0 to 15 and is uniquely represented by a 4 bit block.
	That block is the output S1(B) of S1 for the input B. For example, for input block B = 011011 the first bit is "0" and the last bit "1" giving 01 as the row.
	This is row 1. The middle four bits are "1101". This is the binary equivalent of decimal 13, so the column is column number 13. In row 1, column 13 appears 5.
	This determines the output; 5 is binary 0101, so that the output is 0101. Hence S1(011011) = 0101.
	*/

	for(i=0; i<8; i++)
	{
		int r = sbox[i][((((E>>(46-(6*i)))&2) | ((E>>(43-(6*i)))&1)) * ((E>>(46-(6*i)))&15))];
		preout |= (r<<(32-(4*i)));
	}
	
	for(i=0; i<32; i++)
	{
		*out |= ((preout>>(32-p32i[i]))&1);
	}
}

void encryptDES(DES_KEY* key, ulong* M, ulong* out)
//void encryptDES(DES_KEY* key, byte M[8], byte out[8])
{
	//TODO FIX MEH D:
	ulong IP;
	uint Left;
	uint Left2;
	uint Right;
	ulong res;
	uint tmp;
	int i,j;

	IP ^= IP;
	for(i=0; i<64; i++)
	{
		IP |= (((*M>>(64-ip[i]))&1)<<(64-i));
	}

	Left = (IP>>32);
	Right = (IP&UINT_MAX);

	for(i=1; i<17; i++)
	{
		Left2 = Left;
		Left = Right;

		tmp =0;
		f(&tmp, &Right, &key->k2[i]);
		Right^=Right;
		for(j=0; j<32; j++)
		{
			Right |= (((((Left2>>(31-i))&1)^(tmp>>(31-i))&1)&1)<<(32-i));
		}
	}
	
	res = ((Right<<31)|Left);
	for(i=0; i<64; i++)
	{
		*out |= (((res>>(64-fp[i]))&1)<<(64-i));
	}
}

void decryptDES(DES_KEY* key, ulong* M, ulong* out)
{
	//TODO FIX MEH D:
	ulong IP;
	uint Left;
	uint Left2;
	uint Right;
	ulong res;
	uint tmp;
	int i,j;

	IP ^= IP;
	for(i=0; i<64; i++)
	{
		IP |= (((*M>>(64-ip[i]))&1)<<(64-i));
	}

	Left = (IP>>32);
	Right = (IP&UINT_MAX);

	for(i=16; i>0; i--)
	{
		Left2 = Left;
		Left = Right;

		tmp =0;
		f(&tmp, &Right, &key->k2[i]);
		Right^=Right;
		for(j=0; j<32; j++)
		{
			Right |= (((((Left2>>(31-i))&1)^(tmp>>(31-i))&1)&1)<<(31-i));
		}
	}
	
	res = ((Right<<31)|Left);
	for(i=0; i<64; i++)
	{
		*out |= (((res>>(64-fp[i]))&1)<<(64-i));
	}
}

void encrypt3DES(TDES_KEY* key, ulong* M, ulong* out)
{
	encryptDES(&key->k1, M, out);
	decryptDES(&key->k2, M, out);
	encryptDES(&key->k3, M, out);
}

void decrypt3DES(TDES_KEY* key, ulong* M, ulong* out)
{
	decryptDES(&key->k3, M, out);
	encryptDES(&key->k2, M, out);
	decryptDES(&key->k1, M, out);
}

int main(int argc, char *argv[])
{
	int i = 0;
	TDES_KEY key;
	//Bytes for k1, k2 and k3
	ulong data = 0x133457799BBCDFF1;
	
	union
	{
		byte message[8];
		ulong M;
	} in;
	in.message[0] = 'A';
	in.message[1] = '1';
	in.message[2] = 'C';
	in.message[3] = '3';
	in.message[4] = 'E';
	in.message[5] = '5';
	in.message[6] = 'G';
	in.message[7] = '\0';

	if(argc < 3)
	{
		i = 1;
	}
	
	key.k1.k = data;
	key.k2.k = data;
	key.k3.k = data;
	create3DESKey(&key);
	
	printf("Plain: %s\n", in.message);
	printf("Hex: %llX\n", in.M);

	data^=data;
	encryptDES(&key.k1, &in.M, &data);
	printf("Encrypted: %llX\n",data);

	decryptDES(&key.k1, &data, &in.M);
	printf("Decrypted: %llX\n", in.M);
	printf("Result: %s\n", in.message);

	system("pause");

	if(i == 0)
	{
		char* buf;
		for(i=2; i<argc; i++)
		{
			buf = argv[i];
			buf += strlen(argv[i]);
		}
		if(strcmp(argv[1], "-e") == 0)
		{
			return 0;
		}
		else if(strcmp(argv[1], "-d") == 0)
		{
			return 0;
		}
	}

	return 0;
}


/*
Triple DES uses a "key bundle" which comprises three DES keys, K1, K2 and K3, each of 56 bits (excluding parity bits). The encryption algorithm is:
	ciphertext = EK3(DK2(EK1(plaintext)))

I.e., DES encrypt with K1, DES decrypt with K2, then DES encrypt with K3.

Decryption is the reverse:
	plaintext = DK1(EK2(DK3(ciphertext)))
I.e., decrypt with K3, encrypt with K2, then decrypt with K1.

Each triple encryption encrypts one block of 64 bits of data.

In each case the middle operation is the reverse of the first and last.
This improves the strength of the algorithm when using keying option 2, and provides backward compatibility with DES with keying option 3.


The standards define three keying options:
Keying option 1: All three keys are independent.
Keying option 2: K1 and K2 are independent, and K3 = K1.
Keying option 3: All three keys are identical, i.e. K1 = K2 = K3.

Keying option 1 is the strongest, with 3 × 56 = 168 independent key bits.

Keying option 2 provides less security, with 2 × 56 = 112 key bits.
This option is stronger than simply DES encrypting twice, e.g. with K1 and K2, because it protects against meet-in-the-middle attacks.

Keying option 3 is equivalent to DES, with only 56 key bits.
This option provides backward compatibility with DES, because the first and second DES operations cancel out.
It is no longer recommended by the National Institute of Standards and Technology (NIST),[6] and is not supported by ISO/IEC 18033-3.
*/







// des.cpp - modified by Wei Dai from Phil Karn's des.c
// The original code and all modifications are in the public domain.

/*
 * This is a major rewrite of my old public domain DES code written
 * circa 1987, which in turn borrowed heavily from Jim Gillogly's 1977
 * public domain code. I pretty much kept my key scheduling code, but
 * the actual encrypt/decrypt routines are taken from from Richard
 * Outerbridge's DES code as printed in Schneier's "Applied Cryptography."
 *
 * This code is in the public domain. I would appreciate bug reports and
 * enhancements.
 *
 * Phil Karn KA9Q, karn@unix.ka9q.ampr.org, August 1994.
 */

#ifdef CRYPTOPP_IMPORTS


/* Set key (initialize key schedule array) */
void RawSetKey(CipherDir dir, const byte *key)
{
	SecByteBlock buffer(56+56+8);
	byte *const pc1m=buffer;                 /* place to modify pc1 into */
	byte *const pcr=pc1m+56;                 /* place to rotate pc1 into */
	byte *const ks=pcr+56;
	register int i,j,l;
	int m;
	
	for (j=0; j<56; j++) {          /* convert pc1 to bits of key */
		l=pc1[j]-1;             /* integer bit location  */
		m = l & 07;             /* find bit              */
		pc1m[j]=(key[l>>3] &    /* find which key byte l is in */
			bytebit[m])     /* and which bit of that byte */
			? 1 : 0;        /* and store 1-bit result */
	}
	for (i=0; i<16; i++) {          /* key chunk for each iteration */
		memset(ks,0,8);         /* Clear key schedule */
		for (j=0; j<56; j++)    /* rotate pc1 the right amount */
			pcr[j] = pc1m[(l=j+totrot[i])<(j<28? 28 : 56) ? l: l-28];
		/* rotate left and right halves independently */
		for (j=0; j<48; j++){   /* select bits individually */
			/* check bit that goes to ks[j] */
			if (pcr[pc2[j]-1]){
				/* mask it in if it's there */
				l= j % 6;
				ks[j/6] |= bytebit[l] >> 2;
			}
		}
		/* Now convert to odd/even interleaved form for use in F */
		k[2*i] = ((word32)ks[0] << 24)
			| ((word32)ks[2] << 16)
			| ((word32)ks[4] << 8)
			| ((word32)ks[6]);
		k[2*i+1] = ((word32)ks[1] << 24)
			| ((word32)ks[3] << 16)
			| ((word32)ks[5] << 8)
			| ((word32)ks[7]);
	}
	
	if (dir==DECRYPTION)     // reverse key schedule order
		for (i=0; i<16; i+=2)
		{
			swap(k[i], k[32-2-i]);
			swap(k[i+1], k[32-1-i]);
		}
}

void RawProcessBlock(word32 &l_, word32 &r_)
{
	word32 l = l_, r = r_;
	const word32 *kptr=k;

	for (unsigned i=0; i<8; i++)
	{
		word32 work = rotrFixed(r, 4U) ^ kptr[4*i+0];
		l ^= Spbox[6][(work) & 0x3f]
		  ^  Spbox[4][(work >> 8) & 0x3f]
		  ^  Spbox[2][(work >> 16) & 0x3f]
		  ^  Spbox[0][(work >> 24) & 0x3f];
		work = r ^ kptr[4*i+1];
		l ^= Spbox[7][(work) & 0x3f]
		  ^  Spbox[5][(work >> 8) & 0x3f]
		  ^  Spbox[3][(work >> 16) & 0x3f]
		  ^  Spbox[1][(work >> 24) & 0x3f];

		work = rotrFixed(l, 4U) ^ kptr[4*i+2];
		r ^= Spbox[6][(work) & 0x3f]
		  ^  Spbox[4][(work >> 8) & 0x3f]
		  ^  Spbox[2][(work >> 16) & 0x3f]
		  ^  Spbox[0][(work >> 24) & 0x3f];
		work = l ^ kptr[4*i+3];
		r ^= Spbox[7][(work) & 0x3f]
		  ^  Spbox[5][(work >> 8) & 0x3f]
		  ^  Spbox[3][(work >> 16) & 0x3f]
		  ^  Spbox[1][(work >> 24) & 0x3f];
	}

	l_ = l; r_ = r;
}

#endif