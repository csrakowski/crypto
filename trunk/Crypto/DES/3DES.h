#pragma once

/*****************************\
* Christiaan Rakowski
* Crypto Collection
*
* http://en.wikipedia.org/wiki/DES_supplementary_material
* http://orlingrabbe.com/des.htm
*
* 3DES (Triple DES) Encryption
* Safety	Triple DES uses a "key bundle" which comprises three DES keys, K1, K2 and K3, each of 56 bits (excluding parity bits).
*			This improves the strength of the algorithm when using keying option 1 an 2, and provides backward compatibility with DES with keying option 3.
*
*			The standards define three keying options:
*			Keying option 1: All three keys are independent.
*			Keying option 2: K1 and K2 are independent, and K3 = K1.
*			Keying option 3: All three keys are identical, i.e. K1 = K2 = K3.
*
*			Keying option 1 is the strongest, with 3 × 56 = 168 independent key bits.
*			But due to the meet-in-the-middle attack the effective security it provides is only 112 bits.
*			The best attack known on keying option 1 requires around 232 known plaintexts, 2113 steps, 290 single DES encryptions, and 288 memory.
*			This is not currently practical and NIST considers keying option 1 to be appropriate through 2030.
*
*			Keying option 2 provides less security, with 2 × 56 = 112 key bits.
*			However, this option is susceptible to certain chosen-plaintext or known-plaintext attacks and thus it is designated by NIST to have only 80 bits of security.
*
*			Keying option 3 is equivalent to DES, with only 56 key bits.
*			This option provides backward compatibility with DES, because the first and second DES operations cancel out.
*			It is no longer recommended by the National Institute of Standards and Technology (NIST),[6] and is not supported by ISO/IEC 18033-3.
*			http://en.wikipedia.org/wiki/3DES
*
* FunFact	Bruce Schneier PGP signs his grocery lists so that he can detect if someone has tampered with his milk. http://www.schneierfacts.com/fact/76
*			There was no DES fun fact, so I'll leave the PGP one.
\*****************************/

#include "../SpecialMath/SpecialMath.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
	ulong k;		//The 64 bit input key
	ulong k2[16];	//The 16 48 bit keys
	ulong kPlus;	//The permuted key
	uint c[17];		//The 16 left keys
	uint d[17];		//The 16 right keys
} DES_KEY;

typedef struct {
	DES_KEY k1;
	DES_KEY k2;
	DES_KEY k3;
} TDES_KEY;

/* Tables defined in the Data Encryption Standard documents
 * Three of these tables, the initial permutation, the final
 * permutation and the expansion operator, are regular enough that
 * for speed, we hard-code them. They're here for reference only.
 * Also, the S and P boxes are used by a separate program, gensp.c,
 * to build the combined SP box, Spbox[]. They're also here just
 * for reference.
 */

/* initial permutation IP */
/*
This table specifies the input permutation on a 64-bit block.
The meaning is as follows: the first bit of the output is taken from the 58th bit of the input;
the second bit from the 50th bit, and so on,
with the last bit of the output taken from the 7th bit of the input.
*/
static const byte ip[] = {
	   58, 50, 42, 34, 26, 18, 10,  2,
	   60, 52, 44, 36, 28, 20, 12,  4,
	   62, 54, 46, 38, 30, 22, 14,  6,
	   64, 56, 48, 40, 32, 24, 16,  8,
	   57, 49, 41, 33, 25, 17,  9,  1,
	   59, 51, 43, 35, 27, 19, 11,  3,
	   61, 53, 45, 37, 29, 21, 13,  5,
	   63, 55, 47, 39, 31, 23, 15,  7
};

/* final permutation IP^-1 */
/* See IP */
static const byte fp[] = {
	   40,  8, 48, 16, 56, 24, 64, 32,
	   39,  7, 47, 15, 55, 23, 63, 31,
	   38,  6, 46, 14, 54, 22, 62, 30,
	   37,  5, 45, 13, 53, 21, 61, 29,
	   36,  4, 44, 12, 52, 20, 60, 28,
	   35,  3, 43, 11, 51, 19, 59, 27,
	   34,  2, 42, 10, 50, 18, 58, 26,
	   33,  1, 41,  9, 49, 17, 57, 25
};

/* expansion operation matrix */
/*
The expansion function is interpreted as for the initial and final permutations.
Note that some bits from the input are duplicated at the output;
e.g. the fifth bit of the input is duplicated in both the sixth and eighth bit of the output.
Thus, the 32-bit half-block is expanded to 48 bits
*/
static const byte ei[] = {
	   32,  1,  2,  3,  4,  5,
		4,  5,  6,  7,  8,  9,
		8,  9, 10, 11, 12, 13,
	   12, 13, 14, 15, 16, 17,
	   16, 17, 18, 19, 20, 21,
	   20, 21, 22, 23, 24, 25,
	   24, 25, 26, 27, 28, 29,
	   28, 29, 30, 31, 32,  1
};

/* The (in)famous S-boxes */
/*
This table lists the eight S-boxes used in DES.
Each S-box replaces a 6-bit input with a 4-bit output.
Given a 6-bit input, the 4-bit output is found by selecting the row using the outer two bits, and the column using the inner four bits.
For example, an input "011011" has outer bits "01" and inner bits "1101";
noting that the first row is "00" and the first column is "0000", the corresponding output for S-box S5 would be "1001" (=9),
the value in the second row, 14th column. (See S-box).
*/
static const byte sbox[8][64] = {
	   /* S1 */
	   14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
		0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
		4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
	   15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13,

	   /* S2 */
	   15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
		3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
		0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
	   13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9,

	   /* S3 */
	   10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
	   13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
	   13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
		1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12,

	   /* S4 */
		7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
	   13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
	   10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
		3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14,

	   /* S5 */
		2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
	   14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
		4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
	   11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3,

	   /* S6 */
	   12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
	   10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
		9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
		4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13,

	   /* S7 */
		4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
	   13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
		1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
		6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12,

	   /* S8 */
	   13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
		1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
		7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
		2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
};

/* 32-bit permutation function P used on the output of the S-boxes */
/* The P permutation shuffles the bits of a 32-bit half-block */
static const byte p32i[] = {
	   16,  7, 20, 21,
	   29, 12, 28, 17,
		1, 15, 23, 26,
		5, 18, 31, 10,
		2,  8, 24, 14,
	   32, 27,  3,  9,
	   19, 13, 30,  6,
	   22, 11,  4, 25
};

/* permuted choice table (key) */
/*
The "Left" and "Right" halves of the table show which bits from the input key form the left and right sections of the key schedule state.
Note that only 56 bits of the 64 bits of the input are selected; the remaining eight were specified for use as parity bits.
*/
static const byte pc1[] = {
		//Left
	   57, 49, 41, 33, 25, 17,  9,
		1, 58, 50, 42, 34, 26, 18,
	   10,  2, 59, 51, 43, 35, 27,
	   19, 11,  3, 60, 52, 44, 36,
	   
	   //Right
	   63, 55, 47, 39, 31, 23, 15,
		7, 62, 54, 46, 38, 30, 22,
	   14,  6, 61, 53, 45, 37, 29,
	   21, 13,  5, 28, 20, 12,  4
};

/* number left rotations of pc1 */
static const byte totrot[] = {
	   1,2,4,6,8,10,12,14,15,17,19,21,23,25,27,28
};

/* number left rotations of pc1 */
static const byte rolls[] = {
	1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1
};

/* permuted choice key (table) */
/* This permutation selects the 48-bit subkey for each round from the 56-bit key-schedule state */
static const byte pc2[] = {
	   14, 17, 11, 24,  1,  5,
		3, 28, 15,  6, 21, 10,
	   23, 19, 12,  4, 26,  8,
	   16,  7, 27, 20, 13,  2,
	   41, 52, 31, 37, 47, 55,
	   30, 40, 51, 45, 33, 48,
	   44, 49, 39, 56, 34, 53,
	   46, 42, 50, 36, 29, 32
};

/* End of DES-defined tables */

void createDESKey(DES_KEY* key);
void create3DESKey(TDES_KEY* key);
void parse3DESKey(TDES_KEY* key, char* file);

void encryptDES(DES_KEY* key, ulong* M, ulong* out);
void encrypt3DES(TDES_KEY* key, ulong* M, ulong* out);
void encryptFile3DES(char* key, char* fileIn, char* fileOut);

void decryptDES(DES_KEY* key, ulong* M, ulong* out);
void decrypt3DES(TDES_KEY* key, ulong* M, ulong* out);
void decryptFile3DES(char* key, char* fileIn, char* fileOut);

#ifdef __cplusplus
}
#endif
