#pragma once

/*****************************\
* Christiaan Rakowski
* Crypto Collection
\*****************************/

//-----------------------Util-------------------------------
#include "SpecialMath.h"

//--------------------Encryption----------------------------
#include "Vigenere.h"
#include "Ceasar.h"
#include "RSA.h"
#include "3DES.h"

//----------------------Hashing-----------------------------
#include "MD5.h"
#include "SHA1.h"

//----------------------Settings----------------------------
#define CEASAR		0
#define VIGENERE	1
#define RSA			2
#define TRIPLEDES	3
#define MD5			4
#define SHA1		5
