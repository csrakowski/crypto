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

//----------------------Hashing-----------------------------
#include "MD5.h"
#include "SHA1.h"

//----------------------Settings----------------------------
#define CEASAR		0
#define VIGENERE	1
#define RSA			2
#define MD5			3
#define SHA1		4
