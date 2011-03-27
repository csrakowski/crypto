#include "3DES.h"

/*****************************\
* Christiaan Rakowski
* Crypto Collection
\*****************************/

void encryptDES()
{
}

void decryptDES()
{
}

void encrypt3DES()
{
	encryptDES();	//k3
	decryptDES();	//k2
	encryptDES();	//k1
}

void decrypt3DES()
{
	decryptDES();	//k1
	encryptDES();	//k2
	decryptDES();	//k3
}
