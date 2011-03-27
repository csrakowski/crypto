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
	encryptDES();	//k1
	decryptDES();	//k2
	encryptDES();	//k3
}

void decrypt3DES()
{
	decryptDES();	//k1
	encryptDES();	//k2
	decryptDES();	//k3
}
