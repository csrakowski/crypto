#pragma once

/*****************************\
* Christiaan Rakowski
* Crypto Collection
*
* 3DES (Triple DES) Encryption
* Safety	Due to the key size it's not as secure as you can get with RSA, but it is still a valid choice
* FunFact	Bruce Schneier PGP signs his grocery lists so that he can detect if someone has tampered with his milk. http://www.schneierfacts.com/fact/76
*			There was no DES fun fact, so I'll leave the PGP one.
\*****************************/

#ifdef __cplusplus
extern "C" {
#endif

void encryptDES();
void decryptDES();

void encrypt3DES();
void decrypt3DES();

#ifdef __cplusplus
}
#endif
