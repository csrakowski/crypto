#pragma once

/*****************************\
* Christiaan Rakowski
* Crypto Collection
*
* Ceasar Cipher
* Safety:	Easily Bruteforcable with only 25 possibilites, can even be done on paper using language facts: http://www.oxforddictionaries.com/page/oecfactslanguage/the-oec-facts-about-the-language
* FunFact:	It's often misquoted, but when Bruce Schneier killed Julius Caesar for promoting weak cryptography he actually said, "Et tu, Bruce?" http://www.schneierfacts.com/fact/807
\*****************************/



#ifdef __cplusplus
extern "C" {
#endif

const static char alphabet[] = { 'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z' };

void CeasarCipher(char* message, int shift);

#ifdef __cplusplus
}
#endif
