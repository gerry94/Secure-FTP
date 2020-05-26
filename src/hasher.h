#ifndef HASHER_H
#define HASHER_H

#include <string>
#include <openssl/hmac.h>
#include <iostream>

using namespace std;

class Hasher {
	private:
		string key_auth;
		string hmac;
public:
	Hasher(string);
	void compute(string, uint32_t); //passo il relativo seqno e calcolo hmac e lo salvo nella variabile privata
	bool verify(string, uint32_t); //passo expected seqno e il ciphertext
	string getHmac();
	void setHmac(string);
};

#endif
