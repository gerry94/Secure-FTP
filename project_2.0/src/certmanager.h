#ifndef CERMANAGER_H
#define CERTMANAGER_H

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include <iostream>
#include <string>

using namespace std;

class CertManager 
{
	private:
		string path;
		X509 *my_cert;
		X509 *peer_cert;
		X509_STORE *store;
	public:
		CertManager(string);
		~CertManager(void);
		
		bool initStore();
		bool initPeerCert(string);
		string getString(); //restituisce il certificato cert sotto forma di stringa
		string getPeerName(); //estrae e restituisce il nome del proprietario di un certificato
		bool verify();
		
		X509* getPeerCert();
};

#endif
