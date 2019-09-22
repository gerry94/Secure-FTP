#include "certmanager.h"

CertManager::CertManager(string p)
{
	this->path = p;
	this->peer_cert = NULL;
	this->store = NULL;
	
	FILE *fpem = fopen(this->path.c_str(), "rx");
	if(!fpem)
		cout<<"File certificato non trovato."<<endl;
	
	this->my_cert = PEM_read_X509(fpem, NULL,NULL,NULL);
	if(!this->my_cert)
		cout<<"Errore lettura certificato."<<endl;
		
	fclose(fpem);
}
CertManager::~CertManager(void)
{
    if(this->my_cert) X509_free(this->my_cert);
    if(this->peer_cert) X509_free(this->peer_cert);
    if(this->store) X509_STORE_free(this->store);
}

bool CertManager::initStore()
{
	//inizializzo lo this->store
	this->store = X509_STORE_new();
	FILE *fp;
	
	//aggiungo cert della trusted CA
	X509 *ca_cert;
	fp = fopen("../certif/SimpleAuthorityCA_cert.pem", "rx");
	if(!fp) return false;
	ca_cert = PEM_read_X509(fp, NULL, NULL, NULL);
	X509_STORE_add_cert(this->store, ca_cert);
	
	fclose(fp);
	
	//aggiungo lista cert revocati
	X509_CRL *crl;
	fp = fopen("../certif/SimpleAuthorityCA_crl.pem", "rx");
	if(!fp) return false;
	crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL);
	fclose(fp);
	
	X509_STORE_add_crl(this->store, crl);
	X509_STORE_set_flags(this->store, X509_V_FLAG_CRL_CHECK);
	
	X509_free(ca_cert);
	X509_CRL_free(crl);
	
	return true;
}

string CertManager::getString()
{
	unsigned char *buf = NULL;
	int size = i2d_X509(this->my_cert, &buf);
	if(size <= 0) return "";

	string rets;
	rets.assign((char*)buf, size);
	
	OPENSSL_free(buf);
	
	return rets;
}

bool CertManager::initPeerCert(string buf)
{
	const char *tmp_str = buf.c_str();
	this->peer_cert = d2i_X509(NULL, (const unsigned char**)&tmp_str, buf.size());
	if(!this->peer_cert) return false;
	else return true;
}

string CertManager::getPeerName()
{
	X509_NAME *subject_name = X509_get_subject_name(this->peer_cert);
	
	char *oneline = X509_NAME_oneline(subject_name, NULL, 0);
	string sname(oneline);
	OPENSSL_free(oneline);
	
	sname = sname.substr(9, sname.npos);
	
	return sname;
}

bool CertManager::verify()
{
	X509_STORE_CTX *ctx = X509_STORE_CTX_new();
	X509_STORE_CTX_init(ctx, this->store, this->peer_cert, NULL);
	
	//verifica del certificato
	if(X509_verify_cert(ctx) != 1) 
	{
		int error = X509_STORE_CTX_get_error(ctx);
		switch(error) 
		{
			case 20:
				cout<<"Impossibile trovare la Certification Authority specificata."<<endl;
				break;
			case 23:
				cout<<"Il certificato è stato revocato!"<<endl;
				break;
			default:
				cout<<"Codice: "<<error<<endl;
				break;
		}
		return false;
	}
	X509_STORE_CTX_free(ctx);
	return true;
}

X509* CertManager::getPeerCert() {	return this->peer_cert; }
