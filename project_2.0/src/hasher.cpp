#include "hasher.h"

Hasher::Hasher(string ka)
{
	this->key_auth = ka;
	this->hmac = "";
}

string Hasher::getHmac()
{
	return this->hmac;
}

void Hasher::setHmac(string new_val)
{
	this->hmac = new_val;
}

void Hasher::compute(string message, uint32_t seqno)
{
	message.append(to_string(seqno));
	
	unsigned int hash_len;
	//create a buf for our digest
	unsigned char *hash_buf = new unsigned char[32]; //32 byte
		
	//create message digest context
	HMAC_CTX* mdctx = HMAC_CTX_new();
	if(!mdctx) cout<<"hmac() out of memory"<<endl;
	
	//Init,Update,Finalise digest
	bool result = HMAC_Init_ex(mdctx, (unsigned char*)this->key_auth.c_str(), 32, EVP_sha256(), NULL)
	&& HMAC_Update(mdctx, (unsigned char*)message.c_str(), message.size())
	&& HMAC_Final(mdctx, hash_buf, &hash_len);
	
	if(!result) cout<<"errore nella compute_hmac!!"<<endl;
	
	this->hmac.assign((char*)hash_buf, hash_len);
	//BIO_dump_fp(stdout, (const char*)message.c_str(), message.length());
	
	//Delete context
	HMAC_CTX_free(mdctx);
	delete[] hash_buf;
}

bool Hasher::verify(string ciphertext, uint32_t expected_seqno) //ciphertext è la quantita su cui calcolare hmac e verificare con quello ricevuto (this)
{
	string hmac_recv = this->hmac;
	
	this->compute(ciphertext, expected_seqno); //ora this->hmac contiene hmac calcolato
	
	if(CRYPTO_memcmp((unsigned char*)this->hmac.c_str(), (unsigned char*)hmac_recv.c_str(), 32) != 0)
	{
		//if(dbgmode) {
			cout<<"######### Errore verify_hmac() ############"<<endl;
			cout<<"HMAC calcolato: "<<endl;
			BIO_dump_fp(stdout, (const char*)this->hmac.c_str(), this->hmac.length());
			
			cout<<"HMAC ricevuto: "<<endl;
			BIO_dump_fp(stdout, (const char*)hmac_recv.c_str(), hmac_recv.length());
			
			cout<<"############################################"<<endl;
		//}
		return false;
	}
	return true;
}
