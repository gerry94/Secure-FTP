//LIBRERIE C-SOCKET
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
//LIBRERIE OPENSSL
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/conf.h>
#include <openssl/err.h>

//LIBRERIE VARIE
#include <unistd.h>
#include <cstring>
#include <string>
#include <regex>
#include <iostream>
#include <fstream>
#include <errno.h>
#include <dirent.h>
#include <time.h>

using namespace std;

# define CHUNK 		512000
# define IP_ADDR 	"127.0.0.1"
# define PORT_NO 	15050
# define NONCE_LENGTH 	  4 //byte
# define IV_LENGTH 	 16 //initialization value (controllare la dimensione (byte)
# define SESSION_KEY_LEN 16 //controllare dim

// alcuni prototipi

void send_data(string, int, int);
void recvData(int);


//========variabili socket========
struct timeval tv; //server per impostar il timeout sulle recv()
int ret, sd, new_sd, porta;
unsigned int len;
struct sockaddr_in my_addr, cl_addr;
fd_set master, read_fds;
int fdmax;
bool busy = false; //serve per accettare una sola connessione
//================================
bool dbgmode = false; //serve oer attivare dei messaggi di debug nelle funzioni
string net_buf;

string filename;
int code; //codice comando ricevuto dal client
long long int ctx_len, lmsg;
fstream fp;

//==========variabili cybersecurity===========
EVP_CIPHER_CTX *decr_context;
EVP_CIPHER_CTX *encr_context; //context usato nelle encrypt/decrypt
bool first_encr = true, first_decr = true; //var che indica se è la prima volta che uso encr/decr in modo da fare una volta sola la Init()

uint32_t seqno; //numero di sequenza pacchetti
uint32_t seqno_r; //num sequenza ricevuto
bool secure_connection = false;
string cert_server = "../certif/Server_cert.pem";
X509_STORE *store;
X509 *client_cert;
string key_encr,init_v, key_auth, nonce_b;
char *nonce_a; //nonce_a= ricevuto dal client
bool key_handshake = true; //indica se siamo in fase di scambio di chiavi in modo da non usare la cifratura con chiavi che sarebbero non ancora inizializzate 
//============================================

int decrypt(char *ciphertext, int ciphertext_len, char *plaintext)
{
	int outl, plaintext_len;

	if(first_decr) { // Create and initialise the context 
		decr_context = EVP_CIPHER_CTX_new();
		EVP_DecryptInit(decr_context, EVP_aes_128_cfb8(), (const unsigned char*)key_encr.c_str(), (const unsigned char*)init_v.data());
		first_decr = false;
	}
	
	if((plaintext_len = EVP_DecryptUpdate(decr_context, (unsigned char*)plaintext, &outl, (unsigned char*)ciphertext, ciphertext_len))==0)
	{
		cerr<<"Errore di EVP_DecryptUpdate."<<endl;
		return 0;
	}
	plaintext_len = outl;

	return plaintext_len;
}

int encrypt(char *plaintext, int plaintext_len, char *ciphertext)
{
	int outl, ciphertext_len;
	
	if(first_encr) {	/* Create and initialise the context */
		encr_context = EVP_CIPHER_CTX_new();
		EVP_EncryptInit(encr_context, EVP_aes_128_cfb8(), (const unsigned char*)key_encr.c_str(), (const unsigned char*)init_v.data());
		first_encr = false;
	}
	if((ciphertext_len = EVP_EncryptUpdate(encr_context, (unsigned char*)ciphertext, &outl, (unsigned char*)plaintext, plaintext_len))==0)
	{
		cerr<<"Errore di EVP_EncryptUpdate."<<endl;
		return 0;
	}

	return ciphertext_len;
}

void send_ack(int sock, bool ack)
{
	if(send(sock, (void*)&ack, sizeof(ack), 0)== -1)
	{
		cerr<<"Errore di send(ack). Codice:"<<errno<<endl;
		exit(1);
	}
}

bool check_command_injection(string buf)
{
	regex b("[A-Za-z0-9.-_]+");
	if(regex_match(buf, b))
		return true;
	else 
		return false;
}

bool create_rand_val(string &dest, int val_length)
{
	if(val_length <= 0)
		return false;
		
	if(RAND_poll() != 1){
		cerr<<"Errore esecuzione RAND_poll()"<<endl;
		return false;
	}	
	
	char *val = new char[val_length];
	
	if(RAND_bytes((unsigned char*)val, val_length) != 1){
		cerr<<"Errore esecuzione RAND_bytes"<<endl;
		return false;
	}	
	dest.assign(val, val_length);
	
	delete[] val;
	return true;
}

bool create_ca_store()
{
	store = X509_STORE_new();
	FILE *fp;
	
	//aggiungo cert della trusted CA
	X509 *ca_cert;
	fp = fopen("../certif/SimpleAuthorityCA_cert.pem", "r");
	if(!fp) return false;
	ca_cert = PEM_read_X509(fp, NULL, NULL, NULL);
	X509_STORE_add_cert(store, ca_cert);
	
	fclose(fp);
	
	//aggiungo lista cert revocati
	X509_CRL *crl;
	fp = fopen("../certif/SimpleAuthorityCA_crl.pem", "r");
	if(!fp) return false;
	crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL);
	fclose(fp);
	
	X509_STORE_add_crl(store, crl);
	X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
	
	cout<<"Creato deposito dei Certificati."<<endl;
	
	X509_free(ca_cert);
	X509_CRL_free(crl);
	return true;
}

bool authorized_client(string name)
{
	string path = "../certif/authorized_clients.bin";
	
	fstream ff;
	ff.open(path, ios::in | ios::binary);
	if(!ff)
	{
		cerr<<"errore apertura file client autorizzati!"<<endl;
		return false;
	}
	
	string line;
	while(ff >> line)
		if(line == name) return true;
	
	ff.close();
	return false;
}

bool recv_authentication(int sd)
{        
	nonce_a = new char[NONCE_LENGTH];
	if(recv(sd, (void*)nonce_a, NONCE_LENGTH, 0) == -1)
	{
		cerr<<"Errore in fase di ricezione nonce_a. Codice: "<<errno<<endl;
		return false;
	}

	recvData(sd);
	string buf = net_buf;
	
	/*if(recv(sd, (void*)&lmsg, sizeof(uint64_t), 0) == -1)
	{
		cerr<<"Errore in fase di ricezione lunghezza. Codice: "<<errno<<endl;
		return false;
	}
	
	len = ntohl(lmsg); // Rinconverto in formato host

	unsigned char *buf = new unsigned char[len];
	if(recv(sd, (void*)buf, len, 0) == -1)
	{
		cerr<<"Errore in fase di ricezione buffer dati. Codice: "<<errno<<endl;
		return false;
	}
	*/
	
	client_cert = d2i_X509(NULL, (const unsigned char**)&buf, buf.size());
	if(!client_cert) return false;
	
	X509_NAME *subject_name = X509_get_subject_name(client_cert);
	char* oneline = X509_NAME_oneline(subject_name, NULL, 0);
	string sname = string(oneline);
	
	free(oneline);
	OPENSSL_free(&buf);
	
	sname = sname.substr(9, sname.npos);
	cout<<"Ricevuto certificato del client: "<<sname<<endl;
	
	//verificare che sia fra gli autorizzati
	if(!authorized_client(sname))
	{
		cerr<<"ERRORE: Il client '"<<sname<<"' non è autorizzato presso questo Server!"<<endl;
		return false;
	}
	
	X509_STORE_CTX *ctx = X509_STORE_CTX_new();
	X509_STORE_CTX_init(ctx, store, client_cert, NULL);
	
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
		send_ack(sd, false);
		return false;
	}
	cout<<"Certificato client sul socket "<<sd<<" valido."<<endl;
	send_ack(sd, true);
	X509_STORE_CTX_free(ctx);

	return true;
	
}

bool recv_ack(int sd)
{
	bool ack;
	if(recv(sd, &ack, sizeof(ack), 0) == -1)
	{
	    cerr<<"Errore in fase di recv(ack). Codice: "<<errno<<endl;
	    exit(1);
	}
	return ack;
}

bool send_authentication(int sd)
{
	X509 *s_cert;
	FILE *fpem = fopen(cert_server.c_str(), "r");
	
	if(!fpem)
	{
		cout<<"File certificato non trovato."<<endl;
		return false;
	}
	
	s_cert = PEM_read_X509(fpem, NULL,NULL,NULL);
	if(!s_cert)
	{
		cout<<"Errore lettura certificato."<<endl;
		return false;
	}

	unsigned char *buf = NULL;
	unsigned long int fsize = i2d_X509(s_cert, &buf);
	if(fsize <= 0) return false;
	
	string s_buf;
	s_buf.assign((char*)buf, fsize);
	send_data(s_buf, fsize, sd);
	
	/*
	lmsg = htons(fsize);
	if(send(sd, (void*) &lmsg, sizeof(uint64_t), 0) == -1)
	{
		cerr<<"Errore di send(size). Codice: "<<errno<<endl;
		return false;
	}

	if(send(sd, (void*)buf, fsize, 0)== -1)
	{
		cerr<<"Errore di send(file.pem). Codice: "<<errno<<endl;
		return false;
	}*/
	OPENSSL_free(buf);
	X509_free(s_cert);
	
	cout<<"Certificato inviato al client."<<endl;
	if(!recv_ack(sd))
	{
		cout<<"Errore di autenticazione."<<endl;
		return false;
	}
	
	fclose(fpem);
	return true;	
}

void sock_connect(int port)
{
	//Creazione socket
    sd = socket(AF_INET, SOCK_STREAM, 0);
    
    //Creazione indirizzo di bind

    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(port);
    my_addr.sin_addr.s_addr = INADDR_ANY;
    
    ret = bind(sd, (struct sockaddr*)&my_addr, sizeof(my_addr) );
    ret = listen(sd, 10);
    
    if(ret < 0){
        cerr<<"Errore in fase di bind: "<<endl;
        exit(-1);
    }
}

void quit(int i)
{
	close(i);
	FD_CLR(i, &master);
	cout<<"Socket "<<i<<" chiuso."<<endl;
	busy = false;
	code = 0, seqno=0;
	secure_connection=false;
	key_handshake = true;
	first_encr = true;
	first_decr = true;
	EVP_CIPHER_CTX_free(encr_context);
	EVP_CIPHER_CTX_free(decr_context);
}

int check_seqno(uint32_t seqno_r) //-1 in caso di errore, 0 se corrisponde
{
	if(dbgmode) cout<<"Ricevuto: "<<seqno_r<<" | Atteso: "<<seqno<<endl;
	if(seqno_r != seqno) //gestire la chiusura della connessione per bene
	{
		cerr<<"Numeri di sequenza fuori fase!"<<endl;
		return -1;
	}
	if(seqno_r == UINT32_MAX)
	{
		cout<<"Sessione scaduta!"<<endl;
		exit(0);
	}
	else return 0;
}

void send_seqno(int sd)
{
	if(dbgmode) cout<<"Invio seqno "<<seqno<<" in corso..."<<endl;
	//invio seqno
	if(send(sd, (void*)&seqno, sizeof(uint32_t), 0)== -1)
	{
		cerr<<"Errore di send(seqno). Codice: "<<errno<<endl;
		exit(1);
	}
}

void recv_seqno(int sd)
{
	if(dbgmode) cout<<"Attendo seqno..."<<endl;
	//ricevo numero di sequenza dal client
	if(recv(sd, &seqno_r, sizeof(uint32_t), 0) == -1)
	{
	    cerr<<"Errore di recv(seqno). Codice: "<<errno<<endl;
	    exit(1);
	}
}

void send_file(int sd)
{
	fp.seekg(0, fp.end); //scorro alla fine del file per calcolare la lunghezza (in Byte)
	long long int fsize = fp.tellg(); //fsize conta il num di "caratteri" e quindi il numero di byte --> occhio che se dim file > del tipo int ci sono problemi
	fp.seekg(0, fp.beg); //mi riposizione all'inizio
	
	cout<<"Lunghezza file(Byte): "<<fsize<<endl;
	char *ptx_buf = new char[CHUNK]; //buffer per lettura da file
	char *ctx_buf = new char[CHUNK]; //buffer (cifrato) da trasmettere sul socket
	
	lmsg = htonl(fsize); //invio lunghezza file
	
	send_seqno(sd);
	if(send(sd, &lmsg, sizeof(uint64_t), 0) == -1)
	{
		cerr<<"Errore di send(size)."<<endl;
		exit(1);
	}
	seqno++;
	
	cout<<"Invio del file: "<<net_buf<<" in corso..."<<endl;
	
	long long int mancanti = fsize;
	long long int inviati = 0;
	int count=0, progress=0;

	while((mancanti-CHUNK)>0)
	{
		//invio il numero di sequenza
		send_seqno(sd);
		
		fp.read(ptx_buf, CHUNK); //ora buf contiene il contenuto del file letto
		
		if(encrypt(ptx_buf, CHUNK, ctx_buf) == 0) { cerr<<"Errore di encrypt()."<<endl; exit(1); }
		int n = send(sd, (void*)ctx_buf, CHUNK, 0);
		if(n == -1)
		{
			cerr<<"Errore di send(buf). Codice: "<<errno<<endl;;
			exit(1);
		}
		count++; seqno++;

		mancanti -= n;
		inviati += n;
		
		progress = (inviati*100)/fsize;
		cout<<"\r"<<progress<<"%";	
	}
	delete[] ptx_buf;
	delete[] ctx_buf;
	
	if(mancanti!=0)
	{
		char *ctx_buf = new char[mancanti];
		char *ptx_buf = new char[mancanti];
		
		//invio il numero di sequenza
		send_seqno(sd);
		
		fp.read(ptx_buf, mancanti); //ora buf contiene il contenuto del file letto
		
		if(encrypt(ptx_buf, mancanti, ctx_buf) == 0) { cerr<<"Errore di encrypt()."<<endl; exit(1); }
		
		int n = send(sd, (void*)ctx_buf, mancanti, 0);
		if(n == -1)
		{
			cerr<<"Errore di send(buf). Codice: "<<errno<<endl;;
			exit(1);
		}
		count++; seqno++;
		inviati += n;
		progress = (inviati*100)/fsize;
		cout<<"\r"<<progress<<"%";
		
		delete[] ptx_buf;
		delete[] ctx_buf;	
	}
	cout<<endl;
	cout<<"Inviato file in "<<count<<" pacchetti."<<endl;
	fp.close();
}

void recv_file(string filename)
{
	recv_seqno(new_sd);
	if(check_seqno(seqno_r) == -1) exit(1);
	
	if(recv(new_sd, &lmsg, sizeof(uint64_t), MSG_WAITALL) == -1) {
		cerr<<"Errore in fase di ricezione lunghezza file. Codice: "<<errno<<endl;
		exit(1);
	}
	seqno++;
	ctx_len = ntohl(lmsg); // Rinconverto in formato host
	
	if(ctx_len <= 0)
	{
		cout<<"Errore dimensione file."<<endl;
		return;
	}
								
	char *ctx_buf = new char[CHUNK];
	char *ptx_buf = new char[CHUNK];
//il flag WAITALL indica che la recv aspetta TUTTI i pacchetti. Senza ne riceve solo uno e quindi file oltre una certa dimensione risultano incompleti							
	
	cout<<"Ricezione di "<<filename<<" in corso..."<<endl;
	
	long long int mancanti = ctx_len, ricevuti = 0;
	int count=0, progress = 0, ret=0;
	
	string path ="../serv_files/";
	path.append(filename);

	fp.open(path.c_str(), ios::out | ios::binary); //creo il file con il nome passato
	
	if(!fp) { cerr<<"Errore apertura file."<<endl; exit(1); }
	
	while((mancanti-CHUNK) > 0)
	{
		//ricevo numero di sequenza dal client
		recv_seqno(new_sd);		
		if(check_seqno(seqno_r) == -1)
		{
			fp.close();
			remove(path.c_str()); //elimino il file
			exit(1); //gestire meglio la chiusura
		}
		
		int n = recv(new_sd, (void*)ctx_buf, CHUNK, MSG_WAITALL);		
		if(n == -1)
		{
			cerr<<"Errore in fase di ricezione buffer dati. Codice: "<<errno<<endl;
			exit(1);
		}
		if((ret = decrypt(ctx_buf, CHUNK, ptx_buf))==0) { cerr<<"Errore di decrypt()."<<endl; exit(1); }

		ricevuti += n;
		mancanti -= n;
		
		seqno++;

		fp.write(ptx_buf, CHUNK);

		//percentuale di progresso
		progress = (ricevuti*100)/ctx_len;
		cout<<"\r"<<progress<<"%";

		count++;
	}
	delete[] ptx_buf;
	delete[] ctx_buf;
	
	if(mancanti != 0)
	{
		char *ptx_buf = new char[mancanti];
		char *ctx_buf = new char[mancanti];
		
		//ricevo numero di sequenza dal client
		recv_seqno(new_sd);
		if(check_seqno(seqno_r) == -1)
		{
			fp.close();
			remove(path.c_str()); //elimino il file
			exit(1); //gestire meglio la chiusura
		}
		
		int n = recv(new_sd, (void*)ctx_buf, mancanti, MSG_WAITALL);
		if(n == -1)
		{
			cerr<<"Errore in fase di ricezione buffer dati. Codice: "<<errno<<endl;
			exit(1);
		}
		if((ret = decrypt(ctx_buf, mancanti, ptx_buf))==0) { cerr<<"Errore di decrypt()."<<endl; exit(1); }

		seqno++;
		ricevuti += n;
		
		fp.write(ptx_buf, mancanti);
		
		progress = (ricevuti*100)/ctx_len;
		cout<<"\r"<<progress<<"%";

		count++;
		
		delete[] ptx_buf;
		delete[] ctx_buf;
	}
	cout<<endl;
	cout<<"Ricevuto file in "<<count<<" pacchetti, per un totale di "<<ricevuti<<" bytes."<<endl;
	
	if(ricevuti != ctx_len)
	{
		cerr<<"Errore di trasferimento."<<endl;
		return;
	}
							
	cout<<"Salvataggio file completato in "<<path<<endl;
	fp.close();
	cout<<"File chiuso."<<endl;
	
	code=0; //metto il codice neutro per evitare eventuali problemi nello switch
}

void send_data(string buf, int buf_len, int sock) 
{
	send_seqno(sock);
	
	len = buf_len; // buf.length();
	lmsg = htonl(len);	
	
	if(send(sock, (void*) &lmsg, sizeof(uint32_t), 0) == -1)
	{
		cerr<<"Errore di send(size). Codice: "<<errno<<endl;
		exit(1);
	}
	seqno++;
	send_seqno(sock);
	
	char *ctx_buf = new char[buf_len];
	
	if(!key_handshake)
	{
        	char *ptx_buf = new char[buf_len]; //+1 ?
		memcpy(ptx_buf, buf.data(), buf_len);
		
		if(encrypt(ptx_buf, buf_len, ctx_buf) == 0) { cerr<<"Errore di encrypt() nella send_data()."<<endl; exit(1); }
		delete[] ptx_buf;
	}
	else
		memcpy(ctx_buf, buf.data(), buf_len);
	
	if(send(sock, (void*)ctx_buf, buf_len, 0) == -1)
	{
		cerr<<"Errore di send(buf). Codice: "<<errno<<endl;
		exit(1);
	}      
        seqno++;
        delete[] ctx_buf;
        code = 0;
}

void recvData(int sd)
{
	recv_seqno(sd);
	if(check_seqno(seqno_r) == -1) exit(1);
	
	// Attendo dimensione del mesaggio                
	if(recv(sd, (void*)&lmsg, sizeof(uint16_t), 0) == -1)
	{
		cerr<<"Errore in fase di ricezione lunghezza. "<<endl;
		exit(1);
	}
	seqno++;
	len = ntohs(lmsg); // Rinconverto in formato host
	
	recv_seqno(sd);
	if(check_seqno(seqno_r) == -1) exit(1);
	
	char *tmp_buf = new char[len];
	if(recv(sd, (void*)tmp_buf, len, 0) == -1)
	{
		cerr<<"Errore in fase di ricezione buffer dati. "<<endl;
		exit(1);
	}

	if(!key_handshake) //se la cifratura è abilitata
	{
		char *ptx_buf = new char[len];
		if(decrypt(tmp_buf, len, ptx_buf)==0) { cerr<<"Errore di decrypt() nella recvData()"<<endl; exit(1); }
		net_buf.assign(ptx_buf, len);
		delete[] ptx_buf;
	}
	else //siamo ancora in fase di handshake chiavi pertanto non devo decifrare normalmente
		net_buf.assign(tmp_buf, len);
	
	net_buf.resize(len);
	seqno++;
	delete[] tmp_buf;
}

void recv_status(int sd)
{
	recvData(sd); //il comando può essere ricevuto solo dopo che la connessioe è sicura quindi viene sempre cifrato
	code = stoi(net_buf, NULL, 10);
	
	if(dbgmode) cout<<"Ricevuto comando "<<code<<" dal client."<<endl;
}

bool search_file(string filename)
{
	DIR *d;
	struct dirent *dir;
	d = opendir("../serv_files");
	if(d)
	{
		while((dir = readdir(d)) != NULL)
				if(dir->d_name == filename)
					return true;
		closedir(d);
	}
	cout<<"File non trovato."<<endl;
	return false;
}

void list(int sock)
{
	DIR *d;
	struct dirent *dir;

	string lista_file = "\n";
	
	d = opendir("../serv_files");
	if(d)
	{
		while((dir = readdir(d)) != NULL) //legge due righe che non ci interessano, una ".." e l'altra "." ---> risolvere
		{
			if(dir->d_type == 8) {
				lista_file.append(dir->d_name);
				lista_file.append("\n");
			}
		}
		closedir(d);
	}
	
	cout<<"Invio lista file disponibili in corso..."<<endl;

	send_data(lista_file, lista_file.length(), sock);
	cout<<"Lista inviata."<<endl;
}

//firma digitale
string sign(string toSign)
{
	//prendere kpriv del server dal file pem
	FILE *fp = fopen("../certif/Server_key.pem", "r");
	if(!fp) { cerr<<"errore apertura serv_key.pem."<<endl; exit(1); }
	
	EVP_PKEY *evp_serv_privk = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	if(!evp_serv_privk) {cout<<"Chiave non prelevata"<<endl; exit(1);}
	fclose(fp);

	unsigned char* body_sign = new unsigned char[toSign.size()];
	memcpy(body_sign, toSign.data(), toSign.size());
	
	unsigned char* tmp_sign = new unsigned char[EVP_PKEY_size(evp_serv_privk)];
	unsigned int sign_len = 0;

	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if(!ctx) {cout<<"Creazione ctx non riuscita"<<endl; exit(1);}

	if(EVP_SignInit(ctx, EVP_sha256()) == 0) { cerr<<"SignInit Error"<<endl; exit(1);}
	if(EVP_SignUpdate(ctx, body_sign, toSign.size()) == 0) { cerr<<"SignInit Error"<<endl; exit(1);}
	if(EVP_SignFinal(ctx, tmp_sign, &sign_len, evp_serv_privk) == 0) { cerr<<"SignFianl Error"<<endl; exit(1);}

	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(evp_serv_privk);

	string signature;
	signature.assign((char*)tmp_sign, sign_len);
	
	delete[] tmp_sign;
	delete[] body_sign;
	
	return signature;	
}

bool verifySign(string received_sign, string msg)
{
	unsigned char* tmp_sign = new unsigned char[received_sign.size()];
	memcpy(tmp_sign, received_sign.data(), received_sign.size());
	unsigned int sign_len = received_sign.size();

	unsigned char* to_verify = new unsigned char[msg.size()];
	memcpy(to_verify, msg.data(), msg.size());
	unsigned int msg_len = msg.size();

	EVP_PKEY *evp_cli_pubk = X509_get_pubkey(client_cert);
	if(!evp_cli_pubk)
	{
		cout<<"Chiave pubblica server erroneamente prelevata"<<endl;
		exit(1);
	}
	
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if(!ctx) {cout<<"Errore ctx"<<endl; exit(1);}

	if(EVP_VerifyInit(ctx, EVP_sha256()) == 0) {cerr<<"VerifyInit Error"<<endl; return false;}
	if(EVP_VerifyUpdate(ctx, msg.data(), msg.size()) == 0) {cerr<<"VerifyUpdate Error"<<endl; return false;}
	if(EVP_VerifyFinal(ctx, (const unsigned char*)received_sign.data(), received_sign.size(), evp_cli_pubk) == 0) 
	{	
		cerr<<"ERRORE: verifica digital_signature fallita. Codice: "<<endl;
		cout<<ERR_GET_REASON(ERR_get_error())<<endl;
		return false;
	}

	delete[] to_verify;
	delete[] tmp_sign;

	EVP_PKEY_free(evp_cli_pubk);
	EVP_MD_CTX_free(ctx);

	cout<<"Firma digitale verificata."<<endl;
	return true;

}


void create_secure_session(int i)
{
	//generare Ks, Ka, IV e nonce_b
	create_rand_val(key_encr, SESSION_KEY_LEN);

	create_rand_val(key_auth, SESSION_KEY_LEN);

	create_rand_val(init_v, IV_LENGTH);
	//init_v.resize(IV_LENGTH);
	
	//string tmp_nb;
	//tmp_nb.assign(nonce_b, NONCE_LENGTH);
	create_rand_val(nonce_b, NONCE_LENGTH);
	
	//memcpy(nonce_b, tmp_nb.data(), NONCE_LENGTH);
	
	string conc_key = key_encr;
 	conc_key.append(key_auth);
 	
	unsigned char* plaintext = new unsigned char[conc_key.size()];
	memcpy(plaintext, conc_key.data(), conc_key.size());

	//1) prendere kpub del client dal certificato
 	EVP_PKEY *evp_cli_pubk = X509_get_pubkey(client_cert);
 	
 	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
 	if(!ctx) { cerr<<"Errore creazione del context."<<endl; }
 	
	int iv_size = EVP_CIPHER_iv_length(EVP_aes_128_cfb8());
 	unsigned char iv[iv_size];

	int pubk_size = EVP_PKEY_size(evp_cli_pubk);
 	unsigned char *ek = new unsigned char[pubk_size];

 	unsigned char *out = new unsigned char[48]; //2 chiavi = 16*2 + altri 16 byte
 	
 	int klen = 0;
	int outl = 0;
	int cipher_len = 0;
 	
 	if(EVP_SealInit(ctx, EVP_aes_128_cfb8(), &ek, &klen, iv, &evp_cli_pubk, 1) == 0) { cerr<<"errore seal."<<endl; exit(1); }

	if(EVP_SealUpdate(ctx, out, &outl, plaintext, conc_key.size()) == 0) { cerr<<"errore SealUpdate."<<endl; exit(1); }
 	cipher_len = outl;
 	
 	if(EVP_SealFinal(ctx, out+cipher_len, &outl) == 0) { cerr<<"errore SealFinal."<<endl; exit(1); }
 	cipher_len += outl;

	EVP_PKEY_free(evp_cli_pubk);
	EVP_CIPHER_CTX_free(ctx);

	//3) invio chiavi di sessione cifrate con chiave pubblica del client, iv, nonce_a
	string outs, ivs, eks;
	outs.assign((char*)out, cipher_len);
	ivs.assign((char*)iv, iv_size);
	eks.assign((char*)ek, klen);

	send_data(eks, klen, i);
	send_data(ivs, iv_size, i);
	send_data(outs, cipher_len, i);

	send_data(init_v, IV_LENGTH, i);
	
	string s_nonce_a;
	s_nonce_a.assign(nonce_a, NONCE_LENGTH);
	send_data(s_nonce_a, NONCE_LENGTH, i);

	delete[] ek;
	delete[] out;
	delete[] plaintext;
	
	//4)invio firma dal server su chiavi cifrate, iv e nonce_a
	string forSign = outs;
 	forSign.append(init_v);
	forSign.append(s_nonce_a);

	string signature = sign(forSign);

	send_data(signature, signature.size(), i);

	send_data(nonce_b, NONCE_LENGTH, i);

	//ricevo firma e nonce_b

	recvData(i);
	string nonce_b_cli = net_buf;

	recvData(i);
	string signed_nonce = net_buf;


	if(!verifySign(signed_nonce, nonce_b_cli))
	{
		cout<<"Nonce_b non verificato"<<endl;
		exit(1);
	}

	
	//mi appoggio ad una stringa altrimenti non funziona l'operatore di confront
	string app(nonce_b); 

	app.resize(NONCE_LENGTH);

	if(nonce_b_cli == app) cout<<"nonce_b verificato."<<endl;
	else cout<<"ERRORE verifica nonce_b."<<endl;
	
	key_handshake = false;
	
	cout<<"SERVER: Fine hadshake chiavi/certificati."<<endl;	
}

int main()
{
	if(!create_ca_store())
	{
		cerr<<"Impossibile creare deposito certificati."<<endl;
		return 0;
	}
	
	FD_ZERO(&master);
	FD_ZERO(&read_fds);
	
	sock_connect(PORT_NO);
    	
    	FD_SET(sd, &master);
    	fdmax = sd;
cout<<"Server avviato. "<<endl;
while(1){

    	read_fds = master;
    	if(select(fdmax +1, &read_fds, NULL, NULL, NULL) == -1)
    	{
    		cerr<<"SERVER: select() error."<<endl;
    		close(sd);
    	}

    	for(int i = 0; i<=fdmax; i++)
    	{
    		if(FD_ISSET(i, &read_fds))
    		{
    			if((i == sd) && !busy) //busy serve per accettare una sola connessione
    			{
    				len = sizeof(cl_addr);
    				// Accetto nuove connessioni
    				new_sd = accept(sd, (struct sockaddr*) &cl_addr, &len);
    				
				    if(new_sd == -1)
				    {
					    cerr<<"SERVER: accept() error. "<<endl;
					    close(sd);
				    }
				    else
				    {
				    	FD_SET(new_sd, &master);
				    	
					//salvare new_sd come id del client
					
					if(new_sd > fdmax)
					    fdmax = new_sd;
					    
				        cout<<"SERVER: accettata nuova connessione con il client da "<<inet_ntoa(cl_addr.sin_addr)<<" sul socket "<<new_sd<<". "<<endl;
				        busy = true;
				        
				        tv.tv_sec = 2000; //20sec timeout
				        setsockopt(new_sd, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&tv, sizeof(struct timeval));
				        
				    }
    			}
    			else {

			if(FD_ISSET(i, &master)) 
			{
			
				if(!secure_connection) { //eseguo la authenticate solo la prima volta
						if(!recv_authentication(i))
						{
							cerr<<"Impossibile stabilire una connessione protetta."<<endl;
							quit(i);
							break;
						}
						else  //il server deve autenticarsi con il client
						{	
							cout<<"Invio certificato al client..."<<endl;
							if(!send_authentication(i))
							{					
								cerr<<"Certificato server non valido."<<endl;
								exit(1);
							}
							else
							{
								create_secure_session(i);
								//se tutto va a buon fine setto la secure_connection
								secure_connection = true;
								cout<<"SERVER: Aperta sessione sicura."<<endl;
							}
								
						}
				}
            			if(i != sd)
            			{
            				//ricevo numero di sequenza (criptato) dal client
            				recv_status(i);
					
					switch(code)
					{
						//case 0:
						//	break;
						case 1: //============ricezione file============ comando !upload
						{
							cout<<"In attesa di file..."<<endl;
							
							recvData(new_sd); //ricevo nome file
							
							if(!check_command_injection(net_buf)) {
								cout<<"ERRORE: Il nome file presenta caratteri non consentiti!"<<endl;	
								break;					
							}
							cout<<"Ricevuto il nome_file: "<<net_buf<<endl;
							
							bool found = search_file(net_buf.c_str());
							
							send_seqno(i);
							
							//2) mando l'esito al client
							if(send(i, (void*)&found, sizeof(found), 0)== -1)
							{
								cerr<<"Errore di send() relativa all'esistenza del file. Codice:"<<errno<<endl;
								exit(1);
							}
							seqno++;
							
							if(found)
							{
								cout<<"File esistente."<<endl;
								break;
							}
							else recv_file(net_buf.c_str());
													
							break;
						}
						case 2: //========download file============= comando !get
						{	recvData(new_sd);
							
							string filename = net_buf.c_str();
							cout<<"Il client "<<new_sd<<" ha richiesto di scaricare il file: "<<filename<<endl;
							
							//1) controllo se il file esite
							bool found = search_file(filename);
							
							send_seqno(i);
							//2) mando l'esito al client
							if(send(i, (void*)&found, sizeof(found), 0)== -1)
							{
								cerr<<"Errore di send() relativa all'esistenza del file. Codice:"<<errno<<endl;
								exit(1);
							}
							seqno++;
							
							//3) se non esiste mi fermo qua
							if(!found) { cout<<"File inesistente."<<endl; break; }
							
							//4) se esiste, procedo all'invio
							
							string path ="../serv_files/";
							path.append(filename);
							
							fp.open(path.c_str(), ios::in | ios::binary); //apro il file in modalità binaria
				    	
					    		if(!fp) { cerr<<"ERRORE: apertura file non riuscita."<<endl; break; }
					    		else 
					    		{
								cout<<"Invio file in corso..."<<endl;
								send_file(i);
							}
							break;
						}
						case 3: //=============quit=============
							quit(i);
							break;
						case 4: //============invio lista file disponibili========
							list(i);
							break;
						case 5:
							cout<<"@ @ @ @  @     @  @ @ @ @  @ @ @ @  @ @ @ @  @ @ @ @    @     @  @  @ @ @ @ @"<<endl;
							cout<<"@        @     @  @     @  @        @     @  @     @    @     @         @    "<<endl;
							cout<<"  @      @     @  @ @ @ @  @        @ @ @ @  @     @    @     @  @      @    "<<endl;
							cout<<"    @    @     @  @        @ @ @    @ @      @ @   @    @     @  @      @    "<<endl;
							cout<<"      @  @     @  @        @        @   @    @   @ @    @     @  @      @    "<<endl;
							cout<<"@ @ @ @  @ @ @ @  @        @ @ @ @  @     @  @ @ @ @ @  @ @ @ @  @      @    "<<endl;
							X509_STORE_free(store);
							exit(EXIT_SUCCESS);
						default:
							break;
					
					}
            			}
            		}
            		}
            		}
            	}//chiusura for
       }//chiusura while
return 0;
}
