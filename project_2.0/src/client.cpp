//LIBRERIE C-SOCKET
#include <arpa/inet.h> 
#include <netinet/in.h> 
#include <sys/socket.h> 
#include <sys/types.h>

//LIBRERIE OPENSSL
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/hmac.h>

//LIBRERIE VARIE
#include <unistd.h> 
#include <iostream>
#include <string>
#include <regex>
#include <cstdio>
#include <fstream>
#include <errno.h>
#include <dirent.h>
#include <stdlib.h>
#include <time.h>


using namespace std;

# define CHUNK 512000 //512 KiB
# define IP_ADDR "127.0.0.1"
# define PORT_NO 15050
# define NONCE_LENGTH 4 //byte
# define IV_LENGTH 16
# define SESSION_KEY_LEN 16
# define AUTH_KEY_LEN 32

//========prototipi funzioni============
bool recv_ack();
void send_ack(bool);
void send_status(int);
void printMsg();
void send_port();
void sock_connect(const char*, int);
void create_udp_socket();
void quit(int);
void send_data(string, int);
void send_file();
void recvData(int);
void recv_file(string,int);
bool check_command_injection(string);
bool search_file(string);
int check_seqno(uint32_t);
void send_seqno(int);
void recv_seqno(int);
bool send_authentication();
bool recv_authentication();
bool create_nonce();
string compute_hmac(string);
bool verify_hmac(string, string);
void send_hmac(string, int);
bool recv_hmac(string, int);

//=====variabili socket ==========
struct timeval tv;
int porta, ret, sd;
struct sockaddr_in srv_addr;
bool udp_sock_created = false;
fd_set master, read_fds;
int fdmax;
int udp_socket;
uint32_t udp_port;
struct sockaddr_in address;
//================================
bool dbgmode = 1; //serve oer attivare dei messaggi di debug nelle funzioni
string net_buf;

int stato, len;
long long int lmsg;
fstream fp; //puntatore al file da aprire

//==========variabili cybersecurity===========

EVP_CIPHER_CTX *decr_context;
EVP_CIPHER_CTX *encr_context; //context usato nelle encrypt/decrypt
bool first_encr = true, first_decr = true; //var che indica se è la prima volta che uso encr/decr in modo da fare una volta sola la Init()

uint32_t seqno = 0; //numero di sequenza pacchetti
uint32_t seqno_r = 0; //num seq ricevuto
uint32_t expected_seqno = 0; //seqno atteso per calcolare hmac relativo ad un messaggio
string cert_name = "../certif/gerardo_cert.pem";
X509_STORE *store;
char *nonce_client;
string key_auth, key_encr, init_v;
bool key_handshake = true; //indica se siamo in fase di scambio di chiavi in modo da non usare la cifratura con chiavi che sarebbero non ancora inizializzate 
int HASH_SIZE = EVP_MD_size(EVP_sha256());
//============================================

string compute_hmac(const string message)
{
	//declaring the hash function we want to use (md = message digest)

	/*if(dbgmode) {
		cout<<"Messaggio in chiaro + seq.No: "<<endl;
		BIO_dump_fp(stdout, (const char*)message.c_str(), message.size());
	}*/

	unsigned int hash_len;
	//create a buf for our digest
	unsigned char *hash_buf = new unsigned char[HASH_SIZE];
		
	//create message digest context
	HMAC_CTX* mdctx = HMAC_CTX_new();
	if(!mdctx) cout<<"hmac() out of memory"<<endl;
	
	//Init,Update,Finalise digest
	bool result = HMAC_Init_ex(mdctx, (unsigned char*)key_auth.c_str(), AUTH_KEY_LEN, EVP_sha256(), NULL)
	&& HMAC_Update(mdctx, (unsigned char*)message.c_str(), message.size())
	&& HMAC_Final(mdctx, hash_buf, (unsigned int*) &hash_len);
	
	if(!result) cout<<"errore nella compute_hmac!!"<<endl;
	string outs;
	outs.assign((char*)hash_buf, hash_len);

	//Delete context
	HMAC_CTX_free(mdctx);
	delete[] hash_buf;
	
	return outs;
}

bool verify_hmac(const string ciphertext, const string hmac_recv)
{
	//1) calcolo hmac del plaintext ricevuto
	string hmac_calc = compute_hmac(ciphertext);

	//2) confronto hmac calcolato con hmac ricevuto
	if(CRYPTO_memcmp((unsigned char*)hmac_calc.c_str(), (unsigned char*)hmac_recv.c_str(), HASH_SIZE) != 0)
	{
		if(dbgmode) {
			cout<<"######### Errore verify_hmac() ############"<<endl;
			cout<<"HMAC calcolato: "<<endl;
			BIO_dump_fp(stdout, (const char*)hmac_calc.c_str(), hmac_calc.length());
			
			cout<<"HMAC ricevuto: "<<endl;
			BIO_dump_fp(stdout, (const char*)hmac_recv.c_str(), hmac_recv.length());
			
			cout<<"############################################"<<endl;
		}
		return false;
	}
	else return true;
}

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
	
	if(dbgmode) cout<<"Creato deposito dei Certificati."<<endl;
	//utilizzo store ...
	return true;
}

bool recv_authentication()
{
	// Attendo dimensione del mesaggio                
	if(recv(sd, (void*)&lmsg, sizeof(uint64_t), 0) == -1)
	{
		cerr<<"Errore in fase di ricezione lunghezza. Codice: "<<errno<<endl;
		return false;
	}
	
	len = ntohs(lmsg); // Rinconverto in formato host
	
	char *buf = new char[len];
	if(recv(sd, (void*)buf, len, 0) == -1)
	{
		cerr<<"Errore in fase di ricezione buffer dati. Codice: "<<errno<<endl;
		return false;
	}

	X509 *cert = d2i_X509(NULL, (const unsigned char**)&buf, len);
	if(!cert) return false;
	
	X509_NAME *subject_name = X509_get_subject_name(cert);
	string sname = X509_NAME_oneline(subject_name, NULL, 0);
	
	sname = sname.substr(9, sname.npos);
	X509_STORE_CTX *ctx = X509_STORE_CTX_new();
	X509_STORE_CTX_init(ctx, store, cert, NULL);
	
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
		send_ack(false);
		return false;
	}
	cout<<"Certificato del server "<<sname<<" valido."<<endl;
	send_ack(true);
	X509_STORE_CTX_free(ctx);
	return true;
	
}

int main()
{
	udp_port = PORT_NO;
	sock_connect(IP_ADDR, PORT_NO); //argv[0] è il comando ./client, argv[1]=porta client, argv[2] porta server
	
	FD_ZERO(&master);
	FD_ZERO(&read_fds);
	FD_SET(0, &master);
	FD_SET(sd, &master);
	fdmax = sd;

    	create_udp_socket();
	
	tv.tv_sec = 2000; //20sec timeout
        setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&tv, sizeof(struct timeval));
        
	if(!create_ca_store())
	{
		cerr<<"Impossibile creare deposito certificati."<<endl;
		return 0;
	}
    	
    	if(!send_authentication())
	{
    		cerr<<"Certificato non valido."<<endl;
		exit(1);
	}

	if(!recv_authentication())
	{
		cerr<<"Certificato server non valido."<<endl;
		exit(1);
	}
	
	recvData(sd);
	key_encr = net_buf;
	
	recvData(sd);
	key_auth = net_buf;

	recvData(sd);
	init_v = net_buf;

	recvData(sd);
	string nonce_a = net_buf;

	recvData(sd);
	string nonce_b = net_buf;

	string app(nonce_client); //mi appoggio ad una stringa altrimenti non funziona l'operatore di confronto
	app.resize(NONCE_LENGTH);
	
	if(nonce_a == app) cout<<"nonce_a verificato."<<endl;
	else cout<<"ERRORE di verifica nonce_a."<<endl; //gestire questa cosa
	
	if(send(sd, (void*)nonce_b.c_str(), NONCE_LENGTH, 0) ==-1)
	{
		cerr<<"Errore in fase di send nonce_b. Codice: "<<errno<<endl;
		exit(1);
	}
	
	key_handshake = false;
	cout<<"SYSTEM: Fine hadshake chiavi/certificati. Stabilita connessione sicura."<<endl;
	
	HASH_SIZE = EVP_MD_size(EVP_sha256());
	
	cout<<"======================================="<<endl;
	cout<<"|            CLIENT AVVIATO           |"<<endl;
	cout<<"======================================="<<endl;
	
	printMsg();

while(1)
{	printf(">");
	fflush(stdout);
	read_fds = master;
	
	if(select(fdmax +1, &read_fds, NULL, NULL, NULL) == -1)
    	{
    		perror("SERVER: select() error.");
    		exit(1);
    	}

    	for(int i = 0; i<=fdmax; i++)
    	{	
    		if(FD_ISSET(i, &read_fds))
    		{	
    			if(i == 0)
    			{
    				net_buf.clear();
    				cin>>net_buf; //controllo secure coding?
    				
    				if(net_buf == "!help") {
					stato=0;
					printMsg(); }
				else if(net_buf == "!upload") 
					stato = 1;
				else if(net_buf ==  "!get")
					stato = 2;
				else if(net_buf == "!quit")
					stato = 3;
				else if(net_buf == "!list")
					stato = 4;
				else if(net_buf == "!squit")
					stato = 5;
				else stato = -1; //stato di errore

				
				switch(stato) 
				{
					case 0: //stato neutro
						break;
					case 1: //====== !upload ==========
						net_buf.clear();
						cout<<"Inserire il nome del file da inviare: "<<endl;
						cin>>net_buf;
						if(!check_command_injection(net_buf)){
							cout<<"Carattere non consentito"<<endl;	
							break;					
						}
				    		else 
				    		{
				    			//controllare esistenza file
				    			if(!search_file(net_buf)) { cout<<"File inesistente."<<endl; break; }
				    			
				    			send_status(stato);				    			
				    			send_data(net_buf, net_buf.length()); //invio il nome file
				    			
				    			//string fname_hmac = compute_hmac(net_buf); //calcolo e invio l'hmac(nomefile)
				    			//send_data(fname_hmac, fname_hmac.length());
				    			
				    			recv_seqno(sd);
				    			if(check_seqno(seqno_r) == -1) exit(1);
				    			
				    			//ricevo conferma esistenza file
							bool found;
							if(recv(sd, &found, sizeof(found), 0) == -1) //sostituito new_sd con i
							{
							    cerr<<"Errore in fase di recv() relativa all'esistenza del file. Codice: "<<errno<<endl;
							    exit(1);
							}
							seqno++;
							
							if(found) //esiste già un file con questo nome sul server
							{
								cout<<"Esiste già un file "<<net_buf<<" sul server. Rinominare il file e riprovare."<<endl;
								break;
							}
				    			else
				    			{
				    				string path = "../download/";
				    				path.append(net_buf);
				    				fp.open(path.c_str(), ios::in | ios::binary);			    
				    				if(!fp) { cerr<<"ERRORE: apertura file non riuscita."<<endl; break; }
				    				cout<<"Apertura file eseguita correttamente."<<endl;
				    				
				    				send_file(); //invio il file vero e proprio			
				    			}
				    		}
				    		
						break;
					case 2: //========== !get ===============
					{
						net_buf.clear();
						send_status(stato);
						
						cout<<"Inserire il nome del file da scaricare: "<<endl;
						cin>>net_buf;
						if(!check_command_injection(net_buf)){
							cout<<"Carattere non consentito"<<endl;	
							break;						
						}
										    		
						//controllo esistenza file in locale
						if(search_file(net_buf.c_str()))
						{
							char c;
							cout<<"ATTENZIONE: Esiste già un file con questo nome. Sovrascriverlo? (s/n):"<<endl;
							cin>>c;
							if(c!='s') break;
						}						

						send_data(net_buf, net_buf.length()); //invio nome al server e attendo conferma per il download
						
						//string fname_hmac = compute_hmac(net_buf); //calcolo e invio hmac(nomefile)
						//send_data(fname_hmac, fname_hmac.length());
						
						recv_seqno(sd);
						if(check_seqno(seqno_r) == -1) exit(1);
						
						//ricevo conferma esistenza file
						bool found;
						if(recv(sd, &found, sizeof(found), 0) == -1) //sostituito new_sd con i
						{
						    cerr<<"Errore in fase di recv() relativa all'esistenza del file. Codice: "<<errno<<endl;
						    exit(1);
						}
						seqno++;
						
						if(!found) { cout<<"File inesistente sul server!"<<endl; break; }
						else
						{
							cout<<"Il file è disponibile per il download."<<endl;
							cout<<"In attesa del file: "<<net_buf<<endl;
							
							recv_file(net_buf.c_str(), sd);
						}
						
						break;
					}
					case 3:
						send_status(stato);
						quit(i);
						break;
					case 4: //comando !List
					{
						send_status(stato);
						
						recvData(sd); //ricevo la lista e la decifro
						//string tmp_lista = net_buf, 
						string lista = net_buf;
						
						sleep(0.5);
						cout<<"======= FILE DISPONIBILI ========"<<endl;
						cout<<lista;
						cout<<endl<<"================================="<<endl;
						break;
					}
					case 5:
						send_status(stato);
						cout<<"Disconnessione in corso..."<<endl;
						quit(i);
						break;
					default:
						cout<<"Comando non riconosciuto. Riprovare."<<endl;
						break;
				} //chiusura switch
					
    			}
    		}
    	}
}

	return 0;
}

void send_ack(bool ack)
{
	if(send(sd, (void*)&ack, sizeof(ack), 0)== -1)
	{
		cerr<<"Errore di send(ack). Codice:"<<errno<<endl;
		exit(1);
	}
}

bool recv_ack()
{
	bool ack;
	if(recv(sd, &ack, sizeof(ack), 0) == -1)
	{
	    cerr<<"Errore in fase di recv(ack). Codice: "<<errno<<endl;
	    exit(1);
	}
	return ack;
}

int check_seqno(uint32_t sr)
{
	if(dbgmode) cout<<"Ricevuto: "<<sr<<" | Atteso: "<<seqno<<endl;
	if(sr == UINT32_MAX)
	{
		cout<<"Sessione scaduta! Aprire una nuova connessione."<<endl;
		exit(0);
	}
	
	if(sr != seqno) //gestire la chiusura della connessione per bene
	{
		cerr<<"Numeri di sequenza fuori fase!"<<endl;
		return -1;
	}
	else return 0;
}

void send_seqno(int sd)
{
	if(dbgmode) cout<<"Invio seqno "<<seqno<<" in corso..."<<endl;
	
	//invio seqno
	if(send(sd, &seqno, sizeof(uint32_t), 0)== -1)
	{
		cerr<<"Errore di send(seqno). Codice: "<<errno<<endl;
		exit(1);
	}
}

void recv_seqno(int sd)
{
	if(dbgmode) cout<<"Attendo seqno..."<<endl;
	int ret;
	//ricevo numero di sequenza dal client
	if((ret=recv(sd, &seqno_r, sizeof(uint32_t), 0)) == -1)
	{
	    cerr<<"Errore di recv(seqno). Codice: "<<errno<<endl;
	    exit(1);
	}
	cout<<"ret: "<<ret<<endl;
	cout<<"Ricevuto seqno "<<seqno_r<<endl;
}

void recv_file(string filename, int new_sd)
{
	recv_seqno(new_sd);
	if(recv(new_sd, &lmsg, sizeof(uint64_t), MSG_WAITALL) == -1)
	{
		cerr<<"Errore in fase di ricezione lunghezza file. Codice: "<<errno<<endl;
		exit(1); 
	}
	seqno++;
	long long int fsize = ntohl(lmsg); // Rinconverto in formato host
	cout<<"Lunghezza file (Bytes): "<<fsize<<endl;							
	char *ptx_buf = new char[CHUNK];
	char *ctx_buf = new char[CHUNK];
//il flag WAITALL indica che la recv aspetta TUTTI i pacchetti. Senza ne riceve solo uno e quindi file oltre una certa dimensione risultano incompleti							
	
	cout<<"Ricezione di "<<filename<<" in corso..."<<endl;
	
	long long int mancanti = fsize;
	long long int ricevuti = 0;
	int count=0, progress = 0;
	
	string path = "../download/";
	path.append(filename);
	
	fp.open(path.c_str(), ios::out | ios::binary); //creo il file con il nome passato
	
	if(!fp) { cerr<<"Errore apertura file."<<endl; exit(1); }
	
	while((mancanti-CHUNK) > 0)
	{
		//ricevo numero di sequenza dal server
		recv_seqno(new_sd);
		
		if(check_seqno(seqno_r) == -1)
		{
			fp.close();
			remove(filename.c_str()); //elimino il file
			exit(1); //gestire meglio la chiusura
		}
		
		expected_seqno = seqno;
		
		int n = recv(new_sd, (void*)ctx_buf, CHUNK, MSG_WAITALL);
		if(n == -1)
		{
			cerr<<"Errore in fase di ricezione buffer dati. Codice: "<<errno<<endl;
			exit(1);
		}
		seqno++;
		
		string app_buf;
		app_buf.assign(ctx_buf, CHUNK);
		if(!recv_hmac(app_buf, new_sd)) //ricevo l'hmac di questo pacchetto
		{
			fp.close();
			remove(filename.c_str()); //elimino il file
			return;
		}

		if((ret = decrypt(ctx_buf, CHUNK, ptx_buf))==0) { cerr<<"Errore di decrypt()."<<endl; exit(1); }
		
		ricevuti += n;
		mancanti -= n;
		
		fp.write(ptx_buf, CHUNK);

		//percentuale di progresso
		progress = (ricevuti*100)/fsize;
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
			remove(filename.c_str()); //elimino il file
			exit(1); //gestire meglio la chiusura
		}
		
		expected_seqno = seqno;
		
		int n = recv(new_sd, (void*)ctx_buf, mancanti, MSG_WAITALL);
		if(n == -1)
		{
			cerr<<"Errore in fase di ricezione buffer dati. Codice: "<<errno<<endl;
			exit(1);
		}
		seqno++;

		string app_buf;
		app_buf.assign(ctx_buf, mancanti);
		if(!recv_hmac(app_buf, new_sd)) //ricevo l'hmac di questo pacchetto
		{
			if(dbgmode) cout<<"DIGEST_CHECK fallito nella parte mancante!"<<endl;
			fp.close();
			remove(filename.c_str()); //elimino il file
		}

		if((ret = decrypt(ctx_buf, mancanti, ptx_buf))==0) { cerr<<"Errore di decrypt()."<<endl; exit(1); }
		
		ricevuti += n;
		progress = (ricevuti*100)/fsize;
		cout<<"\r"<<progress<<"%";
		count++;
		
		fp.write(ptx_buf, mancanti);

		delete[] ptx_buf;
		delete[] ctx_buf;
	}
	cout<<endl;
	cout<<"Ricevuto file in "<<count<<" pacchetti, per un totale di "<<ricevuti<<" bytes."<<endl;
	
	if(ricevuti != fsize)
	{
		cerr<<"Errore di trasferimento."<<endl;
		remove(filename.c_str()); //elimino il file
		return;
	}
							
	cout<<"Salvataggio file completato."<<endl;
	fp.close();
	cout<<"File chiuso."<<endl;
}

void send_file()
{
	fp.seekg(0, fp.end); //scorro alla fine del file per calcolare la lunghezza (in Byte)
	long long int fsize = fp.tellg(); //fsize conta il num di "caratteri" e quindi il numero di byte --> occhio che se dim file > del tipo int ci sono problemi
	fp.seekg(0, fp.beg); //mi riposizione all'inizio
	
	cout<<"Lunghezza file(Byte): "<<fsize<<endl;
	
	char *ptx_buf = new char[CHUNK]; //buffer per lettura da file
	char *ctx_buf = new char[CHUNK]; //buffer (cifrato) da trasmettere sul socket
	
	if(fsize >= 4200000000) lmsg = htonl(0);
	else lmsg = htonl(fsize); //invio lunghezza file (max 4.2 GiB)
	
	send_seqno(sd);
	if(send(sd, &lmsg, sizeof(uint64_t), 0) == -1)
	{
		cerr<<"Errore di send(size)."<<endl;
		exit(1);
	}
	seqno++;
	
	if(fsize >= 4200000000)
	{
		cout<<"Errore: dimensione file troppo grande. Dim. max: 4,2 GigaByte."<<endl;
		return;
	}
	
	cout<<"Invio del file: "<<net_buf<<" in corso..."<<endl;
	
	long long int mancanti = fsize;
	long long int inviati = 0;
	int count=0, progress=0, ret=0;
	
	while((mancanti-CHUNK)>0)
	{
		//invio il numero di sequenza
		send_seqno(sd);
		
		fp.read(ptx_buf, CHUNK); //ora buf contiene il contenuto del file letto
		
		if((ret = encrypt(ptx_buf, CHUNK, ctx_buf)) == 0) { cerr<<"Errore di encrypt()."<<endl; exit(1); }
		
		int n = send(sd, (void*)ctx_buf, CHUNK, 0);
		if(n == -1)
		{
			cerr<<"Errore di send(buf). Codice: "<<errno<<endl;;
			exit(1);
		}
		count++; seqno++;
		
		//if(dbgmode) { cout<<"ptx_buf nella send_file() passato per calcolo HMAC: "<<endl; BIO_dump_fp(stdout, (const char*)ptx_buf, mancanti); }
		string app_buf;
		app_buf.assign(ctx_buf, CHUNK);
		send_hmac(app_buf, sd);
		
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

		if((ret = encrypt(ptx_buf, mancanti, ctx_buf)) == 0) { cerr<<"Errore di encrypt()."<<endl; exit(1); }
		
		int n = send(sd, (void*)ctx_buf, mancanti, 0);
		if(n == -1)
		{
			cerr<<"Errore di send(buf). Codice: "<<errno<<endl;;
			exit(1);
		}
		count++; seqno++;
		
		//if(dbgmode) { cout<<"ptx_buf nella send_file() passato per calcolo HMAC: "<<endl; BIO_dump_fp(stdout, (const char*)ptx_buf, mancanti); }
		string app_buf;
		app_buf.assign(ctx_buf, mancanti);
		send_hmac(app_buf, sd);
		
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

void recvData(int sd)
{
	recv_seqno(sd);
	if(check_seqno(seqno_r) == -1) exit(1);

	// Attendo dimensione del mesaggio                
	if(recv(sd, (void*)&lmsg, sizeof(uint32_t), 0) == -1)
	{
		cerr<<"Errore in fase di ricezione lunghezza. Codice: "<<errno<<endl;
		exit(1);
	}
	seqno++;
	len = ntohl(lmsg); // Rinconverto in formato host
	
	recv_seqno(sd);
	if(check_seqno(seqno_r) == -1) exit(1);

	expected_seqno = seqno;
	
	char *tmp_buf = new char[len];
	if(recv(sd, (void*)tmp_buf, len, MSG_WAITALL) == -1)
	{
		cerr<<"Errore in fase di ricezione buffer dati. Codice: "<<errno<<endl;
		exit(1);
	}
	seqno++;
	if(!key_handshake) //se la cifratura è abilitata
	{
		string app_buf;
		app_buf.assign(tmp_buf, len);
		if(!recv_hmac(app_buf, sd)) //ricevo hmac(lista+seqno)
			exit(1);

		char *ptx_buf = new char[len];
		if(decrypt(tmp_buf, len, ptx_buf)==0) { cerr<<"Errore di decrypt() nella recvData()"<<endl; exit(1); }
		net_buf.assign(ptx_buf, len);
		delete[] ptx_buf;
	}
	else //siamo ancora in fase di handshake chiavi pertanto non devo decifrare normalmente
		net_buf.assign(tmp_buf, len);
		
	net_buf.resize(len);
	delete[] tmp_buf;	
}

void send_data(string buf, int buf_len)
{
	//invio seqno
	send_seqno(sd);

	lmsg = htons(buf_len);
	
	if(send(sd, (void*) &lmsg, sizeof(uint32_t), 0) == -1)
	{
		cerr<<"Errore di send(size). Codice: "<<errno<<endl;
		exit(1);
	}
	seqno++;
	
	send_seqno(sd);
	char *ptx_buf = new char[buf_len]; //+1 ?
	memcpy(ptx_buf, buf.data(), buf_len);
	
	char *ctx_buf = new char[buf_len];
	if(encrypt(ptx_buf, buf_len, ctx_buf) == 0) { cerr<<"Errore di encrypt() nella send_data()."<<endl; exit(1); }
	
        if(send(sd, (void*)ctx_buf, buf_len, 0) == -1)
        {
        	cerr<<"Errore di send(buf). Codice: "<<errno<<endl;;
        	exit(1);
        }
        seqno++;        
        stato = -1;

	string app_buf;
	app_buf.assign(ctx_buf, buf_len);
	send_hmac(app_buf, sd);

        delete[] ptx_buf;
        delete[] ctx_buf;
}

void send_status(int stato)
{
	if(stato < 0) stato = 0;
	send_data(to_string(stato), 1);
}

void printMsg()
{
	cout<<"Sono disponibili i seguenti comandi: "<<endl<<endl;
	cout<<"!help --> mostra l'elenco dei comandi disponibili "<<endl;
	cout<<"!upload --> carica un file presso il server "<<endl;
	cout<<"!get --> scarica un file dal server "<<endl;
	cout<<"!quit --> disconnette il client dal server ed esce "<<endl;
	cout<<"!list --> visualizza elenco file disponibili sul server "<<endl;
	cout<<"!squit --> SUPERQUIT: termina client e server "<<endl;
	cout<<endl;
}

void send_port()
{
	if(send(sd, (void*) &porta, sizeof(porta), 0) == -1)
		cout<<"Errore di send(). "<<endl;
}

void create_udp_socket()
{
	int yes = 1;
	
	if((udp_socket = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
		cerr<<"errore creazione socket UDP."<<endl;
		exit(1);
	}
	
	address.sin_family = AF_INET;
    	address.sin_port = htons(udp_port);
    	address.sin_addr.s_addr = htonl(INADDR_ANY);
    	
    	if(setsockopt(udp_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1)
    	{
    		cerr<<"Errore di setsockopt."<<endl;
    		exit(1);
    	}
    	
    	if(bind(udp_socket, (struct sockaddr*)&address, sizeof(address)) == -1)
    	{
    		cerr<<"errore in fase di bind() udp."<<endl;
    		exit(1);
    	}
    	
    	if(udp_socket > fdmax)
    		fdmax = udp_socket;
    	FD_SET(udp_socket, &master);
	
	udp_sock_created = true;
}

void sock_connect(const char* address, int porta_server)
{
	/* Creazione socket */
    	sd = socket(AF_INET, SOCK_STREAM, 0);
    	
    	/* Creazione indirizzo del server */ 
    	srv_addr.sin_family = AF_INET;
    	srv_addr.sin_port = htons(porta_server);
    	inet_pton(AF_INET, address, &srv_addr.sin_addr);
    	
    	if(connect(sd, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0)
   	{
        	cerr<<"Errore in fase di connessione: "<<endl;
        	exit(-1);
    	}
    	else if(dbgmode)
    	{
    		cout<<"Connessione al server "<<address<<" sulla porta "<<porta_server<<" effettuata con successo."<<endl;
    		cout<<"Ricezione messaggi istantanei su porta "<<porta<<"."<<endl<<endl;
    	}
}

void quit(int i)
{			
	FD_CLR(i, &master);
	close(sd);
	cout<<"Client disconnesso."<<endl;
	EVP_CIPHER_CTX_free(encr_context);
	EVP_CIPHER_CTX_free(decr_context);
	exit(0);
}

bool check_command_injection(string buf)
{
	regex b("[A-Za-z0-9.-_]+");
	if(regex_match(buf, b))
		return true;
	else 
		return false;
}

bool search_file(string buf) //return true se il file esiste
{
	DIR *d;
	struct dirent *dir;
	d = opendir("../download");
	if(d)
	{
		while((dir = readdir(d)) != NULL)
			if(dir->d_type == 8)
				if(dir->d_name == buf) return true;
	closedir(d);
	}
	return false;
}

bool create_nonce()
{
	if(RAND_poll() != 1){
		cerr<<"Errore esecuzione RAND_poll()"<<endl;
		return false;
	}

	nonce_client = new char[NONCE_LENGTH];

	if(RAND_bytes((unsigned char*)nonce_client, NONCE_LENGTH) != 1){
		cerr<<"Errore esecuzione RAND_bytes"<<endl;
		return false;
	}

	/*lmsg = htons(NONCE_LENGTH);
	if(send(sd, (void*) &lmsg, sizeof(uint16_t), 0) == -1)
	{
		cerr<<"Errore di send(size). Codice: "<<errno<<endl;
		return false;
	}*/
	
	//nonce_length è già nota al server
	if(send(sd, (void*)nonce_client, NONCE_LENGTH, 0)== -1)
	{
		cerr<<"Errore di send(nonce). Codice: "<<errno<<endl;
		return false;
	}

	return true;
}

bool send_authentication()
{

	if(!create_nonce())
		return false;
	
	X509 *cert;
	FILE *fpem = fopen(cert_name.c_str(), "rb");
	
	if(!fpem)
	{
		cout<<"File certificato non trovato."<<endl;
		return false;
	}
	
	cert = PEM_read_X509(fpem, NULL,NULL,NULL);
	if(!cert)
	{
		cout<<"Errore lettura certificato."<<endl;
		return false;
	}

	unsigned char *buf = NULL;
	unsigned long int fsize = i2d_X509(cert, &buf);
	if(fsize <= 0) return false;
	
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
	}
	OPENSSL_free(buf);
	
	cout<<"Certificato inviato al server."<<endl;
	if(!recv_ack())
	{
		cout<<"Errore di autenticazione."<<endl;
		exit(1);
	}
	
	fclose(fpem);
	return true;	
}
void send_hmac(string buf, int sock)
{
	if(dbgmode) cout<<"send_hmac()..."<<endl;
	send_seqno(sock);
	
	//if(dbgmode) { cout<<"Ciphertext da firmare: "<<endl; BIO_dump_fp(stdout, (const char*)buf.c_str(), buf.length()); }
	
	//calcolo hmac di {messaggio,seqno}, seqno-1 perchè è relativo al MESSAGGIO che era la send precedente a questa
	string buf_hmac = compute_hmac(buf.append(to_string(seqno-1))); 
	
	char *c_buf_hmac = new char[HASH_SIZE];
	memcpy(c_buf_hmac, buf_hmac.data(), HASH_SIZE);

	if(send(sock, (void*)c_buf_hmac, HASH_SIZE, 0) == -1)
	{
		cerr<<"Errore di send_hmac(). Codice: "<<errno<<endl;
		exit(1);
	}
	seqno++; 
	
	if(dbgmode) {
		cout<<"HMAC inviato: "<<endl;
		BIO_dump_fp(stdout, (const char*)c_buf_hmac, HASH_SIZE);
	}
	
	delete[] c_buf_hmac;
}

bool recv_hmac(string ciphertext, int sock)
{
	if(dbgmode) cout<<"recv_hmac()..."<<endl;
	
	recv_seqno(sock);
	if(check_seqno(seqno_r) == -1) exit(1);
	
	char *c_buf_hmac = new char[HASH_SIZE];
	if(recv(sock, (void*)c_buf_hmac, HASH_SIZE, 0) == -1)
	{
		cerr<<"Errore di recv_hmac(). Codice: "<<errno<<endl;
		exit(1);
	}
	seqno++;
	
	net_buf.clear();
	net_buf.assign(c_buf_hmac, HASH_SIZE);
	net_buf.resize(HASH_SIZE);
	delete[] c_buf_hmac;
	
	ciphertext.append(to_string(expected_seqno)); //seqno-1 perchè è relativo al seqno del messaggio che era la recv preced..

	if(!verify_hmac(ciphertext, net_buf))
	{
		cerr<<"Digest Check fallito!"<<endl;
		return false;
	}
	sleep(0.5);
	return true;
}

