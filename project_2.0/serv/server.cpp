#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/select.h>
#include <string>
#include <iostream>
#include <fstream>
#include <errno.h>
#include <dirent.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/rand.h>
#include <time.h>
#include <cstring>

using namespace std;

# define CHUNK 512000
# define IP_ADDR "127.0.0.1"
# define PORT_NO 15050
# define NONCE_LENGTH 4 //byte
# define IV_LENGTH 6 //initialization value (controllare la dimensione (byte)
# define SESSION_KEY_LEN 8 //controllare dim

//========variabili socket========
int ret, sd, new_sd, porta;
unsigned int len;
struct sockaddr_in my_addr, cl_addr;
fd_set master, read_fds;
int fdmax;
bool busy = false; //serve per accettare una sola connessione
//================================

string net_buf;

string filename;
int code;
long long int ctx_len, lmsg;
fstream fp;

//==========variabili cybersecurity===========

uint32_t seqno; //numero di sequenza pacchetti
uint32_t seqno_r; //num sequenza ricevuto
bool secure_connection = false;
string cert_server = "../Certificati_PrivateKey/Server_cert.pem";
X509_STORE *store;
char *key_encr, *key_auth, *init_v, *nonce_a, *nonce_b; //nonce_a= ricevuto dal client

//============================================

void send_ack(int sock, bool ack)
{
	if(send(sock, (void*)&ack, sizeof(ack), 0)== -1)
	{
		cerr<<"Errore di send(ack). Codice:"<<errno<<endl;
		exit(1);
	}
}

char* create_rand_val(int val_length)
{
	if(val_length <= 0)
		return NULL;
		
	if(RAND_poll() != 1){
		cerr<<"Errore esecuzione RAND_poll()"<<endl;
		return NULL;
	}	
	
	char *val = new char[val_length];
	
	if(RAND_bytes((unsigned char*)val, val_length) != 1){
		cerr<<"Errore esecuzione RAND_bytes"<<endl;
		return NULL;
	}	
	
	return val;
}

/*bool send_nonce(char *nonce)
{
	lmsg = htons(NONCE_LENGTH);
	if(send(sd, (void*) &lmsg, sizeof(uint16_t), 0) == -1)
	{
		cerr<<"Errore di send(size). Codice: "<<errno<<endl;
		return false;
	}

	if(send(sd, (void*)nonce, NONCE_LENGTH, 0)== -1)
	{
		cerr<<"Errore di send(nonce). Codice: "<<errno<<endl;
		return false;
	}

	return true;
}*/

bool create_ca_store()
{
	store = X509_STORE_new();
	FILE *fp;
	
	//aggiungo cert della trusted CA
	X509 *ca_cert;
	fp = fopen("../Certificati_PrivateKey/SimpleAuthorityCA_cert.pem", "r");
	if(!fp) return false;
	ca_cert = PEM_read_X509(fp, NULL, NULL, NULL);
	X509_STORE_add_cert(store, ca_cert);
	
	fclose(fp);
	
	//aggiungo lista cert revocati
	X509_CRL *crl;
	fp = fopen("../Certificati_PrivateKey/SimpleAuthorityCA_crl.pem", "r");
	if(!fp) return false;
	crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL);
	fclose(fp);
	
	X509_STORE_add_crl(store, crl);
	X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
	
	cout<<"Creato deposito dei Certificati."<<endl;
	//utilizzo store ...
	return true;
}

bool recv_nonce(int sd)
{
	// Attendo dimensione del messaggio 
	/*if(recv(sd, (void*)&lmsg, sizeof(uint64_t), 0) == -1)
	{
		cerr<<"Errore in fase di ricezione lunghezza. Codice: "<<errno<<endl;
		return false;
	}
	
	len = ntohs(lmsg); // Rinconverto in formato host*/
	
	nonce_a = new char[NONCE_LENGTH];
	
	if(recv(sd, (void*)nonce_a, NONCE_LENGTH, 0) == -1)
	{
		cerr<<"Errore in fase di ricezione nonce_a. Codice: "<<errno<<endl;
		return false;
	}
	return true;
}

bool recv_authentication(int sd)
{        
	if(!recv_nonce(sd))
		return false;

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
	X509 *cert;
	FILE *fpem = fopen(cert_server.c_str(), "rb");
	
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
}


int check_seqno(uint32_t seqno_r) //-1 in caso di errore, 0 se corrisponde
{
	if(seqno_r != seqno) //gestire la chiusura della connessione per bene
	{
		cerr<<"Numeri di sequenza fuori fase!"<<endl;
		return -1;
	}
	else return 0;
}

void send_seqno(int sd)
{
	//invio seqno
	if(send(sd, (void*)&seqno, sizeof(uint32_t), 0)== -1)
	{
		cerr<<"Errore di send(seqno). Codice: "<<errno<<endl;
		exit(1);
	}
}

void recv_seqno(int sd)
{
	//ricevo numero di sequenza dal client
	if(recv(sd, &seqno_r, sizeof(uint32_t), 0) == -1)
	{
	    cerr<<"Errore di recv(seqno). Codice: "<<errno<<endl;
	    exit(1);
	}
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
	net_buf = tmp_buf;
	net_buf.resize(len);
	seqno++;
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
								
	char *buf = new char[CHUNK];
//il flag WAITALL indica che la recv aspetta TUTTI i pacchetti. Senza ne riceve solo uno e quindi file oltre una certa dimensione risultano incompleti							
	
	cout<<"Ricezione di "<<filename<<" in corso..."<<endl;
	
	long long int mancanti = ctx_len;
	long long int ricevuti = 0;
	int count=0, progress = 0;
	
	string path ="./files/";
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
		
		int n = recv(new_sd, (void*)buf, CHUNK, MSG_WAITALL);
		if(n == -1)
		{
			cerr<<"Errore in fase di ricezione buffer dati. Codice: "<<errno<<endl;
			exit(1);
		}

		ricevuti += n;
		mancanti -= n;
		
		seqno++;
		fp.write(buf, CHUNK);

		//percentuale di progresso
		progress = (ricevuti*100)/ctx_len;
		cout<<"\r"<<progress<<"%";

		count++;
	}
	if(mancanti != 0)
	{
		delete[] buf;
		char *buf = new char[mancanti];
		
		//ricevo numero di sequenza dal client
		recv_seqno(new_sd);
		if(check_seqno(seqno_r) == -1)
		{
			fp.close();
			remove(path.c_str()); //elimino il file
			exit(1); //gestire meglio la chiusura
		}
		
		int n = recv(new_sd, (void*)buf, mancanti, MSG_WAITALL);
		if(n == -1)
		{
			cerr<<"Errore in fase di ricezione buffer dati. Codice: "<<errno<<endl;
			exit(1);
		}
		ricevuti += n;
		fp.write(buf, mancanti);
		seqno++;
		
		progress = (ricevuti*100)/ctx_len;
		cout<<"\r"<<progress<<"%";

		count++;
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

void send_data(string buf, int lung, int sock) 
{
	len = lung; // buf.length();
	lmsg = htonl(len);
	
	send_seqno(sock);
	if(send(sock, (void*) &lmsg, sizeof(uint32_t), 0) == -1)
	{
		cerr<<"Errore di send(size). Codice: "<<errno<<endl;
		exit(1);
	}
	seqno++;
	send_seqno(sock);
        
        if(send(sock, (void*)buf.c_str(), len, 0) == -1)
        {
        	cerr<<"Errore di send(buf). Codice: "<<errno<<endl;
        	exit(1);
        }
        seqno++;
        code = 0;
}

bool search_file(string filename)
{
	DIR *d;
	struct dirent *dir;
	d = opendir("./files");
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
	
	d = opendir("./files");
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

void send_file(int sd)
{
	fp.seekg(0, fp.end); //scorro alla fine del file per calcolare la lunghezza (in Byte)
	long long int fsize = fp.tellg(); //fsize conta il num di "caratteri" e quindi il numero di byte --> occhio che se dim file > del tipo int ci sono problemi
	fp.seekg(0, fp.beg); //mi riposizione all'inizio
	
	cout<<"Lunghezza file(Byte): "<<fsize<<endl;
	char *buf = new char[CHUNK];
	
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
		
		fp.read(buf, CHUNK); //ora buf contiene il contenuto del file letto
		int n = send(sd, (void*)buf, CHUNK, 0);
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
	if(mancanti!=0)
	{
		delete[] buf; //occhio !!
		char *buf = new char[mancanti];
		
		//invio il numero di sequenza
		send_seqno(sd);
		
		fp.read(buf, mancanti); //ora buf contiene il contenuto del file letto
		
		int n = send(sd, (void*)buf, mancanti, 0);
		if(n == -1)
		{
			cerr<<"Errore di send(buf). Codice: "<<errno<<endl;;
			exit(1);
		}
		count++; seqno++;
		inviati += n;
		progress = (inviati*100)/fsize;
		cout<<"\r"<<progress<<"%";	
	}
	cout<<endl;
	cout<<"Inviato file in "<<count<<" pacchetti."<<endl;
	fp.close();
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
							{	//generare Ks, Ka, IV e nonce_b
								key_encr = create_rand_val(SESSION_KEY_LEN);
								key_auth = create_rand_val(SESSION_KEY_LEN);
								init_v = create_rand_val(IV_LENGTH);
								nonce_b = create_rand_val(NONCE_LENGTH);
								
								//string s(key_encr);
								send_data(key_encr,SESSION_KEY_LEN, i);
								send_data(key_auth, SESSION_KEY_LEN, i);
								send_data(init_v, IV_LENGTH, i);
								send_data(nonce_a, NONCE_LENGTH, i);
								send_data(nonce_b, NONCE_LENGTH, i);
								
								char *tmp_buf = new char[NONCE_LENGTH];
								if(recv(i, (void*)tmp_buf, NONCE_LENGTH, 0) == -1)
								{
									cerr<<"Errore in fase di ricezione buffer dati. "<<endl;
									exit(1);
								}
								net_buf = tmp_buf;
								net_buf.resize(NONCE_LENGTH);
								delete[] tmp_buf;
								
								//mi appoggio ad una stringa altrimenti non funziona l'operatore di confront
								string app(nonce_b); 
								
								app.resize(NONCE_LENGTH);
								
								if(net_buf == app) cout<<"nonce_b verificato."<<endl;
								else cout<<"ERRORE verifica nonce_b."<<endl;
								
								//se tutto va a buon fine setto la secure_connection	
								secure_connection = true;
							}
								
						}
				}
            			if(i != sd)
            			{
            				//ricevo numero di sequenza dal client
					recv_seqno(i);					
            				if(check_seqno(seqno_r) == -1) exit(1);
            				
            				//ricevo comando dal client
            				if(recv(i, &code, sizeof(code), 0) == -1) //sostituito new_sd con i
					{
					    cerr<<"Errore in fase di ricezione comando: "<<endl;
					    exit(1);
		        		}
		        		seqno++;
					//cout<<"Ricevuto comando "<<code<<" dal client "<<i<<"."<<endl;
					
					switch(code)
					{
						//case 0:
						//	break;
						case 1: //============ricezione file============ comando !upload
						{
							cout<<"In attesa di file..."<<endl;
							
							recvData(new_sd); //ricevo nome file
							
							cout<<"Ricevuto il nome_file: "<<net_buf.c_str()<<endl;
							
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
							
							string path ="./files/";
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
							//cout<<"SUPERQUIT"<<endl;
							cout<<"@ @ @ @  @     @  @ @ @ @  @ @ @ @  @ @ @ @  @ @ @ @    @     @  @  @ @ @ @ @"<<endl;
							cout<<"@        @     @  @     @  @        @     @  @     @    @     @         @    "<<endl;
							cout<<"  @      @     @  @ @ @ @  @        @ @ @ @  @     @    @     @  @      @    "<<endl;
							cout<<"    @    @     @  @        @ @ @    @ @      @ @   @    @     @  @      @    "<<endl;
							cout<<"      @  @     @  @        @        @   @    @   @ @    @     @  @      @    "<<endl;
							cout<<"@ @ @ @  @ @ @ @  @        @ @ @ @  @     @  @ @ @ @ @  @ @ @ @  @      @    "<<endl;
							X509_STORE_free(store);
							exit(1);
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
