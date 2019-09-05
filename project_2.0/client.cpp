#include <arpa/inet.h> 
#include <netinet/in.h> 
#include <sys/socket.h> 
#include <sys/types.h>
#include <unistd.h> 
#include <iostream>
#include <string>
#include <regex>
#include <cstdio>
#include <fstream>
#include <errno.h>
#include <dirent.h>

using namespace std;

# define CHUNK 512000
# define IP_ADDR "127.0.0.1"
# define PORT_NO 15050

//========prototipi funzioni============
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
bool check_file_existance(string);
int check_seqno(uint32_t);
void send_seqno(int);
void recv_seqno(int);

//=====variabili socket ==========
int porta, ret, sd;
struct sockaddr_in srv_addr;
bool udp_sock_created = false;
fd_set master, read_fds;
int fdmax;
int udp_socket;
uint32_t udp_port;
struct sockaddr_in address;
//================================

string net_buf;

int stato, len;
long long int lmsg;
fstream fp; //puntatore al file da aprire

//==========variabili cybersecurity===========
unsigned int seqno; //numero di sequenza pacchetti
uint32_t seqno_r; //num seq ricevuto
//============================================

int main()
{
	udp_port = PORT_NO;
	sock_connect(IP_ADDR, PORT_NO); //argv[0] è il comando ./client, argv[1]=porta client, argv[2] porta server
	
	FD_ZERO(&master);
	FD_ZERO(&read_fds);
	FD_SET(0, &master);
	FD_SET(sd, &master);
	fdmax = sd;
	
	printMsg();

    	create_udp_socket();
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
				    			if(!check_file_existance(net_buf)) { cout<<"File inesistente."<<endl; break; }
				    			
				    			send_status(stato);				    			
				    			send_data(net_buf, net_buf.length()); //invio il nome file
				    			
				    			//ricevo conferma esistenza file
				    			recv_seqno(sd);
				    			if(check_seqno(seqno_r) == -1) exit(1);
				    			
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
				    				fp.open(net_buf.c_str(), ios::in | ios::binary);			    
				    				if(!fp) { cerr<<"ERRORE: apertura file non riuscita."<<endl; break; }
				    				cout<<"Apertura file eseguita correttamente."<<endl;
				    				
				    				send_file(); //invio il file vero e proprio			
				    			}
				    		}
				    		
						break;
					case 2: //========== !get ===============
						net_buf.clear();
						send_status(stato);
						
						cout<<"Inserire il nome del file da scaricare: "<<endl;
						cin>>net_buf;
						if(!check_command_injection(net_buf)){
							cout<<"Carattere non consentito"<<endl;	
							break;						
						}
						
						//controllo esistenza file in locale
						if(check_file_existance(net_buf.c_str()))
						{
							char c;
							cout<<"ATTENZIONE: Esiste già un file con questo nome. Sovrascriverlo? (s/n):"<<endl;
							cin>>c;
							if(c!='s') break;
						}						

						send_data(net_buf, net_buf.length()); //invio nome al server e attendo conferma per il download
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
							cout<<"In attesa del file: "<<net_buf.c_str()<<endl;
							
							recv_file(net_buf.c_str(), sd);
						}
						
						break;
					case 3:
						send_status(stato);
						quit(i);
						break;
					case 4: //comando !List
						send_status(stato);
						recvData(sd);
						cout<<"======= FILE DISPONIBILI ========"<<endl;
						cout<<net_buf.c_str();
						cout<<endl<<"================================="<<endl;
						//cout<<"Comando non ancora implementato..."<<endl;
						break;
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

int check_seqno(uint32_t sr)
{
	if(sr != seqno) //gestire la chiusura della connessione per bene
	{
		cerr<<"Numeri di sequenza fuori fase!"<<endl;
		return -1;
	}
	else return 0;
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
	char *buf = new char[CHUNK];
//il flag WAITALL indica che la recv aspetta TUTTI i pacchetti. Senza ne riceve solo uno e quindi file oltre una certa dimensione risultano incompleti							
	
	cout<<"Ricezione di "<<filename<<" in corso..."<<endl;
	
	long long int mancanti = fsize;
	long long int ricevuti = 0;
	int count=0, progress = 0;

	fp.open(filename.c_str(), ios::out | ios::binary); //creo il file con il nome passato
	
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
		progress = (ricevuti*100)/fsize;
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
			remove(filename.c_str()); //elimino il file
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
		progress = (ricevuti*100)/fsize;
		cout<<"\r"<<progress<<"%";

		count++;
	}
	cout<<endl;
	cout<<"Ricevuto file in "<<count<<" pacchetti, per un totale di "<<ricevuti<<" bytes."<<endl;
	
	if(ricevuti != fsize)
	{
		cerr<<"Errore di trasferimento."<<endl;
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
	char *buf = new char[CHUNK];
	
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
	
	char *tmp_buf = new char[len];
	if(recv(sd, (void*)tmp_buf, len, MSG_WAITALL) == -1)
	{
		cerr<<"Errore in fase di ricezione buffer dati. Codice: "<<errno<<endl;
		exit(1);
	}
	net_buf = tmp_buf;
	net_buf.resize(len);
	seqno++;
	delete[] tmp_buf;
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

void send_data(string buf, int buf_len)
{
	//invio seqno
	send_seqno(sd);
			
	//len = strlen(buf)+48; //32 è la dim del MAC + 16 la dim di AES = 48
	//len = buf.length();
	lmsg = htons(buf_len);
	
	if(send(sd, (void*) &lmsg, sizeof(uint16_t), 0) == -1)
	{
		cerr<<"Errore di send(size)."<<endl;
		exit(1);
	}
	seqno++;
	
	send_seqno(sd);
        if(send(sd, (void*)buf.c_str(), buf_len, 0) == -1)
        {
        	cerr<<"Errore di send(buf)."<<endl;;
        	exit(1);
        }
        seqno++;        
        stato = -1;
}

void send_status(int stato)
{
	//invio seqno
	send_seqno(sd);
	
	if(send(sd, (void*)&stato, sizeof(stato), 0)== -1)
	{
		cerr<<"Errore di send_status():"<<endl;
		exit(1);
	}
	
	seqno++;
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
    	else
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
	exit(1);
}

bool check_command_injection(string buf)
{
	regex b("[A-Za-z0-9.-_]+");
	if(regex_match(buf, b))
		return true;
	else 
		return false;
}

bool check_file_existance(string buf) //return true se il file esiste
{
	DIR *d;
	struct dirent *dir;
	d = opendir(".");
	if(d)
	{
		while((dir = readdir(d)) != NULL)
			if(dir->d_type == 8)
				if(dir->d_name == buf) return true;
	closedir(d);
	}
	return false;
}

