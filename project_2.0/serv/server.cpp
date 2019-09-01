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

using namespace std;

# define CHUNK 512000
# define IP_ADDR "127.0.0.1"
# define PORT_NO 15050

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
unsigned int seqno; //numero di sequenza pacchetti
//============================================
void sock_connect(int port)
{
/* Creazione socket */
    sd = socket(AF_INET, SOCK_STREAM, 0);
    /* Creazione indirizzo di bind */

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
	code = 0;
}

void recvData(int sd)
{
	// Attendo dimensione del mesaggio                
	if(recv(sd, (void*)&lmsg, sizeof(uint16_t), 0) == -1)
	{
		cerr<<"Errore in fase di ricezione lunghezza. "<<endl;
		exit(1);
	}
	
	len = ntohs(lmsg); // Rinconverto in formato host

	//if(recv(sd, (void*)tmp_buf, len, 0) == -1)
	if(recv(sd, (void*)net_buf.c_str(), len, 0) == -1)
	{
		cerr<<"Errore in fase di ricezione buffer dati. "<<endl;
		exit(1);
	}
}

void recv_file(string filename)
{
	if(recv(new_sd, &lmsg, sizeof(uint64_t), MSG_WAITALL) == -1) {
		cerr<<"Errore in fase di ricezione lunghezza file. Codice: "<<errno<<endl; exit(1); }
      
	ctx_len = ntohl(lmsg); // Rinconverto in formato host
	cout<<"Lunghezza file (Bytes): "<<ctx_len<<endl;							
	char *buf = new char[ctx_len];
//il flag WAITALL indica che la recv aspetta TUTTI i pacchetti. Senza ne riceve solo uno e quindi file oltre una certa dimensione risultano incompleti							
	
	cout<<"Ricezione di "<<filename<<" in corso..."<<endl;
	
	long long int mancanti = ctx_len;
	long long int ricevuti = 0;
	int count=0;
	char *app_buf = buf; //app punta a buf[0]
	int progress = 0;
	
	while((mancanti-CHUNK) > 0)
	{
		int n = recv(new_sd, (void*)buf, CHUNK, MSG_WAITALL);
		if(n == -1)
		{
			cerr<<"Errore in fase di ricezione buffer dati. Codice: "<<errno<<endl;
			exit(1);
		}

		ricevuti += n;
		mancanti -= n;
		
		buf += CHUNK; //mi sposto di CHUNK posizioni in avanti nell'array (vedi aritmetica dei puntatori)
		
		//percentuale di progresso
		progress = (ricevuti*100)/ctx_len;
		cout<<"\r"<<progress<<"%";

		count++;
	}
	if(mancanti != 0)
	{
		int n = recv(new_sd, (void*)buf, (ctx_len-ricevuti), MSG_WAITALL);
		if(n == -1)
		{
			cerr<<"Errore in fase di ricezione buffer dati. Codice: "<<errno<<endl;
			exit(1);
		}
		ricevuti += n;
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
	
	cout<<"Salvataggio file in corso. Attendere..."<<endl;
	
	string path ="./files/";
	path.append(filename);

	fp.open(path.c_str(), ios::out | ios::binary); //creo il file con il nome passato
	
	if(!fp) { cerr<<"Errore apertura file."<<endl; }
	fp.write(app_buf, ctx_len); //scrivo tutto app_buf (lungo ctx_len) nel file
								
	cout<<"Salvataggio file completato in "<<path<<endl;
	fp.close();
	cout<<"File chiuso."<<endl;
	
	code=0; //metto il codice neutro per evitare eventuali problemi nello switch
}

void send_data(string buf, int sock) {
	len = buf.length();
	lmsg = htonl(len);
	
	if(send(sock, (void*) &lmsg, sizeof(uint32_t), 0) == -1)
	{
		cerr<<"Errore di send(size). Codice: "<<errno<<endl;
		exit(1);
	}
        
        if(send(sock, (void*)buf.c_str(), len, 0) == -1)
        {
        	cerr<<"Errore di send(buf). Codice: "<<errno<<endl;
        	exit(1);
        }
        
        code = 0;
}

bool search_file(int sock, string filename)
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

	string lista_file;
	
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
	send_data(lista_file, sock);
	cout<<"Lista inviata."<<endl;
}

void send_file(int sd)
{
	fp.seekg(0, fp.end); //scorro alla fine del file per calcolare la lunghezza (in Byte)
	long long int fsize = fp.tellg(); //fsize conta il num di "caratteri" e quindi il numero di byte --> occhio che se dim file > del tipo int ci sono problemi
	fp.seekg(0, fp.beg); //mi riposizione all'inizio
	
	cout<<"Lunghezza file(Byte): "<<fsize<<endl;
	char *buf = new char[fsize]; //buffer di appoggio per l'invio su socket
	fp.read(buf, fsize); //ora buf contiene il contenuto del file letto
	
	fp.close();
	
	lmsg = htonl(fsize); //invio lunghezza file
	cout<<"lmsg = htonl(fsize): "<<lmsg<<endl;//", sizeof(uint32_t): "<<sizeof(uint32_t)<<endl;
	if(send(sd, &lmsg, sizeof(uint64_t), 0) == -1)
	{
		cerr<<"Errore di send(size)."<<endl;
		exit(1);
	}
	
	cout<<"Invio del file: "<<net_buf<<" in corso..."<<endl;
	
	long long int mancanti = fsize;
	long long int inviati = 0;
	int count=0, progress=0;

	while((mancanti-CHUNK)>0)
	{
		int n = send(sd, (void*)buf, CHUNK, 0);
		if(n == -1)
		{
			cerr<<"Errore di send(buf)."<<endl;;
			exit(1);
		}
		count++;
		
		buf += CHUNK;
		mancanti -= n;
		inviati += n;
		
		progress = (inviati*100)/fsize;
		cout<<"\r"<<progress<<"%";	
	}
	if(mancanti!=0)
	{
		int n = send(sd, (void*)buf, mancanti, 0);
		if(n == -1)
		{
			cerr<<"Errore di send(buf)."<<endl;;
			exit(1);
		}
		count++;
		inviati += n;
		progress = (inviati*100)/fsize;
		cout<<"\r"<<progress<<"%";	
	}
	cout<<endl;
	cout<<"Inviato file in "<<count<<" pacchetti."<<endl;
}	

int main()
{
	
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

			if(FD_ISSET(i, &master)) {
            			if(i != sd)
            			{
            				//ricevo comando dal client
            				if(recv(i, &code, sizeof(code), 0) == -1) //sostituito new_sd con i
					{
					    cerr<<"Errore in fase di ricezione comando: "<<endl;
					    exit(1);
		        		}
		        		
					//cout<<"Ricevuto comando "<<code<<" dal client "<<i<<"."<<endl;
					
					switch(code)
					{
						//case 0:
						//	break;
						case 1: //============ricezione file============
						{
							cout<<"In attesa di file..."<<endl;
							
							recvData(new_sd);
							
							cout<<"Ricevuto il nome_file: "<<net_buf.c_str()<<endl;
							
							recv_file(net_buf.c_str());
													
							break;
						}
						case 2: //========download file=============
						{	recvData(new_sd);
							
							string filename = net_buf.c_str();
							cout<<"Il client "<<new_sd<<" ha richiesto di scaricare il file: "<<filename<<endl;
							
							//1) controllo se il file esite
							bool found = search_file(i, filename);
							
							//2) mando l'esito al client
							if(send(i, (void*)&found, sizeof(found), 0)== -1)
							{
								cerr<<"Errore di send() relativa all'esistenza del file. Codice:"<<errno<<endl;
								exit(1);
							}
							
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
							exit(1);
						case 6: //===== !remove =======
						{
							recvData(new_sd);
							
							string filename = net_buf.c_str();
							cout<<"Il client "<<new_sd<<" ha richiesto di eliminare il file: "<<filename<<endl;
							
							//1) controllo se il file esite
							bool found = search_file(i, filename);
							
							//2) mando l'esito al client
							if(send(i, (void*)&found, sizeof(found), 0)== -1)
							{
								cerr<<"Errore di send() relativa all'esistenza del file. Codice:"<<errno<<endl;
								exit(1);
							}
							
							//3) se non esiste mi fermo qua
							if(!found) { cout<<"File inesistente."<<endl; break; }
							
							//4) attendo conferma
							bool confirm;
							if(recv(i, &confirm, sizeof(confirm), 0) == -1) //sostituito new_sd con i
							{
							    cerr<<"Errore in fase di recv() relativa alla conferma eliminazione file. Codice: "<<errno<<endl;
							    exit(1);
							}
							
							if(!confirm) { cout<<"Operazione annullata."<<endl; break; }
							else
							{
								string path = "./files/";
								path.append(filename);

								if(remove(path.c_str()) == 0)
									cout<<"File eliminato con successo."<<endl;
								else cout<<"Errore eliminazione file. Codice: "<<errno<<endl;
							}
							
							break;
						}
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
