#include <arpa/inet.h> 
#include <netinet/in.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <sys/types.h> 
#include <unistd.h>
#include <openssl/hmac.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h> 
#include <stdbool.h>

# define NET_BUF_SIZE 1024
# define IP_ADDR "127.0.0.1"
# define PORT_NO 15050
bool udp_sock_created = false;

bool registered = false;
int stato = 0;
//0: help, 1= register, 2=who, -1=quit

int response; //-1: errore, 

int porta;
int ret, sd, len, lmsg;
struct sockaddr_in srv_addr;
	
char cmd[50];
char *username;
char *dest_username;
unsigned char net_buf[NET_BUF_SIZE];
FILE *fp;
char *tmp_buffer;

fd_set master, read_fds;
int fdmax;

//strutture UDP per la chat fra clients
int udp_socket;
uint32_t udp_port;
struct sockaddr_in address;

unsigned char *message, *ciphertext;
unsigned char key_hmac[]="0123456789012345678901234567891";
unsigned char *key = (unsigned char *)"0123456789012345"; //128bit key
unsigned char* hash_buf; //net_buf containing digest
int hash_size, ciphertext_len; //size of the digest and ctx
size_t key_hmac_size = sizeof(key_hmac);
int mess_size;


//======================================================
void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;
  int ciphertext_len;

  /* Create and initialise the context */
  ctx = EVP_CIPHER_CTX_new();

  // Encrypt init
  EVP_EncryptInit(ctx, EVP_aes_128_ecb(), key, iv);

  // Encrypt Update: one call is enough because our mesage is very short.
  EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
  ciphertext_len = len;

  //Encrypt Final. Finalize the encryption and adds the padding
  EVP_EncryptFinal(ctx, ciphertext + len, &len);
  ciphertext_len += len;

  // MUST ALWAYS BE CALLED!!!!!!!!!!
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

void hash(char *msg)
{
	//declaring the hash function we want to use
	const EVP_MD* md = EVP_sha256();
	
	hash_size = EVP_MD_size(md);

	//create a net_buf for our digest
	hash_buf = (unsigned char*)malloc(hash_size);
		
	//create message digest context
	HMAC_CTX* mdctx;
	mdctx = HMAC_CTX_new();
	
	//Init,Update,Finalise digest
	HMAC_Init_ex(mdctx, key_hmac, key_hmac_size, md, NULL);
	HMAC_Update(mdctx, (unsigned char*) msg, sizeof(msg));
	HMAC_Final(mdctx, hash_buf, (unsigned int*) &hash_size);
	
	//Delete context
	HMAC_CTX_free(mdctx);
	
	mess_size = strlen(net_buf)+hash_size+1;
	
	message = (unsigned char*)malloc(mess_size);
	
	
	int i, j,k=0;
	
	
	for(i=0; i<strlen(net_buf); i++)
	{
		message[i] = net_buf[i];
		//printf("%c", message[i]); 
	}	
	for(j=i; j<mess_size; j++)
	{
		message[j] = hash_buf[k];
		//printf("%d) ", strlen(message));
		//printf("%02x ", message[j]);
		k = k+1;
	}
	//printf("\n");
	ciphertext = (unsigned char*)malloc(mess_size+16); 
	ciphertext_len = encrypt (message, mess_size, key, NULL, ciphertext);
	// Redirect our ciphertext to the terminal
	  //printf("Ciphertext is:\n");
	  //BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
	  
	//a questo punto message contiene il testo da spedire: E(msg, H(msg))
}

void mdealloc(void** p)
{
	if(*p != NULL)
	{
		free(*p);
		*p = NULL;
	}
}

void send_status(int stato)
{
	if(send(sd, (void*)&stato, sizeof(stato), 0)== -1)
	{
		perror("Errore di send()\n");
		exit(1);
	}
}

void printMsg()
{
	printf("Sono disponibili i seguenti comandi: \n"
		"!help --> mostra l'elenco dei comandi disponibili \n"
		"!upload --> carica un file presso il server\n"
		"!get --> scarica un file dal server\n"
		"!quit --> disconnette il client dal server ed esce\n"
		"!list --> visualizza elenco file disponibili sul server\n"
		"!superquit --> termina client e server\n");
	fflush(stdout);
}

void quit(int i)
{	
	printf("Client disconnesso.\n");
			
	FD_CLR(i, &master);
	close(sd);
	exit(1);
}

void send_port()
{
	if(send(sd, (void*) &porta, sizeof(porta), 0) == -1)
		printf("Errore di send()\n");
}

void create_udp_socket()
{
	int yes = 1;
	
	if((udp_socket = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
		perror("errore creazione socket UDP.\n");
		exit(1);
	}
	
	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
    	address.sin_port = htons(udp_port);
    	address.sin_addr.s_addr = htonl(INADDR_ANY);
    	
    	if(setsockopt(udp_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1)
    	{
    		perror("Errore di setsockopt.\n");
    		exit(1);
    	}
    	
    	if(bind(udp_socket, (struct sockaddr*)&address, sizeof(address)) == -1)
    	{
    		perror("errore in fase di bind() udp.\n");
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
    	memset(&srv_addr, 0, sizeof(srv_addr)); // Pulizia 
    	srv_addr.sin_family = AF_INET;
    	srv_addr.sin_port = htons(porta_server);
    	inet_pton(AF_INET, address, &srv_addr.sin_addr);
    	
    	if(connect(sd, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0)
   	{
        	perror("Errore in fase di connessione: \n");
        	exit(-1);
    	}
    	else
    	{
    		printf("Connessione al server %s (porta %d) effettuata con successo.\n", address, porta_server);
    		printf("Ricezione messaggi istantanei su porta %d\n\n", porta);
    	}
}

void send_data(char* buf)
{		
	len = strlen(buf)+48; //32 è la dim del MAC + 16 la dim di AES = 48
	lmsg = htons(len);
	
	if(send(sd, (void*) &lmsg, sizeof(uint16_t), 0) == -1)
	{
		printf("Errore di send(size)\n");
		exit(1);
	}
        
        if(send(sd, (void*) buf, len, 0) == -1)
        {
        	printf("Errore di send(buf)\n");
        	exit(1);
        }
        
        stato = -1;
}

void recvData(int sd)
{
	// Attendo dimensione del mesaggio                
	if(recv(sd, (void*)&lmsg, sizeof(uint16_t), 0) == -1)
	{
		perror("Errore in fase di ricezione lunghezza. \n");
		exit(1);
	}
		       
	len = ntohs(lmsg); // Rinconverto in formato host

	if(recv(sd, (void*)net_buf, len, 0) == -1)
	{
		perror("Errore in fase di ricezione buffer dati. \n");
		exit(1);
	}
}

int sendFile(FILE* fp, char* net_buf, int s) 
{ 
    int i, len; 
    char ch;
    for (i = 0; i < s; i++) 
    { 
        ch = fgetc(fp);  //leggo un car dal file
        net_buf[i] = ch; //copio nel net_buf
         
        if (ch == EOF)  //se ho finito il file...
        {
		hash(net_buf);
            	return 1;
        } 
    }  
	/*
	char buf[1024];
	
	if(fgets(buf, s, fp) == NULL){
		printf("Errore in lettura file\n");
		return -1;
	}

	for (i = 0; i < s; i++) 
    	{ 
        	printf("%c", buf[i]);
    	} 
	
	//char* p = strchr(buf,'\n');
	//if(p) {*p = '\0'; }
	buf[1024] = '\0';
	
	for (i = 0; i < s; i++) 
    	{ 
        	net_buf[i] = buf[i]; //copio nel net_buf
         
        	if (buf[i] == EOF)  //se ho finito il file...
        	{
			hash(net_buf);
            		return 1;
        	} 
    	} */
}

void list(int sd)
{
	
	recvData(sd);
	printf("File disponibili: \n");
	printf("%s\n", net_buf);

}

int main(int argc, char** argv)
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
    	
    	int i;
    	for(i = 0; i<=fdmax; i++)
    	{	
    		if(FD_ISSET(i, &read_fds))
    		{	
    			if(i == 0)
    			{	
				scanf("%s", net_buf);
				getchar(); // rimuove eventuale spazio o \n 
	
				if(strcmp(net_buf, "!help")==0) 
					stato=0;
				else if(strcmp(net_buf, "!upload")==0) 
					stato = 1;
				else if(strcmp(net_buf, "!get")==0)
					stato = 2;
				else if(strcmp(net_buf, "!quit")==0)
					stato = 3;
				else if(strcmp(net_buf, "!list")==0)
					stato = 4;
				else if(strcmp(net_buf, "!superquit")==0)
					stato = 5;
				else stato = -1; //stato neutro					
				
				switch(stato) 
				{
					case 0:
						send_status(stato);
						printMsg();
						break;	
					case 1:
						
						
						printf("Inserire il nome del file da inviare:\n"); 
						scanf("%s", net_buf);				
						fp = fopen(net_buf, "r");
				    	
				    		if(fp == NULL) {
				    			printf("ERRORE: apertura file non riuscita.\n"); break; }
				    		else { printf("Apertura file eseguita correttamente.\n");

				    		send_status(stato);
						send_data(net_buf); //invio nome file
						
						if (sendFile(fp, net_buf, NET_BUF_SIZE)) 
				  		{
				  			memset(&net_buf, 0, sizeof(net_buf));
				  			
				  			int i;
				  			for(i=0; i<ciphertext_len; i++) 
				  			{
				  				net_buf[i] = ciphertext[i];
				  				//printf("%c", net_buf[i]); 
				  			}
				  			
				  			//invio lunghezza ctx
							lmsg = htons(ciphertext_len);
							
							if(send(sd, (void*) &lmsg, sizeof(uint16_t), 0) == -1)
							{
								printf("Errore di send(size)\n");
								exit(1);
							}
							send_data(net_buf);
							printf("\nFile inviato.\n");
							//pulizia net_buf
					    		memset(&net_buf, 0, sizeof(net_buf)); 
					    	} }
					    	if(fp != NULL) 
					    	{
					    		fclose(fp);
					    		printf("File chiuso.\n");
					    	}	
						break;
					case 2:
						send_status(stato);
						printf("Comando non ancora implementato...\n");
						break;
					case 3:
						send_status(stato);
						quit(i);
						break;
					case 4:
						send_status(stato);
						memset(&net_buf, 0, sizeof(net_buf));
						list(sd);
						//printf("Comando non ancora implementato...\n");
						break;
					case 5:
						send_status(stato);
						quit(i);
						break;
					default:
						printf("Comando non riconosciuto.\n");
						break;
				} //switch
			} //if
		}//if
		} //for
	} //while
}//main
