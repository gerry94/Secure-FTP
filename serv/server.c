#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/select.h>
#include <openssl/hmac.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h> 
#include <dirent.h>

# define NET_BUF_SIZE 1024
# define IP_ADDR "127.0.0.1"
# define PORT_NO 15050

int porta;
int num_clients; //tengo traccia della lunghezza della lista
	
int ret, sd, new_sd, len, code, ctx_len; 
uint16_t lmsg;
pid_t pid;
struct sockaddr_in my_addr, cl_addr;
unsigned char net_buf[NET_BUF_SIZE];

unsigned char key_hmac[]="0123456789012345678901234567891";
size_t key_hmac_size = sizeof(key_hmac);
unsigned char *key = (unsigned char *)"0123456789012345"; //128bit key
unsigned char *decryptedtext, *hash_buf;

int decryptedtext_len, hash_size;
char *filename;
struct client* lista_client; 

fd_set master, read_fds;
int fdmax;

FILE *new_file;
//========================================
void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
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
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int length, plaintext_len;

  /* Create and initialise the context */
  ctx = EVP_CIPHER_CTX_new();

  // Decrypt Init
  EVP_DecryptInit(ctx, EVP_aes_128_ecb(), key, iv);

  // Decrypt Update: one call is enough because our mesage is very short.
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &length, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = length;

  // Decryption Finalize
  if(1 != EVP_DecryptFinal(ctx, plaintext + length, &length)) handleErrors();
  plaintext_len += length;

  // Clean the context!
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

void mdealloc(void** p)
{
	if(*p != NULL)
	{
		free(*p);
		*p = NULL;
	}
}

void sock_connect(int port)
{
/* Creazione socket */
    sd = socket(AF_INET, SOCK_STREAM, 0);
    /* Creazione indirizzo di bind */
    memset(&my_addr, 0, sizeof(my_addr)); // Pulizia 
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(port);
    my_addr.sin_addr.s_addr = INADDR_ANY;
    
    ret = bind(sd, (struct sockaddr*)&my_addr, sizeof(my_addr) );
    ret = listen(sd, 10);
    
    if(ret < 0){
        perror("Errore in fase di bind: \n");
        exit(-1);
    }
}

void quit(int i)
{
	close(i);
	FD_CLR(i, &master);
	printf("Socket %d chiuso.\n", i);
	code = 0;
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

int recvFile(unsigned char* buf) 
{
	decryptedtext = (unsigned char*)malloc(ctx_len);
	// Decrypt the ciphertext
	decryptedtext_len = decrypt(buf, ctx_len, key, NULL, decryptedtext);

  	// Show the decrypted text 
	/*printf("\nDecrypted text is:\n\n");
	int i;
	for(i=0; i<decryptedtext_len; i++)
		printf("%c", decryptedtext[i]);*/

    int i, j; 
    unsigned char uch, *plaintext;
    plaintext = (unsigned char*)malloc(decryptedtext_len);
    
    for (i = 0; i < decryptedtext_len; i++) 
    {
    	plaintext[i] = decryptedtext[i];
        fprintf(new_file, "%c", plaintext[i]);
        
        if (plaintext[i] == (unsigned char)EOF)
        {
        	plaintext[i]='\0';
        	hash((char*)plaintext); //devo fare hash(msg ricevuto) e confrontarlo con il MAC ricevuto
        	
        	unsigned char *mac_buf; //creo un buffer ad-hoc per il MAC ricevuto
        	mac_buf = (unsigned char*)malloc(hash_size);

        	for(j=0; j<hash_size; j++) 
        		mac_buf[j] = decryptedtext[j+i+1]; //salvo il MAC ricevuto    		
			
		int ret = CRYPTO_memcmp(hash_buf, mac_buf, hash_size); //confronto i due MAC per verificare l'autenticità
		if (ret!=0) printf("\nDigest check failed!\n");
		else printf("\nDigest check passed!\n");
            return 1;
        } 
    }
    printf("\n\n");
    return 0; 
}

void send_data(char* buf){
	len = strlen(buf);
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
        
        code = 0;
}

bool check_txt(char const *name)
{
	size_t len = strlen(name);
	return len > 4 && strcmp(name + len - 4, ".txt") == 0;
}

void list(int sock)
{
	DIR *d;
	struct dirent *dir;
	int length = 0;
	int i;

	d = opendir(".");
	if(d)
	{

		while((dir = readdir(d)) != NULL)
		{
			if(check_txt(dir->d_name))
				length += (strlen(dir->d_name)+1);
			//if((strcmp(dir->d_name,"..") != 0) && (strcmp(dir->d_name,".") != 0))

		}

		length += 1;
		
		closedir(d);
	}
	
	d = opendir(".");
	
	if(d)
	{
		char app[length];
		memset(&app, 0, sizeof(app));
		//app = (char*)malloc(length);
		int k=0;
		while(((dir = readdir(d)) != NULL))
		{
			if(check_txt(dir->d_name)){
			//if((strcmp(dir->d_name,"..") != 0) && (strcmp(dir->d_name,".") != 0)){
				//printf("%s\n",dir->d_name);
				//strncat(net_buf, dir->d_name, strlen(dir->d_name));
				strcat(app,dir->d_name);
				strcat(app,"\n");
				
			}
		}
		//printf("%s", app);
		
		memset(&net_buf, 0, sizeof(net_buf));
		
		strncpy(net_buf, app, length);
		printf("%s", net_buf);
		//send_data(net_buf);

		closedir(d);
	}
} 

int main()
{
	
	FD_ZERO(&master);
	FD_ZERO(&read_fds);
	
	sock_connect(PORT_NO);
    	
    	FD_SET(sd, &master);
    	fdmax = sd;
printf("Server avviato.\n"); fflush(stdout);
while(1){

    	read_fds = master;
    	if(select(fdmax +1, &read_fds, NULL, NULL, NULL) == -1)
    	{
    		perror("SERVER: select() error.");
    		close(sd);
    	}
    	int i;
    	for(i = 0; i<=fdmax; i++)
    	{
    		if(FD_ISSET(i, &read_fds))
    		{
    			if(i == sd)
    			{
    				len = sizeof(cl_addr);
    				// Accetto nuove connessioni
    				new_sd = accept(sd, (struct sockaddr*) &cl_addr, &len);
    				
				    if(new_sd == -1)
				    {
					    perror("SERVER: accept() error.\n");
					    close(sd);
				    }
				    else
				    {
				    	FD_SET(new_sd, &master);
				    	
					//salvare new_sd come id del client
					
					if(new_sd > fdmax)
					    fdmax = new_sd;
					    
				        printf("SERVER: accettata nuova connessione con il client da %s sul socket %d.\n", inet_ntoa(cl_addr.sin_addr), new_sd);
				        fflush(stdout);
				    }
    			}
    			else
    			{

			if(FD_ISSET(i, &master)) {
            			if(i != sd) {
            				
				    	memset(net_buf, 0, sizeof(net_buf)); //pulizia
				
					if(recv(i, &code, sizeof(code), 0) == -1) //ho sostituito new_sd con i
					{
					    perror("Errore in fase di ricezione comando: \n");
					    exit(1);
		        		}
		        		
					//printf("Ricevuto comando %d dal client %d", code, i); printf("\n");
					//fflush(stdout);
				
				switch(code) 
				{
					case 0: //codice neutro
						break;               
					case 1:
						printf("In attesa di file...\n");
						
						recvData(new_sd); //ricevo nome file
						filename = (char*)malloc(strlen(net_buf));
						strcpy(filename, net_buf);
						
						//ricevo lunghezza ctx
						if(recv(new_sd, (void*)&lmsg, sizeof(uint16_t), 0) == -1) {
							perror("Errore in fase di ricezione lunghezza. \n"); exit(1); }
							      
						ctx_len = ntohs(lmsg); // Rinconverto in formato host
						
						memset(&net_buf, 0, sizeof(net_buf));
						recvData(new_sd); //ricevo il contenuto del file
						
						new_file = fopen(filename, "w"); //creo il file con il nome passato
					
						if (recvFile(net_buf)) //scrivo il contenuto NEL file
						{
							printf("\nFile ricevuto correttamente.\n");
							fclose(new_file);
						} else { printf("errore ricezione file\n"); }						
						
						break;
					case 2:
						//who(i);
						break;
					case 3:
						quit(i);
						break;
					case 4:
						memset(&net_buf, 0, sizeof(net_buf));
						list(i);
						break;
					case 5:
						exit(1);
					default:
						printf("SERVER: comando non riconosciuto.\n");
						break;
				}
                	}                               
            	}
	}
	}
} //graffa del for
} //while(1)
} //main
