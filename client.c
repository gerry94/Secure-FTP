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
  
#define IP_PROTOCOL 0 
#define IP_ADDRESS "127.0.0.1" // localhost 
#define PORT_NO 15050 
#define NET_BUF_SIZE 1024  
#define sendrecvflag 0 

unsigned char net_buf[NET_BUF_SIZE]; 
FILE *new_file;
char *filename, *msg;
unsigned char *message;

unsigned char key_hmac[]="0123456789012345678901234567891";
unsigned char* hash_buf; //buffer containing digest
int hash_size; //size of the digest
size_t key_hmac_size = sizeof(key_hmac);
int mess_size;

void hash(char *msg)
{
	//declaring the hash function we want to use
	const EVP_MD* md = EVP_sha256();
	
	hash_size = EVP_MD_size(md);

	//create a buffer for our digest
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
	printf("\n");
	//a questo punto message contiene il testo da spedire: (msg, H(msg))
}
void clearBuf(char* b) 
{ 
    int i; 
    for (i = 0; i < NET_BUF_SIZE; i++) 
        b[i] = '\0'; 
}

// funtion sending file 
int sendFile(FILE* fp, char* net_buf, int s) 
{ 
    int i, len; 
    char ch;
    for (i = 0; i < s; i++) 
    { 
        ch = fgetc(fp);  //leggo un car dal file
        net_buf[i] = ch; //copio nel buffer
         
        if (ch == EOF)  //se ho finito il file...
        {
		hash(net_buf);
            	return 1;
        } 
    }  
}

int main()
{
	int sockfd, nBytes; 
	struct sockaddr_in addr_con; 
	int addrlen = sizeof(addr_con); 
	addr_con.sin_family = AF_INET; 
	addr_con.sin_port = htons(PORT_NO); 
	addr_con.sin_addr.s_addr = inet_addr(IP_ADDRESS); 
	
	FILE* fp; 

	// socket() 
	sockfd = socket(AF_INET, SOCK_DGRAM, 
		    IP_PROTOCOL); 

	while(1) //ciclo principale
	{ 
	while(1) //ciclo per la lettura
	{
		printf("Inserire il nome del file da inviare:\n"); 
		scanf("%s", net_buf);
		
	
		fp = fopen(net_buf, "r");
    	
    		if(fp == NULL)
    			printf("ERRORE: apertura file non riuscita.\n");
    		else { printf("Apertura file eseguita correttamente.\n"); break; }
    	}
    	
    	//invio il nome file
	sendto(sockfd, net_buf, NET_BUF_SIZE, sendrecvflag, (struct sockaddr*)&addr_con, addrlen);
    	
    	while(1) //ciclo per l'invio del file
  	{
  		if (sendFile(fp, net_buf, NET_BUF_SIZE)) 
  		{
  			clearBuf(net_buf);
  			//strncpy(net_buf, message, mess_size);
  			int i;
  			for(i=0; i<mess_size; i++) {
  			net_buf[i] = message[i];
  			printf("%c", net_buf[i]); }
                	sendto(sockfd, net_buf, NET_BUF_SIZE, sendrecvflag, (struct sockaddr*)&addr_con, addrlen); 
                	break; 
            	} 
        	// process 
		sendto(sockfd, net_buf, NET_BUF_SIZE, sendrecvflag, (struct sockaddr*)&addr_con, addrlen);
		
		printf("File inviato.\n");
		//pulizia buffer
    		clearBuf(net_buf);
    	}
    	
    	if(fp != NULL) 
    	{
    		fclose(fp);
    		printf("File chiuso.\n");
    	}
    }
free((void*)message);
free((void*)net_buf);	
return 0;
}
