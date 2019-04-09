#include <arpa/inet.h> 
#include <netinet/in.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <sys/types.h> 
#include <unistd.h> 
  
#define IP_PROTOCOL 0 
#define PORT_NO 15050 
#define NET_BUF_SIZE 1024 
#define cipherKey 'S' 
#define sendrecvflag 0 
#define nofile "File Not Found!" 

FILE *new_file;
char *filename;

void clearBuf(char* b) 
{ 
    int i; 
    for (i = 0; i < NET_BUF_SIZE; i++) 
        b[i] = '\0'; 
}

int recvFile(unsigned char* buf, int s) 
{ 
    int i, j; 
    char ch; 
    unsigned char uch;

    for (i = 0; i < s; i++) 
    { 
        ch = buf[i];
        fprintf(new_file, "%c", ch);
        if (ch == EOF)
        {
        	for(j=i+1; j<strlen(buf)+32; j++) {
        		uch = buf[j];
        		fprintf(new_file, "%c", (char)uch);
        		printf("%02x ", uch);
        	}
            return 1;
        } 
        else
            printf("%c", ch); 
    }
    return 0; 
} 

int main() 
{ 
    int sockfd, nBytes; 
    struct sockaddr_in addr_con; 
    int addrlen = sizeof(addr_con); 
    addr_con.sin_family = AF_INET; 
    addr_con.sin_port = htons(PORT_NO); 
    addr_con.sin_addr.s_addr = INADDR_ANY; 
    unsigned char net_buf[NET_BUF_SIZE]; 
    FILE* fp;
    
    sockfd = socket(AF_INET, SOCK_DGRAM, IP_PROTOCOL);
    
    if(sockfd <0)
    	printf("ERRORE: Descrittore socket non ricevuto.\n");
    else
    	printf("Descrittore socket ricevuto correttamente\n");
    
    if(bind(sockfd, (struct sockaddr*)&addr_con, sizeof(addr_con)) == 0)
    	printf("bind() eseguita correttamente.\n");
    else printf("ERRORE: bind() fallita.\n");
    
    while(1)
    {
    	printf("In attesa di file...\n");
    	
    	//pulizia buffer
    	clearBuf(net_buf);
    	
    	while(1)
    	{
	    	//ricevo nome file
	    	nBytes = recvfrom(sockfd, net_buf, NET_BUF_SIZE, sendrecvflag, (struct sockaddr*)&addr_con, &addrlen);
	    	
	    	filename = (char*)malloc(strlen(net_buf));
		strcpy(filename, net_buf);
		new_file = fopen(filename, "w");
	
		//pulizia buffer
		clearBuf(net_buf);

		nBytes = recvfrom(sockfd, net_buf, NET_BUF_SIZE, sendrecvflag, (struct sockaddr*)&addr_con, &addrlen); 
	
		// lettura buffer e salvataggio file
		if (recvFile(net_buf, NET_BUF_SIZE))
		{
			printf("File ricevuto correttamente.\n");
			fclose(new_file);
			//free((void*)filename); //pulizia e deallocamento memoria
			break;
		}
	} 
    }
    return 0;   	 
}
