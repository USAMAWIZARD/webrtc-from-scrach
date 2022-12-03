#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

// Client side implementation of UDP client-server model 
#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 
#include "rtp.c"
#define PORT     8080 
#define SERVERADDRESS "192.168.0.105" // 138.131.156.36"

// Driver code 
int main() { 
    int sockfd; 
    char *hello = "Hello from client"; 
    struct sockaddr_in   servaddr ; 
    
    // Creating socket file descriptor 
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
        perror("socket creation failed"); 
        exit(EXIT_FAILURE); 
    } 
    
    memset(&servaddr, 0, sizeof(servaddr)); 
        
    // Filling server information 
    servaddr.sin_family = AF_INET; 
    servaddr.sin_port = htons(PORT); 
    servaddr.sin_addr.s_addr = SERVERADDRESS; 
        
    int n, len; 
    struct Rtp *packet =create_rtp_packet();
    char packet_str[sizeof(struct Rtp)]; 
    memcpy(packet_str, &packet, sizeof(struct Rtp)); 
    printf("%s %ld\n",packet_str,sizeof(struct Rtp));
    sendto(sockfd,packet_str, strlen(hello), 
        MSG_CONFIRM, (const struct sockaddr *) &servaddr,  
            sizeof(servaddr)); 


    close(sockfd); 
    return 0; 
}