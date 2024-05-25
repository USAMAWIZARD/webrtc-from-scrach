#include <arpa/inet.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "network.h"

struct sockaddr_in * get_network_socket(char *ip , int port){
  
  struct sockaddr_in *socket_address; 
  socket_address = malloc(sizeof(struct sockaddr_in)); 
  socket_address->sin_family = AF_INET; //ipv4 by defalult
  socket_address->sin_port = htons(port);
  socket_address->sin_addr.s_addr =  inet_addr(ip);
  printf("allocating ip %s port %d for RTP \n",ip , port);
  return socket_address;
}

int get_udp_sock_desc(){
  int socket_desc = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if(socket_desc < 0){
     printf("Error while creating socket\n");
     return -1;
  }
  return socket_desc;   
}
