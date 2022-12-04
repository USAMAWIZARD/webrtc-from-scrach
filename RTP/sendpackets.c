#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

// Client side implementation of UDP client-server model
#include "rtp.c"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#define PORT 8080
/*#define SERVERADDRESS "192.168.0.105" // 138.131.156.36"*/
#define SERVERADDRESS "127.0.0.1"

// Driver code
int main() {
  int sockfd;
  char *hello = "Hello from client";
  struct sockaddr_in servaddr;

  // Creating socket file descriptor
  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket creation failed");
    exit(EXIT_FAILURE);
  }

  memset(&servaddr, 0, sizeof(servaddr));

  // Filling server information
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(PORT);
  inet_pton(AF_INET, SERVERADDRESS, &(servaddr.sin_addr));
  int n, len;
  struct Rtp *packet = create_rtp_packet();
  char *payload = "hello";
  AddPayLoad(packet,payload);
  for (int i = 0; i< strlen(payload);i++){
    printf("%c",(packet->payload)[i]);
  }


  sendto(sockfd, packet, sizeof(struct Rtp) - sizeof (char) + strlen(payload)  , MSG_CONFIRM,
         (const struct sockaddr *)&servaddr, sizeof(servaddr));

  close(sockfd);
  return 0;
}
