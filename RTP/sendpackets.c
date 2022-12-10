#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "rtp.c"

#define PORT 8080
#define SERVERADDRESS "192.168.0.105"

// Driver code
int main()
{
  int sockfd;
  struct sockaddr_in servaddr;
  // Creating socket file descriptor
  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
  {
    perror("socket creation failed");
    exit(EXIT_FAILURE);
  }

  memset(&servaddr, 0, sizeof(servaddr));

  // Filling server information
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(PORT);
  inet_pton(AF_INET, SERVERADDRESS, &(servaddr.sin_addr));

  struct Rtp *packet = create_rtp_packet("abcdefghijklmnopqrstuvwxyz");
  
  //  printf("%s",*packet->payload);
  convert_rtp_pkt_to_string(packet);
  sendto(sockfd, packet, sizeof(struct Rtp) - sizeof(char) + strlen(packet->payload), MSG_CONFIRM,
         (const struct sockaddr *)&servaddr, sizeof(servaddr));

  close(sockfd);
  return 0;
}
