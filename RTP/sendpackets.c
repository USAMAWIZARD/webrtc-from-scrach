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
#define SERVERADDRESS "127.0.0.1"

// Driver code
int main() {
  int sockfd;
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
  /*char *test =*/
  /*"\xb0\x61\x6b\x08\xe4\xfe\xa1\x80\x7c\x97\x38\xf3\xbe\xde\x00\x02"*/
  /*"\x41\x0e\x01\x22\x9e\x12\xd2\x00\x00\x75\x76\x4d\x0c\x25\x06\x4a"*/
  /*"\x74\xf2\xde\x96\x8d\xdc\x43\xaa\x69\x4f\xa3\x4a\x58\x83\x24\xbf"*/
  /*"\xf1\x98\x7a\xdc\x30\x23\xde\xda\xe7\xd0\x88\x58\xf9\x32\x45\x4f"*/
  /*"\x39\x20\xf6\x7f\x63\x4b\x50\x81\xf9\x65\xd2\x4e\x70\x4f\x42\xc6"*/
  /*"\xa7\x9f\x5c\x92\x9a\x0c\x03\x16\x73\x4e\xeb\xb0\xbd\xe2\xd2\xab"*/
  /*"\xd8\x51\x48\xb8\xb5\x1f\xed\x46\x9f\x2e\x3f\x06\x2a\x19\xb5\xb2"*/
  /*"\x55\x00\x28\x2f\x33\x40\xbd\xb6\x1e\x6d\xe9\x5f\x22\xda\xf4\x04"*/
  /*"\xca\x16\x1d\x0b\x8b\x62\x6c\x62\xb9\xff\x24\x4a\xa5\xc1\x4a\xef"*/
  /*"\xc3\xaa\xeb\x65\xad\xe7\x4b\x02\x69\xb3\x1b\x50\xc3\x6f\xe8\xdb"*/
  /*"\x19\x47\x27\x54\x23\x89\x44\x01\xdd\xdd\x5d\x0b\xb0\x96\x69\xf7"*/
  /*"\x1d\x02\x56\x88\x61\x9d\x89\x0e\x9f\x6d\x10\x69\x66\xf5\x21\xff"*/
  /*"\x47\xbf\xf1\x9a\x4e\x23\xa4\x28\x32\xf5\x34\x27\x20\x5e\x11\xca"*/
  /*"\x4f\xff\xab\xc2\xf9\x16\xb3\x61\x2b\xac\xd0\x8b\xc6\x30\x62\x3b"*/
  /*"\x65\x85\xb3\xb2\xaa\xc7\x14\x66\x31\x5f\xde\xfa\x82\xdc\x9b\x20"*/
  /*"\xc3\xa9\x2c\x92\x6c\xa9\xdd\x52\x96\x0a\x94\xb1\x0d\xd1\x9a\x42"*/
  /*"\xaf\x02";*/

  /*size_t len;*/
  /*for (size_t i = 0; i < 50; i++) {*/
  /*if (test[i] == 0x12) {*/
  /*len = i + +4;*/
  /*}*/
  /*}*/
  char *payload = "aaaaaaaaaaaaaaaa\xaf\x02\x01";
  /*char *frank = malloc((sizeof(char) * len) + strlen(payload) + 2);*/
  /*memcpy(frank, test, len);*/
  /*strcpy(frank + len, payload);*/
  struct Rtp *packet = create_rtp_packet(payload);
  char packet_str[sizeof(struct Rtp) + strlen(payload) + 1];
  memcpy(packet_str, packet, sizeof(packet_str) / sizeof(packet_str[0]));
  /*frank[(sizeof(char) * len) + strlen(payload) + 1] = 0x02;*/
  /*frank[(sizeof(char) * len) + strlen(payload)] = 0xaf;*/
  sendto(sockfd, packet_str, (sizeof(packet_str) / sizeof(packet_str[0])) - 1,
         MSG_CONFIRM, (const struct sockaddr *)&servaddr, sizeof(servaddr));

  /*sendto(sockfd, frank, len + strlen(payload) + 2, MSG_CONFIRM,*/
  /*(const struct sockaddr *)&servaddr, sizeof(servaddr));*/
  close(sockfd);
  return 0;
}
