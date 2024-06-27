/*
0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0 0|     STUN Message Type     |         Message Length        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Magic Cookie                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                     Transaction ID (96 bits)                  |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             Data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#include "./stun.h"
#include "../Network/network.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

struct stun_binding *stun_bind_request(char *src_ip) {
  // bind request contains only header
  struct Stun stun_request;
  stun_request.zerobits = 0;
  stun_request.msg_type = 1;
  stun_request.msg_type = stun_request.msg_type << 6;
  stun_request.msg_len = 0;

  stun_request.magic_cookie = htonl(0x2112A442);
  char *stun_server_ip = "74.125.250.129";
  socklen_t socklen = sizeof(struct sockaddr_in);
  char *transaction_id = "123456789012\0";
  strncpy(stun_request.transaction_id, transaction_id, 12);

  int sock_desc = get_udp_sock_desc();
  struct sockaddr_in *dest_addr = get_network_socket(stun_server_ip, 19302);
  // struct sockaddr_in *srcaddr = get_network_socket(NULL,5020);
  //
  // if (bind(sock_desc, (struct sockaddr *)srcaddr, sizeof(*srcaddr)) < 0) {
  //   perror("bindig ip for stun failed");
  //   exit(1);
  // }
  int bytes;
  for (int i = 0; i <= 4; i++)
    bytes = sendto(sock_desc, &stun_request, sizeof(stun_request), 0,
                   (struct sockaddr *)dest_addr, sizeof(struct sockaddr_in));

  printf("stun packet sent server :%s with local IP: %s \n", stun_server_ip,
         src_ip);
  char *udp_packet = malloc(1000);
  bytes = recvfrom(sock_desc, udp_packet, 1000, 0, (struct sockaddr *)dest_addr,
                   &socklen);

  struct Stun *stun_respose = malloc(bytes);
  memcpy(stun_respose, udp_packet, bytes);

  struct StunPayload *stun_respose_payload = malloc(12);
  stun_respose_payload = (struct StunPayload *)stun_respose->data;
  uint16_t mapped_port =
      (ntohs(stun_respose_payload->x_port) ^
       ((uint16_t)(ntohs(
           stun_respose->magic_cookie)))); // port and ip is sotred xored with
                                           // the cookie
  uint32_t mapped_ip =
      (stun_respose_payload->x_ip ^ ((stun_respose->magic_cookie)));
  struct in_addr ip_add;
  ip_add.s_addr = mapped_ip;

  struct stun_binding *stun_binding = malloc(sizeof(struct stun_binding));
  stun_binding->bound_ip = inet_ntoa(ip_add);
  stun_binding->bound_port = mapped_port;
  stun_binding->local_ip = src_ip;

  if (bytes == -1)
    printf("error something went wrong when reciving stun response %d", errno);
  else
    printf("\npublic NAT Mapping is  : PORT %d  IP , %s\n", mapped_port,
           stun_binding->bound_ip);
  return stun_binding;
}
