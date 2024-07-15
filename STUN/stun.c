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
#include "../ICE/ice.h"
#include "../Network/network.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#define STUN_IP "74.125.250.129"
#define STUN_PORT 19302

#pragma pack(1)

struct stun_binding *
stun_bind_request( struct RTCIecCandidates *local_candidate,
                  struct RTCIecCandidates *remote_candidate, char *stun_ip,
                  int stun_port) {
  // bind request contains only header
  char *stun_server_ip = stun_ip == NULL ? STUN_IP : stun_ip;
  int stun_server_port = stun_port <= 0 ? STUN_PORT : stun_port;

  struct Stun stun_request;
  stun_request.zerobits = 0;
  stun_request.msg_type = 1;
  stun_request.msg_type = stun_request.msg_type << 6;
  stun_request.msg_len = 0;

  stun_request.magic_cookie = htonl(0x2112A442);
  socklen_t socklen = sizeof(struct sockaddr_in);
  char *transaction_id = "123456789012\0";
  strncpy(stun_request.transaction_id, transaction_id, 12);

  int sock_desc = get_udp_sock_desc();

  struct sockaddr_in *dest_addr =
      get_network_socket(stun_server_ip, stun_server_port);
  struct sockaddr_in *srcaddr = get_network_socket(NULL, 5020);

  if (bind(sock_desc, (struct sockaddr *)srcaddr, sizeof(*srcaddr)) < 0) {
    perror("binding ip for stun failed");
  }
  int bytes;

  bytes = sendto(sock_desc, &stun_request, sizeof(stun_request), 0,
                 (struct sockaddr *)dest_addr, sizeof(struct sockaddr_in));

  
  // close(sock_desc);
  char *local_ip = local_candidate == NULL ? NULL : local_candidate->address;
  printf("stun packet sent server stun://%s:%d with local IP: %s \n",
         stun_server_ip, stun_server_port, local_ip);

  char *udp_packet = malloc(1000);

  bytes = recvfrom(sock_desc, udp_packet, 1000, 0, (struct sockaddr *)dest_addr,
                   &socklen);

  struct Stun *stun_respose = malloc(bytes);
  memcpy(stun_respose, udp_packet, bytes);

  printf("%d bytes cookie %x  zero  %d  %d  %s len %u", bytes,
         ntohs(stun_respose->magic_cookie), stun_respose->zerobits,
         ntohs(stun_respose->msg_len), stun_respose->transaction_id,
         stun_respose->msg_len);

  struct StunPayload *stun_respose_payload = malloc(sizeof(struct StunPayload));
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
  stun_binding->local_ip = local_ip;

  if (bytes == -1)
    printf("error something went wrong when reciving stun response %d", errno);
  else
    printf("\n-----public NAT Mapping is  : PORT %d  IP , %s-----\n",
           mapped_port, stun_binding->bound_ip);
  return stun_binding;
}

char *get_stun_attributes(struct RTCIecCandidates *local_candidate,
                          struct RTCIecCandidates *remote_candidate) {

  // struct stun_attribute *username= mall;
  // username->type = 0x0006;
  // username->length = htons(10);
  // strcpy(username.value,"usama:usam1");
  //
}
