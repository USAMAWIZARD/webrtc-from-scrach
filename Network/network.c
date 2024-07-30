#include "network.h"
#include "../STUN/stun.h"
#include "glib.h"
#include <arpa/inet.h>
#include <bits/pthreadtypes.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#pragma pack(1)
struct sockaddr_in *get_network_socket(char *ip, int port) {

  struct sockaddr_in *socket_address;
  socket_address = malloc(sizeof(struct sockaddr_in));
  socket_address->sin_family = AF_INET; // ipv4 by defalult
  socket_address->sin_port = htons(port);
  socket_address->sin_addr.s_addr =
      ip != NULL ? inet_addr(ip) : htonl(INADDR_ANY);

  return socket_address;
}

int get_udp_sock_desc() {
  int socket_desc = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (socket_desc < 0) {
    printf("Error while creating socket\n");
    return -1;
  }
  return socket_desc;
}

char *get_ip_str(const struct sockaddr *sa, char *s_ip, int *port,
                 size_t maxlen) {
  switch (sa->sa_family) {
  case AF_INET:
    struct sockaddr_in *sin = (struct sockaddr_in *)sa;
    if (s_ip != NULL) {
      inet_ntop(AF_INET, &sin->sin_addr, s_ip, maxlen);
    }
    if (port != NULL)
      *port = htons(sin->sin_port);
    break;

  case AF_INET6:
    inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr), s_ip,
              maxlen);
    break;

  default:
    strncpy(s_ip, "Unknown AF", maxlen);
    return NULL;
  }

  return s_ip;
}

// todo: change here to support diffrent bundle policy make thread argument more
// robust
//
void *packet_listner_thread(void *peer_v) {
  struct RTCPeerConnection *peer = (struct RTCPeerConnection *)peer_v;
  int *sport = malloc(sizeof(int));
  int *rport = malloc(sizeof(int));
  char *sender_ip = malloc(20);
  char *recv_ip = malloc(20);
  char *udp_packet = malloc(1000);
  socklen_t socklen = sizeof(struct sockaddr_in);

  struct sockaddr *sender_addr = malloc(sizeof(struct sockaddr));
  struct sockaddr *receiver_addr = malloc(sizeof(struct sockaddr));

  if (peer->transceiver == NULL &&
      peer->transceiver->local_ice_candidate == NULL) {
    printf("something went wrong  null");
    exit(0);
    return 0;
  }
  struct pollfd *candidates_fds;
  int candidate_list_size = get_candidates_fd_array(peer, &candidates_fds);
  send_stun_bind(NULL, STUN_REQUEST_CLASS,
                 peer->transceiver->local_ice_candidate, NULL);

  while (poll(candidates_fds, candidate_list_size, NULL) != -1) {
    for (int poll_index = 0; poll_index < candidate_list_size; poll_index++) {

      if (!((candidates_fds + poll_index)->revents & POLL_IN)) {
        continue;
      }

      int sock_desc = (candidates_fds + poll_index)->fd;
      int bytes =
          recvfrom(sock_desc, udp_packet, 1000, 0, sender_addr, &socklen);

      if (bytes == -1)
        printf("error something went wrong when reciving stun response %d",
               errno);

      struct NetworkPacket *packet = get_parsed_packet(udp_packet, bytes);

      if (packet == NULL) {
        printf("packet detected a NULL");
        continue;
      }
      getsockname(sock_desc, receiver_addr, &socklen);
      packet->receiver_sock = receiver_addr;

      get_ip_str(sender_addr, sender_ip, sport, socklen);
      get_ip_str((struct sockaddr *)receiver_addr, recv_ip, rport, socklen);

      packet->sender_ip = sender_ip;
      packet->receiver_ip = recv_ip;
      packet->sender_port = sport;
      packet->receiver_port = rport;
      packet->sock_desc = sock_desc;
      packet->sock_len = socklen;

      packet->sender_sock = sender_addr;
      packet->receiver_sock = receiver_addr;

      if (packet->protocol == STUN) {
        on_stun_packet(packet, peer);
      } else if (packet->protocol == RTP) {
        // parse RTP packet
      } else if (packet->protocol == RTCP) {
        // parse RTCP packet
      }
    }
  }
  return 0;
}
struct NetworkPacket *get_parsed_packet(char *packet, int bytes) {

  // check if its a STUN
  struct NetworkPacket *network_packet = malloc(sizeof(struct NetworkPacket));
  struct Stun *stun = malloc(sizeof(struct Stun));
  memcpy(stun, packet, sizeof(struct Stun));

  if (check_if_stun(stun)) {
    network_packet->protocol = STUN;
    network_packet->header.stun_header = stun;
    // class request 00 indication 01 success response 10 error 11
    // method binding 01  response 10
    int class = stun->msg_type & 0x110;
    int method = stun->msg_type & 0x3EEF;

    if (class == STUN_RESPONSE_CLASS && method == STUN_BINDING_METHOD) {
      printf("recived stun binding response \n");
      network_packet->subtype = BINDING_RESPONSE;

      struct StunPayload *stun_respose_payload =
          malloc(sizeof(struct StunPayload));
      int stun_header_size = sizeof(struct Stun);

      memcpy(stun_respose_payload,
             packet + stun_header_size + sizeof(struct TVL),
             sizeof(struct StunPayload));

      network_packet->payload.stun_payload = stun_respose_payload;

      uint32_t magic = STUN_MAGIC_COOKIE;

      uint16_t mapped_port =
          (ntohs(stun_respose_payload->x_port) ^
           ((uint16_t)(ntohs(stun->magic_cookie)))); // port and ip is sotred
                                                     // xored with the cookie
      uint32_t mapped_ip = ntohl(ntohl(stun_respose_payload->x_ip) ^ (magic));

      stun_respose_payload->x_ip = mapped_ip;
    }

    if (class == STUN_REQUEST_CLASS && method == STUN_BINDING_METHOD) {
      printf("received stun biding request\n");
      network_packet->subtype = BINDING_REQUEST;
    }

    // if (class == method ==) {
    // }
    //

    return network_packet;
  }

  // check if RTP RTCP
  return NULL;
}

bool check_if_stun(struct Stun *stun_header) {

  stun_header->msg_type = ntohs(stun_header->msg_type);
  int zerobits = stun_header->msg_type & 0xC000; // 1100000

  if (zerobits != 0) {
    return false;
  }

  uint32_t magic_cookie = ntohl(stun_header->magic_cookie);

  if (magic_cookie != STUN_MAGIC_COOKIE) {
    return false;
  }

  return true;
}
int get_candidates_fd_array(struct RTCPeerConnection *peer,
                            struct pollfd **candidate_fd) {
  if (peer == NULL || peer->transceiver == NULL)
    return 0;
  struct pollfd *fd_array = malloc(sizeof(struct pollfd) * 10);
  struct pollfd *i = fd_array;
  int size = 10;

  for (struct RTCRtpTransceivers *transceiver = peer->transceiver;
       transceiver != NULL; transceiver = transceiver->next_trans) {
    for (struct RTCIecCandidates *candidate = transceiver->local_ice_candidate;
         candidate != NULL; candidate = candidate->next_candidate) {
      printf("testong\n");
      if ((fd_array + size) == i) {
        fd_array = realloc(fd_array, sizeof(struct pollfd) * size +
                                         sizeof(struct pollfd) * 10);
        size = size + 10;
      }
      struct pollfd *fd = malloc(sizeof(struct pollfd));
      fd->fd = candidate->sock_desc;
      fd->events = POLL_IN;

      *i = *fd;
      i++;
    }
    if (BUNDLE_MAX_BUNDLE) { // compare webrtc config param todo
      break;
    }
  }
  *candidate_fd = fd_array;

  // printf("%d %d %d \n", i, fd_array, i - fd_array);
  // printf("testong\n");
  return i - fd_array;
}
struct Stun *parse_stun_header(struct Stun *stun_header) {}
