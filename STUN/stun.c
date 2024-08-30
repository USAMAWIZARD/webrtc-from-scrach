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
#include "glib.h"
#include <arpa/inet.h>
#include <gsasl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <zlib.h>

#define STUN_IP "74.125.250.129"
#define STUN_PORT 19302

#pragma pack(1)

bool send_stun_bind(struct CandidataPair *pair, int message_class,
                    struct RTCIecCandidates *sender_candidate, void *data) {

  if (pair != NULL) {

    if (pair->p0 == NULL || pair->p1 == NULL)
      return 0;
  }
  if (pair == NULL && sender_candidate != NULL) {
    pair = malloc(sizeof(struct CandidataPair));
    pair->p0 = sender_candidate;
    pair->p1 = malloc(sizeof(struct RTCIecCandidates));
    pair->p1->address = STUN_IP;
    pair->p1->port = STUN_PORT;
  }

  // bind request contains only header for stun server
  char *stun_server_ip = STUN_IP;
  int stun_server_port = STUN_PORT;

  struct Stun *stun_message = malloc(sizeof(struct Stun) + 200);
  stun_message->msg_len = 0;
  stun_message->msg_type = htons((STUN_BINDING_METHOD | message_class));

  stun_message->magic_cookie = htonl(STUN_MAGIC_COOKIE);
  socklen_t socklen = sizeof(struct sockaddr_in);

  int sock_desc = pair->p0->sock_desc;

  struct sockaddr_in *srcaddr = pair->p0->src_socket;

  struct sockaddr_in *dest_addr =
      get_network_socket(pair->p1->address, pair->p1->port);
  char *ice_password;

  if (sender_candidate == NULL && message_class == STUN_REQUEST_CLASS) {
    // username:username
    ice_password = pair->p1->password;

    char *usernamekeys =
        g_strdup_printf("%s:%s", pair->p1->ufrag, pair->p0->ufrag);
    strncpy(stun_message->transaction_id, pair->transaction_id, 12);

    add_stun_attribute(stun_message, STUN_ATTRIBUTE_USERNAME, usernamekeys, -1);

    add_stun_attribute(stun_message, STUN_ATTRIBUTE_ICE_CONTROLLING, "adcdfdsa",
                       -1);

    if (true) {
      add_stun_attribute(stun_message, STUN_ATTRIBUTE_USE_CANDIDATE, "", -1);
    }
    // check here
    add_stun_attribute(stun_message, STUN_ATTRIBUTE_PRIORITY,
                       (guchar *)&pair->p0->priority, sizeof(uint32_t));
  }

  if (message_class == STUN_RESPONSE_CLASS) {

    ice_password = pair->p0->password;
    if (data == NULL) {
      printf("cannot send binding rsponse data is null\n");
      return false;
    }
    struct stun_binding *binding = (struct stun_binding *)data;
    struct StunPayload *payload = malloc(sizeof(struct StunPayload));

    strncpy(stun_message->transaction_id, binding->transaction_id,
            sizeof(stun_message->transaction_id));
    guchar *payload_str = malloc(sizeof(struct StunPayload));

    uint16_t mapped_port = htons(
        binding->bound_port ^ STUN_MAGIC_COOKIE_MSB); // port and ip is sotred
                                                      // xored with the cookie
    uint32_t mapped_ip =
        htonl(htonl(inet_addr(binding->bound_ip)) ^ STUN_MAGIC_COOKIE);
    payload->x_ip = mapped_ip;
    payload->reserved = 0x00;
    payload->x_port = mapped_port;
    payload->family = FAMILY_IPV4;

    memcpy(payload_str, payload, sizeof(struct StunPayload));

    add_stun_attribute(stun_message, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,
                       payload_str, sizeof(struct StunPayload));
  }
  if (sender_candidate == NULL && (message_class == STUN_RESPONSE_CLASS ||
                                   message_class == STUN_REQUEST_CLASS)) {
    guchar *stun_message_hmac = generate_HMAC(ice_password, stun_message);

    add_stun_attribute(stun_message, STUN_ATTRIBUTE_MESSAGE_INTIGRITY,
                       stun_message_hmac, 20);

    uint32_t stun_message_crc32 =
        htonl(calculate_crc32(stun_message) ^ 0x5354554e);
    add_stun_attribute(stun_message, STUN_ATTRIBUTE_FINGERPRINT,
                       (guchar *)&stun_message_crc32, 4);

    // exit(0);
  }

  int bytes = sendto(sock_desc, stun_message,
                     sizeof(struct Stun) + ntohs(stun_message->msg_len), 0,
                     (struct sockaddr *)dest_addr, sizeof(struct sockaddr_in));

  if (sender_candidate == NULL && (message_class == STUN_RESPONSE_CLASS))
    if (bytes != -1 && bytes != 0)
      printf("\nstun Packet sent client : stun://%s:%d with C/S : "
             "%s:%d \n",
             pair->p0->address, pair->p0->port, pair->p1->address,
             pair->p1->port);
    else
      printf("something went wrong  while sending stun \n ");

  free(stun_message);
  return true;
}

guchar *generate_HMAC(const gchar *key, struct Stun *stun_message) {
  char *sasl;
  int actual_len = ntohs(stun_message->msg_len);
  int presumed_len = ntohs(stun_message->msg_len) + 20 + 4;

  //  gsasl_saslprep(key, GSASL_ALLOW_UNASSIGNED, &sasl, NULL);

  stun_message->msg_len = htons(presumed_len);

  char *stun_hmac =
      g_compute_hmac_for_data(G_CHECKSUM_SHA1, key, strlen(key), stun_message,
                              actual_len + sizeof(struct Stun));

  // printf("HMAC HASH ---%s\n", stun_hmac);
  // printf("HMAC KEY %s --\n", sasl);
  // print_hex(sasl, strlen(sasl));
  // printf("stunmsage len %d --\n", actual_len + sizeof(struct Stun));
  //
  // print_hex(stun_message, sizeof(struct Stun) + actual_len);
  //
  stun_message->msg_len = htons(actual_len);

  guchar *binhmac = hexstr_to_char(stun_hmac);

  // free(sasl);
  return binhmac;
}
uint32_t calculate_crc32(struct Stun *stun_message) {

  uLong crc = crc32(0L, Z_NULL, 0);
  int actual_len = ntohs(stun_message->msg_len);
  int presumed_len = ntohs(stun_message->msg_len) + 4 + 4;

  stun_message->msg_len = htons(presumed_len);
  uint32_t stun_message_crc32 =
      (crc32(crc, stun_message, actual_len + sizeof(struct Stun)));
  // printf("\n crc32 %x ", stun_message_crc32);
  // print_hex(stun_message, actual_len + sizeof(struct Stun));

  stun_message->msg_len = htons(actual_len);
  return stun_message_crc32;
}
struct TVL *add_stun_attribute(struct Stun *stun, uint16_t type, char *value,
                               int size) {
  uint16_t len = size >= 1 ? size : strlen(value);
  int rem = len % 4;
  int padding_bytes = rem != 0 ? 4 - rem : 0;
  int total_attribute_size = sizeof(struct TVL) + len + padding_bytes;

  struct TVL *tvl_attribute = calloc(1, total_attribute_size);
  tvl_attribute->att_type = htons(type);
  tvl_attribute->att_len = htons(len);

  memcpy(tvl_attribute->value, value, len);

  if (stun != NULL) {
    memcpy(stun->data + ntohs(stun->msg_len), tvl_attribute,
           total_attribute_size);
  }

  stun->msg_len = htons(ntohs(stun->msg_len) + total_attribute_size);
  return tvl_attribute;
}
void on_reflexive_candidates(struct RTCPeerConnection *peer,
                             struct stun_binding *rflx) {
  struct RTCIecCandidates *local_ice_candidate =
      calloc(1, sizeof(struct RTCIecCandidates));

  if (rflx != NULL) {
    local_ice_candidate->priority = 9;
    local_ice_candidate->foundation = 19;
    local_ice_candidate->port = rflx->bound_port;
    local_ice_candidate->address = rflx->bound_ip;
    local_ice_candidate->raddr = rflx->local_ip;
    local_ice_candidate->rport = rflx->bound_port;
    local_ice_candidate->type = rflx->candidate_type;
    local_ice_candidate->component_id = 1;
    local_ice_candidate->sdpMid = 0;
    local_ice_candidate->transport = "udp";

    parse_ice_candidate(local_ice_candidate);
    add_local_icecandidate(peer, local_ice_candidate);
  }
}

void on_stun_packet(struct NetworkPacket *packet,
                    struct RTCPeerConnection *peer) {
  if (peer == NULL || packet == NULL)
    return;

  struct Stun *stun_header = packet->header.stun_header;
  struct StunPayload *stun_respose = packet->payload.stun_payload;

  if (packet->subtype == BINDING_RESPONSE) {
    struct in_addr ip_add;
    ip_add.s_addr = stun_respose->x_ip;
    struct stun_binding *stun_binding = malloc(sizeof(struct stun_binding));
    stun_binding->bound_ip = inet_ntoa(ip_add);
    stun_binding->bound_port = stun_respose->x_port;

    // on_reflexive_candidates(peer, stun_binding);
    if (strcmp(packet->sender_ip, STUN_IP) == 0) {
      stun_binding->candidate_type = "srflx";
      printf("\n-----public NAT Mapping is  : PORT %d  IP , %s %s-----\n",
             stun_binding->bound_port, stun_binding->bound_ip,
             stun_binding->candidate_type);
      // on_reflexive_candidates(peer, stun_binding);
      stun_binding->candidate_type = "prflx";
    } else {
      for (struct RTCRtpTransceivers *transceiver = peer->transceiver;
           transceiver != NULL; transceiver = transceiver->next_trans) {
        for (struct CandidataPair *pair = transceiver->pair_checklist;
             pair != NULL; pair = pair->next_pair) {

          if (strncmp(pair->transaction_id, stun_header->transaction_id, 12) ==
              0) {
            printf("ice pair succeeded %s:%d %s:%d \n", pair->p0->address,
                   pair->p0->port, pair->p1->address, pair->p1->port);
            if (peer->dtls_transport->pair == NULL) {
              peer->dtls_transport->pair = pair;
              start_dtls_negosiation(peer, pair);
            }
            pair->state = ICE_PAIR_SUCCEEDED;
          }
        }
      }
    }
  }

  if (packet->subtype == BINDING_REQUEST) {

    if (packet->sender_ip != NULL) {
      // checking on only  first trans candidate pair for max bundle
      struct stun_binding *binding = malloc(sizeof(struct stun_binding));
      binding->bound_port = *packet->sender_port;
      binding->bound_ip = packet->sender_ip;

      memcpy(binding->transaction_id, stun_header->transaction_id,
             sizeof(stun_header->transaction_id));

      struct CandidataPair *pair = malloc(sizeof(struct CandidataPair));

      for (struct RTCIecCandidates *candidate =
               peer->transceiver->local_ice_candidate;
           candidate != NULL; candidate = candidate->next_candidate) {
        if (strcmp(candidate->address, packet->receiver_ip) == 0 &&
            candidate->port == *packet->receiver_port) {
          pair->p0 = candidate;
          pair->p1 = malloc(sizeof(struct RTCIecCandidates));
          pair->p1->address = packet->sender_ip;
          pair->p1->port = *packet->sender_port;

          send_stun_bind(pair, STUN_RESPONSE_CLASS, NULL, binding);

          free(pair->p1);
          free(pair);
          break;
        }
      }
    }
  }
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
char *get_stun_attributes(struct RTCIecCandidates *local_candidate,
                          struct RTCIecCandidates *remote_candidate) {

  // struct stun_attribute *username= mall;
  // username->type = 0x0006;
  // username->length = htons(9);
  // strcpy(username.value,"usama:usam1");
  return NULL;
}

