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

  // bind request contains only header
  char *stun_server_ip = STUN_IP;
  int stun_server_port = STUN_PORT;

  struct Stun *stun_message = malloc(sizeof(struct Stun) + 200);
  stun_message->msg_len = 0;
  stun_message->msg_type = htons((STUN_BINDING_METHOD | message_class));

  stun_message->magic_cookie = htonl(STUN_MAGIC_COOKIE);
  socklen_t socklen = sizeof(struct sockaddr_in);
  char *transaction_id = g_uuid_string_random();

  strncpy(stun_message->transaction_id, transaction_id, 12);
  strncpy(stun_message->transaction_id, &pair->p0->id, sizeof(uint32_t));

  int sock_desc = pair->p0->sock_desc;

  struct sockaddr_in *srcaddr = pair->p0->src_socket;

  struct sockaddr_in *dest_addr =
      get_network_socket(pair->p1->address, pair->p1->port);

  if (sender_candidate == NULL && message_class == STUN_REQUEST_CLASS) {
    // username:username

    char *usernamekeys =
        g_strdup_printf("%s:%s", pair->p1->ufrag, pair->p0->ufrag);

    add_stun_attribute(stun_message, STUN_ATTRIBUTE_USERNAME, usernamekeys,
                       NULL);

    add_stun_attribute(stun_message, STUN_ATTRIBUTE_ICE_CONTROLLING, "adcdfdsa",
                       NULL);

    if (false) {
      add_stun_attribute(stun_message, STUN_ATTRIBUTE_USE_CANDIDATE, "", NULL);
    }
    // check here
    add_stun_attribute(stun_message, STUN_ATTRIBUTE_PRIORITY,
                       (guchar *)pair->p0->priority, sizeof(uint32_t));
  }

  if (message_class == STUN_RESPONSE_CLASS) {
    if (data == NULL) {
      printf("cannot send binding rsponse data is null\n");
      return false;
    }
    struct stun_binding *binding = (struct stun_binding *)data;
    struct StunPayload *payload = malloc(sizeof(struct StunPayload));
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

    guchar *stun_message_hmac = generate_HMAC(pair->p0->password, stun_message);

    add_stun_attribute(stun_message, STUN_ATTRIBUTE_MESSAGE_INTIGRITY,
                       stun_message_hmac, NULL);

    uint32_t stun_message_crc32 =
        crc32(0, (const Bytef *)&stun_message, ntohs(stun_message->msg_len)) ^
        0x5354554e;

    add_stun_attribute(stun_message, STUN_ATTRIBUTE_FINGERPRINT,
                       (guchar *)&stun_message_crc32, sizeof(uint32_t));
  }

  int bytes = sendto(sock_desc, stun_message,
                     sizeof(struct Stun) + ntohs(stun_message->msg_len), 0,
                     (struct sockaddr *)dest_addr, sizeof(struct sockaddr_in));

  if (bytes != -1 && bytes != 0)
    printf("\n-stun Packet sent client : stun://%s:%d with   server/Cliet : "
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
  gsasl_saslprep(key, GSASL_ALLOW_UNASSIGNED, &sasl, NULL);

  char *stun_hmac = g_compute_hmac_for_data(
      G_CHECKSUM_SHA1, (const guchar *)sasl, strlen(sasl),
      (const guchar *)stun_message, ntohs(stun_message->msg_len));

  // printf("HMAC HASH ---%s\n", stun_hmac);
  // printf("HMAC KEY %s --\n", sasl);
  // memcpy(stun_message, "\0", 1);
  // print_hex((const guchar *)stun_message, stun_message->msg_len);
  guchar *binhmac = hexstr_to_char(stun_hmac);
  free(sasl);
  return binhmac;
}

struct TVL *add_stun_attribute(struct Stun *stun, uint16_t type, char *value,
                               uint16_t size) {
  uint16_t len = size != NULL ? size : strlen(value);
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
    stun_binding->candidate_type = "srflx";
    uint32_t candidate_id;
    memcpy(&candidate_id, stun_header->transaction_id, sizeof(uint32_t));

    for (struct RTCIecCandidates *candidate =
             peer->transceiver->local_ice_candidate;
         candidate != NULL; candidate = candidate->next_candidate) {
      if (candidate->id == candidate_id) {
        stun_binding->local_ip = candidate->address;
      }
    }
    // on_reflexive_candidates(peer, stun_binding);
    printf("\n-----public NAT Mapping is  : PORT %d  IP , %s  %s %s-----\n",
           stun_binding->bound_port, stun_binding->bound_ip,
           stun_binding->local_ip, stun_binding->candidate_type);
    //    exit(0);
  }
  if (packet->subtype == BINDING_REQUEST) {

    if (packet->sender_ip != NULL) {

      // checking on only  first trans candidate pair for max bundle
      struct CandidataPair *checklist = peer->transceiver->pair_checklist;

      for (; checklist != NULL; checklist = checklist->next_pair) {

        if ((strcmp(checklist->p0->address, packet->receiver_ip) == 0 &&
             *packet->receiver_port == checklist->p0->port) &&
            (strcmp(checklist->p1->address, packet->sender_ip) == 0 &&
             *packet->sender_port == checklist->p1->port)) {

          struct stun_binding *binding = malloc(sizeof(struct stun_binding));
          binding->bound_port = checklist->p1->port;
          binding->bound_ip = checklist->p1->address;

          send_stun_bind(checklist, STUN_RESPONSE_CLASS, NULL, binding);
          break;
        }
      }
    }
  }
}
char *get_stun_attributes(struct RTCIecCandidates *local_candidate,
                          struct RTCIecCandidates *remote_candidate) {

  // struct stun_attribute *username= mall;
  // username->type = 0x0006;
  // username->length = htons(10);
  // strcpy(username.value,"usama:usam1");
  //
  return NULL;
}
guchar *hexstr_to_char(const char *hexstr) {
  size_t len = strlen(hexstr);
  if (len % 2 != 0)
    return NULL;
  size_t final_len = len / 2;
  guchar *chrs = (unsigned char *)malloc((final_len + 1) * sizeof(*chrs));
  for (size_t i = 0, j = 0; j < final_len; i += 2, j++)
    chrs[j] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i + 1] % 32 + 9) % 25;
  chrs[final_len] = '\0';
  return chrs;
}
void print_hex(const unsigned char *data, size_t length) {
  for (size_t i = 0; i < length; i++) {
    printf("%02x ", data[i]);
  }
  printf("\n");
}
