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
/*
      0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |         Type                  |            Length             |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                         Value (variable)                ....
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                    Figure 4: Format of STUN Attributes


                        0                 1
                        2  3  4 5 6 7 8 9 0 1 2 3 4 5

                       +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
                       |M |M |M|M|M|C|M|M|M|C|M|M|M|M|
                       |11|10|9|8|7|1|6|5|4|0|3|2|1|0|
                       +--+--+-+-+-+-+-+-+-+-+-+-+-+-+

                Figure 3: Format of STUN Message Type Field

*/
#pragma once
#include "../ICE/ice.h"
#include "../Network/network.h"
#include "glib.h"
#include <stdint.h>
#include <sys/types.h>

#ifndef _STUNH_
#define _STUNH_

#define STUN_MAGIC_COOKIE 0x2112A442
#define STUN_MAGIC_COOKIE_MSB 0x2112
#define STUN_ATTRIBUTE_USERNAME 0x0006
#define STUN_ATTRIBUTE_ICE_CONTROLLING 0x802a
#define STUN_ATTRIBUTE_ICE_CONTROLLED 0x8029
#define STUN_ATTRIBUTE_USE_CANDIDATE 0x0025
#define STUN_ATTRIBUTE_PRIORITY 0x0024
#define STUN_ATTRIBUTE_MESSAGE_INTIGRITY 0x0008
#define STUN_ATTRIBUTE_FINGERPRINT 0x8028
#define STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS 0x0020

// class request 00 indication 01 success response 10 error 11
// method binding 01
#define STUN_REQUEST_CLASS 0x00
#define STUN_RESPONSE_CLASS 0x100

#define STUN_BINDING_METHOD 0x001

#define FAMILY_IPV4 0x01

struct __attribute__((packed)) Stun {
  uint16_t msg_type : 16;
  uint16_t msg_len : 16;
  uint32_t magic_cookie : 32;
  char transaction_id[12];
  // data
  char data[];
};

// client binding request
// server icecandidate

struct __attribute__((packed)) StunPayload {
  uint8_t reserved;
  uint8_t family;
  uint16_t x_port; // ip and are xor mapped with Transaction id
  uint32_t x_ip;
};
struct TVL {
  uint16_t att_type;
  uint16_t att_len;
  char value[];
};
struct stun_binding {
  char *local_ip;
  char *bound_ip;
  uint16_t bound_port;
  char *candidate_type;
};
bool send_stun_bind(struct CandidataPair *pair, int message_class,
                    struct RTCIecCandidates *sender_candidate, void *data);

struct TVL *add_stun_attribute(struct Stun *stun, uint16_t type, char *value,
                               uint16_t size);

guchar *generate_HMAC(const gchar *key, struct Stun *message);
void on_reflexive_candidates(struct RTCPeerConnection *peer,
                             struct stun_binding *rflx);

guchar *hexstr_to_char(const char *hexstr);

void print_hex(const unsigned char *data, size_t length);
void on_stun_packet(struct NetworkPacket *packet,
                           struct RTCPeerConnection *peer);


#endif // !_STUNH_
