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
*/
#include "../ICE/ice.h"
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

#ifndef _STUNH_
#define _STUNH_

struct __attribute__((packed)) Stun {
  int zerobits : 2;
  uint16_t msg_type : 14;
  uint16_t msg_len : 16;
  uint32_t magic_cookie : 32;
  char transaction_id[12];
  // data
  char data[];
};

// client binding request
// server icecandidate   

struct __attribute__((packed)) StunPayload {
  uint16_t att_type;
  uint16_t att_len;
  uint8_t reserved;
  uint8_t family;
  uint16_t x_port; // ip and are xor mapped with Transaction id
  uint32_t x_ip;
};
struct stun_binding {
  char *local_ip;
  char *bound_ip;
  uint16_t bound_port;
};
struct stun_attribute {
  uint16_t type;
  uint16_t length;
  char value[];
};
struct stun_binding *
stun_bind_request(struct RTCIecCandidates *local_candidate,
                  struct RTCIecCandidates *remote_candidate, char *stun_ip,
                  int stun_port);
#endif // !_STUNH_
