#include <stdlib.h>
#include <stdint.h>

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
#ifndef _STUNH_
#define _STUNH_ 

#pragma pack(1)
struct __attribute__((packed)) Stun {
  int zerobits : 2;
  uint16_t msg_type : 14;
  uint16_t msg_len : 16;
  uint32_t magic_cookie: 32;
  char transaction_id[12];
  //data
  char data[];
};
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
struct stun_binding* stun_bind_request(char* src_ip);

#endif // !_STUNH_
