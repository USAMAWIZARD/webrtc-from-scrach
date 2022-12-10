#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct __attribute__((packed)) Rtp
{
  unsigned char v : 2;
  unsigned char padding : 1;
  unsigned char ext : 1;
  unsigned char csrc_count : 4;
  unsigned char marker : 1;
  unsigned char pt : 7;
  unsigned short int seq_no : 16;
  long int timestamp : 32;
  long int ssrc : 32;
  long int csrc : 32;
  long int hader_ex : 32;
  char payload[];
};

struct Rtp *create_rtp_packet(char *payload)
{
  static long int seqno = 0;
  struct Rtp *rtp_packet;
  rtp_packet = (struct Rtp *)malloc(sizeof(rtp_packet) + (strlen(payload) * sizeof(char)) + sizeof(char));
  // mere wireshark me agar \0 hai to age ka data drop karderaha tha to ff rakha sab
  rtp_packet->v = 3;
  rtp_packet->padding = 1;
  rtp_packet->ext = 1;
  rtp_packet->csrc_count = 0xf;
  rtp_packet->marker = 1;
  rtp_packet->pt = 0x3f;
  rtp_packet->seq_no = 0x7fff;
  rtp_packet->timestamp = 0xffffffff;
  rtp_packet->ssrc = 0xffffffff;
  rtp_packet->csrc = 0xffffffff;
  rtp_packet->hader_ex = 0xffffffff;
  //rtp_packet->payload = *payload;
  memcpy(&rtp_packet->payload,payload, strlen(payload)+1);

  seqno++;
  return rtp_packet;
}
