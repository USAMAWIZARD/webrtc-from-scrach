
/*
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|V=2|P|X|  CC   |M|     PT      |       sequence number       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           timestamp                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           synchronization source (SSRC) identifier          |
+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
|            contributing source (CSRC) identifiers           |
|                             ....                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct __attribute__((packed)) Rtp {
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
  unsigned int csrc_count : 4;
  unsigned int ext : 1;
  unsigned int padding : 1;
  unsigned int v : 2;
#elif G_BYTE_ORDER == G_BIG_ENDIAN
  unsigned int v : 2;
  unsigned int padding : 1;
  unsigned int ext : 1;
  unsigned int csrc_count : 4;
#endif
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
  unsigned int pt : 7;
  unsigned int marker : 1;
#elif G_BYTE_ORDER == G_BIG_ENDIAN
  unsigned int marker : 1;
  unsigned int pt : 7;
#endif
  unsigned int seq_no : 16;
  long int timestamp : 32;
  long int ssrc : 32;
  long int csrc : 32;
  long int header_ext : 32;
  char payload[];
};

struct Rtp *create_rtp_packet(char *payload) {
  static long int seqno = 0;
  struct Rtp *rtp_packet;
  rtp_packet =
      (struct Rtp *)malloc(sizeof(*rtp_packet) +
                           (strlen(payload) * sizeof(char)) + sizeof(char) * 2);
  // mere wireshark me agar \0 hai to age ka data drop karderaha tha to ff rakha
  // sab
  rtp_packet->v = 2;
  rtp_packet->padding = 1;
  rtp_packet->ext = 1;
  rtp_packet->csrc_count = 0;
  rtp_packet->marker = 1;
  rtp_packet->pt = 1;
  rtp_packet->seq_no = 1;
  rtp_packet->timestamp = 1;
  rtp_packet->ssrc = 1;
  rtp_packet->csrc = 1;
  rtp_packet->header_ext = 1;
  char *newpay = malloc(strlen(payload) + 1);
  newpay[0] = 0x00;
  strcpy(newpay + 1, payload);
  memcpy(&rtp_packet->payload, newpay, strlen(payload));
  seqno++;
  return rtp_packet;
}
/*char *convert_rtp_pkt_to_string(struct Rtp *rtp_packet)*/
/*{*/
/*char *str=NULL;*/
/*str = (char *)malloc(sizeof(*rtp_packet)); // yaha seg fault aa raha hai*/
/*sprintf(str, "%d %d %d %d %d %d %d  %ld %ld %ld %ld
 * %s",rtp_packet->v,rtp_packet->padding,rtp_packet->ext,rtp_packet->csrc_count,rtp_packet->marker,rtp_packet->pt,rtp_packet->seq_no,rtp_packet->timestamp,rtp_packet->ssrc,rtp_packet->csrc,rtp_packet->header_ext,rtp_packet->payload);*/
/*return str;*/
/*}*/
