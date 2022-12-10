#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct Rtp
{
  unsigned int v : 2;
  unsigned int padding : 1;
  unsigned int ext : 1;
  unsigned int csrc_count : 4;
  unsigned int marker : 1;
  unsigned int pt : 7;
  unsigned int seq_no : 16;
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
  rtp_packet->v = 1;
  rtp_packet->padding = 1;
  rtp_packet->ext = 1;
  rtp_packet->csrc_count = 0;
  rtp_packet->marker = 1;
  rtp_packet->pt = 1;
  rtp_packet->seq_no = 1;
  rtp_packet->timestamp = 1;
  rtp_packet->ssrc = 1;
  rtp_packet->csrc = 1;
  rtp_packet->hader_ex = 1;
  memcpy(&rtp_packet->payload, payload, strlen(payload) + 1);
  char str[300];

  // sprintf(str, "%d %d %d %d %d %d %d  %ld %ld %ld %ld %s",rtp_packet->v,rtp_packet->padding,rtp_packet->ext,rtp_packet->csrc_count,rtp_packet->marker,rtp_packet->pt,rtp_packet->seq_no,rtp_packet->timestamp,rtp_packet->ssrc,rtp_packet->csrc,rtp_packet->hader_ex);
  seqno++;
  return rtp_packet;
}
char *convert_rtp_pkt_to_string(struct Rtp *rtp_packet)
{
  char *str;
  str = (char *)malloc(sizeof(char) * 300); // yaha seg fault aa raha hai
  //sprintf(str, "%d %d %d %d %d %d %d  %ld %ld %ld %ld %s", rtp_packet->v, rtp_packet->padding, rtp_packet->ext, rtp_packet->csrc_count, rtp_packet->marker, rtp_packet->pt, rtp_packet->seq_no, rtp_packet->timestamp, rtp_packet->ssrc, rtp_packet->csrc, rtp_packet->hader_ex);
 // str="hello";
 // printf("pkt %s", *str);
//  return str;
}