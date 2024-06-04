
// https://datatracker.ietf.org/doc/html/rfc3550
/*
RTP Header

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|V=2|P|X|  CC   |M|     PT      |       sequence number       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           timestamp                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           synchronization source (SSRC) identifier          |
+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
|            contributing source (CSRC) identifiers           |
|                             ....                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

RTP payload header.

  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|F|NRI|  Type   |                                               |
+-+-+-+-+-+-+-+-+                                               |
|                                                               |
|               Bytes 2..n of a single NAL unit                 |
|                                                               |
|                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               :...OPTIONAL RTP padding        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
#include <string.h>
#pragma pack(1)
#include "../Network/network.h"
#include "rtp.h"
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

void getdata(void *data);
void rtp_sender_thread(struct RtpStream *rtpStream, char *payload , int payload_size);
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
#else
#error "Byte order is not recognized it should either be big or little endian"
#endif

#if G_BYTE_ORDER == G_LITTLE_ENDIAN
  unsigned int pt : 7;
  unsigned int marker : 1;
#elif G_BYTE_ORDER == G_BIG_ENDIAN
  unsigned int marker : 1;
  unsigned int pt : 7;
#error "Byte order is not recognized it should either be big or little endian"
#endif
  unsigned int seq_no : 16;
  int timestamp : 32;
  unsigned int ssrc : 32;
char *payload[];
};

struct Rtp *init_rtp_packet() {
  struct Rtp *rtp_packet_packet;
  rtp_packet_packet = (struct Rtp *)malloc(sizeof(*rtp_packet_packet)+10000);
  rtp_packet_packet->v = 2;
  rtp_packet_packet->pt = 96;
  rtp_packet_packet->ext = 0;
  rtp_packet_packet->marker = 0;
  rtp_packet_packet->padding = 0;
  rtp_packet_packet->seq_no = 0; //htons(rand());
  rtp_packet_packet->csrc_count = 0;
  rtp_packet_packet->ssrc = 0;
  rtp_packet_packet->timestamp = 0;

  //  strcpy(rtp_packet_packet->NAL,"faasdfasdfasdfasdfasdfasdfafdasdf");
  //  memset(rtp_packet_packet,0,sizeof(*rtp_packet_packet)+34);

  printf("%ld size of a ", sizeof(*rtp_packet_packet));
  return rtp_packet_packet;
}

struct RtpStream *create_rtp_stream(char *ip, int port,
                                    struct RtpSession *rtp_session,
                                    void *media_data_callback,
                                    void *callback_data) {

  struct RtpStream *newRtpStream;
  newRtpStream = malloc(sizeof(struct RtpStream));
  newRtpStream->media_data_callback = media_data_callback;
  newRtpStream->ip = ip;
  newRtpStream->port = port;
  newRtpStream->callback_data = callback_data;
  newRtpStream->rtp_packet = init_rtp_packet();;
  newRtpStream->socket_len = sizeof(struct sockaddr_in);
  rtp_session->streams[++rtp_session->totalStreams] = newRtpStream;

  return newRtpStream;
}

// create a new thread and start sending rtp totalStreams
bool start_rtp_stream(struct RtpStream *rtpStream) {
  rtpStream->socket_address =
      get_network_socket(rtpStream->ip, rtpStream->port);
  rtpStream->sockdesc = get_udp_sock_desc();
  (*rtpStream->media_data_callback)(rtpStream->callback_data,
                                    &rtp_sender_thread, rtpStream);

  return true;
}

void rtp_sender_thread(struct RtpStream *rtpStream, char *payload, int payload_size) {
  int socket_len = rtpStream->socket_len;
  rtpStream->rtp_packet->seq_no = ntohs(rtpStream->rtp_packet->seq_no) ;
  rtpStream->rtp_packet->seq_no++;
  rtpStream->rtp_packet->seq_no = htons(rtpStream->rtp_packet->seq_no) ;
//  int payload_size = strlen(payload);
  
  memcpy(rtpStream->rtp_packet->payload, payload,payload_size);

  int bytes = sendto(rtpStream->sockdesc, rtpStream->rtp_packet, sizeof(*rtpStream->rtp_packet) + payload_size , 0,
             (struct sockaddr *)(rtpStream->socket_address), socket_len);
  //sleep(1);
  if (bytes == -1) {
    printf("\n failed to send the data %d  %d  socket_len %d\n", errno, payload_size, socket_len );
  } else {
    printf("\n sent data %d   %d  socket_len %d\n", errno, payload_size, socket_len );
  }
}

bool stop_rtp_stream(struct RtpStream *rtpStream) {
  if (close(rtpStream->sockdesc) < 0) {
    printf("failed to close the RTP");
    return false;
  }
  return true;
}
