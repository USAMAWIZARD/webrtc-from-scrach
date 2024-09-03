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
#include "../Network/network.h"
#include "../WebRTC/webrtc.h"
#include "rtp.h"
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#pragma pack(1)

void getdata(void *data);
void send_rtp_packet(struct RtpStream *rtpStream, char *payload,
                     int payload_size);

struct Rtp *init_rtp_packet() {
  struct Rtp *rtp_packet_packet;
  rtp_packet_packet = (struct Rtp *)malloc(sizeof(*rtp_packet_packet) + 50000);
  rtp_packet_packet->v = 2;
  rtp_packet_packet->pt = 96;
  rtp_packet_packet->ext = 0;
  rtp_packet_packet->marker = 0;
  rtp_packet_packet->padding = 0;
  rtp_packet_packet->seq_no = 0; // htons(rand());
  rtp_packet_packet->csrc_count = 1;
  rtp_packet_packet->ssrc = 12343;
  rtp_packet_packet->csrc = 1;
  rtp_packet_packet->timestamp = 0;

  //  strcpy(rtp_packet_packet->NAL,"faasdfasdfasdfasdfasdfasdfafdasdf");
  //  memset(rtp_packet_packet,0,sizeof(*rtp_packet_packet)+34);

  return rtp_packet_packet;
}

struct RtpStream *create_rtp_stream(char *ip, int port,
                                    struct RtpSession *rtp_session,
                                    struct MediaStreamTrack *track) {

  struct RtpStream *newRtpStream;
  newRtpStream = malloc(sizeof(struct RtpStream));
  newRtpStream->media_data_callback = track->get_data_callback;
  newRtpStream->ip = ip;
  newRtpStream->port = port;
  newRtpStream->callback_data = track->userdata;
  newRtpStream->rtp_packet = init_rtp_packet();
  ;
  newRtpStream->socket_len = sizeof(struct sockaddr_in);
  newRtpStream->timestamp = rand();
  newRtpStream->socket_address =
      get_network_socket(newRtpStream->ip, newRtpStream->port);
  newRtpStream->sockdesc = get_udp_sock_desc();

  rtp_session->streams[++rtp_session->totalStreams] = newRtpStream;
  return newRtpStream;
}

// create a new thread and start sending rtp totalStreams
bool start_rtp_stream(struct RtpStream *rtpStream) {
  (*rtpStream->media_data_callback)(rtpStream->callback_data, &send_rtp_packet,
                                    rtpStream);
  return true;
}

  void send_rtp_packet(struct RtpStream *rtpStream, char *payload,
                     int payload_size) {
  int socket_len = rtpStream->socket_len;
  rtpStream->rtp_packet->seq_no = ntohs(rtpStream->rtp_packet->seq_no);
  rtpStream->rtp_packet->seq_no++;
  rtpStream->rtp_packet->seq_no = htons(rtpStream->rtp_packet->seq_no);
  rtpStream->rtp_packet->timestamp = htonl(rtpStream->timestamp);
  memcpy(rtpStream->rtp_packet->payload, payload, payload_size);
  int bytes =
      sendto(rtpStream->sockdesc, rtpStream->rtp_packet,
             sizeof(*rtpStream->rtp_packet) + payload_size, 0,
             (struct sockaddr *)(rtpStream->socket_address), socket_len);
  // printf("%d\n",rtpStream->rtp_packet->marker);
  usleep(15000);
  if (bytes == -1) {
    printf("\n failed to send the data %s  %d  socket_len %d desc %d\n",
           strerror(errno), payload_size, socket_len, rtpStream->sockdesc);

  } else {
    // printf("\n sent data %d   %d  socket_len %d desc %d\n", errno,
    // payload_size, socket_len , rtpStream->sockdesc);
  }
}

bool stop_rtp_stream(struct RtpStream *rtpStream) {
  if (close(rtpStream->sockdesc) < 0) {
    printf("failed to close the RTP");
    return false;
  }
  return true;
}
