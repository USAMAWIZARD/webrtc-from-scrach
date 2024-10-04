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
+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+ | contributing source
(CSRC) identifiers           | |                             .... |
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
#include "../SRTP/srtp.h"
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

void getdata(void *data);
void send_rtp_packet(struct RtpStream *rtpStream, char *payload,
                     int payload_size);

struct Rtp *init_rtp_packet(struct RtpStream *rtpStream) {
  struct Rtp *rtp_packet_packet;
  rtp_packet_packet = (struct Rtp *)malloc(sizeof(*rtp_packet_packet) + 50000);
  rtp_packet_packet->v = 2;
  rtp_packet_packet->pt = rtpStream->payload_type;
  rtp_packet_packet->ext = 0;
  rtp_packet_packet->marker = rtpStream->marker;
  rtp_packet_packet->padding = 0;
  rtp_packet_packet->seq_no = htons(rtpStream->seq_no); // htons(rand());
  rtp_packet_packet->csrc_count = 1;
  rtp_packet_packet->ssrc = htonl(rtpStream->ssrc);
  rtp_packet_packet->csrc = 1;
  rtp_packet_packet->timestamp = 0;

  return rtp_packet_packet;
}

struct RtpStream *create_rtp_stream(struct RtpSession *rtp_session,
                                    struct MediaStreamTrack *track,
                                    uint32_t ssrc, uint8_t payload_type) {
  // set src and remote ip port
  struct RtpStream *newRtpStream;
  newRtpStream = malloc(sizeof(struct RtpStream));
  newRtpStream->media_data_callback = track->get_data_callback;

  newRtpStream->ssrc = ssrc;
  newRtpStream->payload_type = payload_type;
  newRtpStream->callback_data = track->userdata;
  newRtpStream->seq_no = rand();

  return newRtpStream;
}
void init_rtp_stream(struct RtpStream *stream, struct CandidataPair *pair,
                     struct SrtpEncryptionCtx *srtp_encryption_ctx) {

  stream->socket_len = sizeof(struct sockaddr_in);
  stream->timestamp = rand();
  stream->pair = pair;
  stream->rtp_packet = init_rtp_packet(stream);
  stream->srtp_encryption_ctx = srtp_encryption_ctx;
}

void send_rtp_packet(struct RtpStream *rtpStream, char *payload,
                     int payload_size) {
  static uint16_t rtp_mtu_size = 1400;

  int socket_len = rtpStream->socket_len;

  rtpStream->rtp_packet->seq_no = htons(rtpStream->seq_no++);
  rtpStream->rtp_packet->timestamp = htonl(rtpStream->timestamp);

  memcpy(rtpStream->rtp_packet->payload, payload, payload_size);

  if (rtpStream->srtp_encryption_ctx)
    encrypt_srtp(rtpStream->srtp_encryption_ctx, rtpStream->rtp_packet,
                 payload_size);
  int bytes =
      sendto(rtpStream->pair->p0->sock_desc, rtpStream->rtp_packet,
             sizeof(*rtpStream->rtp_packet) + payload_size, 0,
             (struct sockaddr *)(rtpStream->pair->p1->src_socket), socket_len);
  usleep(15000);
  if (bytes == -1) {
    printf("\n failed to send the data %s  %d  socket_len %d desc %d\n",
           strerror(errno), payload_size, socket_len,
           rtpStream->pair->p0->sock_desc);

  } else {
    // printf("\n sent data %d   %d  socket_len %d desc %d\n", errno,
    // payload_size, socket_len , rtpStream->sockdesc);
  }
}

// create a new thread and start sending rtp totalStreams
bool start_rtp_stream(struct RtpStream *rtpStream) {

  (*rtpStream->media_data_callback)(rtpStream->callback_data, &send_rtp_packet,
                                    rtpStream);
  return true;
}
bool stop_rtp_stream(struct RtpStream *rtpStream) {
  if (close(rtpStream->pair->p0->sock_desc) < 0) {
    printf("failed to close the RTP");
    return false;
  }
  return true;
}
