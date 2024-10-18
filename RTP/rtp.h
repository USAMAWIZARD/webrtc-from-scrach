#pragma once
#include "../SRTP/srtp.h"
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>

#ifndef _RTPH_
#define _RTPH_

struct RtpStream {
  void (*media_data_callback)(void *,
                              void (*parsed_data_callback)(struct RtpStream *,
                                                           char *, uint32_t),
                              struct RtpStream *);
  struct Rtp *rtp_packet;
  void *callback_data;
  struct CandidataPair *pair;
  char *streamState;
  int socket_len;
  uint8_t payload_type : 7;
  int clock_rate;
  uint16_t seq_no;
  uint32_t ssrc;
  uint32_t timestamp;
  uint8_t marker : 1;
  struct SrtpEncryptionCtx *srtp_encryption_ctx;
  struct MediaStreamTrack *track;
};

struct RtpSession {
  struct RtpStream *streams[10];
  int totalStreams;
};
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
  unsigned int timestamp : 32;
  unsigned int ssrc : 32;
  unsigned int csrc : 32;
  guchar payload[];
};
struct RtpSession *create_rtp_session();
void init_rtp_stream(struct RtpStream *stream, struct CandidataPair *pair,
                     struct SrtpEncryptionCtx *srtp_encryption_ctx);
struct RtpStream *create_rtp_stream(struct RtpSession *rtp_session,
                                    struct MediaStreamTrack *track,
                                    uint32_t ssrc, uint8_t payload_type);

bool start_rtp_session(struct RtpSession *rtpSession);
bool start_rtp_stream(struct RtpStream *rtpStream);
int get_udp_sock_desc();
// void send_rtp_packet(struct RtpStream *rtpStream, char *payload, int
// payload_size);

#endif
