#pragma once
#ifndef _WEBRTCH_
#define _WEBRTCH_

#include "../DTLS/dtls.h"
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#define SEND_ONLY "sendonly"
#define RECV_ONLY "recvonly"
#define SEND_RECV "sendrecv"

#define BUNDLE_MAX_BUNDLE 1
#define BUNDLE_MAC_COMPAT 2
#define BUNDEL_BALANCED 3

enum RTC_CONNECTION_STATE {
  PEER_CONNECTION_NEW,
  PEER_CONNECTION_CONNECTING,
  PEER_CONNECTED,
  PEER_DISCONNECTED,
  PEER_CLOSED
};
enum RTC_SIGNALLING_STATE {
  STABLE,
  HAVE_LOCAL_OFFER,
  HAVE_LOCAL_ANSWER,
  HAVE_REMOTE_OFFER,
  HAVE_REMOTE_ANSWER
};
struct RTCPeerConnection {
  char *connection_state;
  pthread_t *listener_thread_id;
  struct RTCSessionDescription *current_local_desc;
  struct RTCSessionDescription *current_remote_desc;
  char *ice_connection_state;
  enum RTC_SIGNALLING_STATE signalling_state;
  struct MediaStreamTrack *media_tracks;
  struct RTCRtpTransceivers *transceiver;
  void *on_ice_candidate;
  char *ice_role;
  bool local_gathering_compleated;
  bool remote_gathering_compleated;
  int bundle_policy;
  struct RTCDtlsTransport *dtls_transport;
};

struct MediaStreamTrack {
  char *kind;
  char *label;
  bool *muted;
  void *get_data_callback;
  char *id;
  void *userdata;
  struct MediaStreamTrack *next_track;
  struct RtpStream *rtp_stream;
};

struct Transport {
  struct RtpStream *rtp_stream;
  struct RtpStream *rtcp_stream;
  struct MediaStreamTrack *track;
  char *state;
};

struct RTCRtpTransceivers {
  struct RTCIecCandidates *local_ice_candidate;
  struct RTCIecCandidates *remote_ice_candidate;
  struct CandidataPair *pair_checklist;
  char *currentDirection;
  char *direction;
  int mid;
  struct Transport *sender;
  struct Transport *recvier;
  char *local_ice_ufrag;
  char *remote_ice_ufrag;
  char *local_ice_password;
  char *remote_ice_password;
  bool stoped;
  bool handshake_sending_started;
  struct RTCRtpTransceivers *next_trans;
};

struct args {
  struct RTCRtpTransceivers *transceiver;
  struct RTCIecCandidates *candidate;
};

struct RTCPeerConnection *NEW_RTCPeerConnection();

bool add_track(struct RTCPeerConnection *peer, struct MediaStreamTrack *track);

struct RTCSessionDescription *create_offer(struct RTCPeerConnection *peer);
struct MediaStreamTrack *NEW_MediaTrack(char *kind, char *label,
                                        void *get_data_callback,
                                        void *userdata);
struct RTCRtpTransceivers *add_transceivers(struct RTCPeerConnection *peer,
                                            struct MediaStreamTrack *track);

void set_local_description(struct RTCPeerConnection *peer,
                           struct RTCSessionDescription *sdp);
bool set_remote_discription(struct RTCPeerConnection *peer,
                            struct RTCSessionDescription *sdp);

void add_ice_candidate(struct RTCPeerConnection *peer,
                       struct RTCIecCandidates *candidate);

#endif
