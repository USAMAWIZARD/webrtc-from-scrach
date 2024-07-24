#include "../WebRTC/webrtc.h"
#include "stdbool.h"
#include <glib.h>
#include <json-glib/json-glib.h>
#include <stdint.h>
#ifndef _ICEH_
#define _ICEH_

#define TRANSPORT_STATE_NEW "new"
#define TRANSPORT_STATE_CONNECTING "connecting"
#define TRANSPORT_STATE_CONNECTED "connected"
#define TRANSPORT_STATE_CLOSED "closed"
#define TRANSPORT_STATE_FAILED "failed"

#define ICE_NEW "new"
#define ICE_GATHRING "gathring"
#define ICE_COMPLEATE "complete"

#define ICE_PAIR_WAITING "waiting"       // check not sent
#define ICE_PAIR_INPROGRESS "inprogress" // check sent response not recived
#define ICE_PAIR_SUCCEEDED "succeeded"
#define ICE_PAIR_FAILED                                                        \
  "failed" // check sent no respose or unfavorable response
#define ICE_PAIR_FROZEN "frozen"

#define ICE_AGENT_CONTROLLING "controlling"
#define ICE_AGENT_CONROLLED "controlled"

#define HOST_CANDIDATE "host"
#define SRFLX_CANDIDATE "srflx"
#define PRFLX_CANDIDATE "prflx"
#define RELAY_CANDIDATE "relay"
struct RTCIecCandidates {
  char *address;
  char *candidate;
  int component_id;
  int foundation;
  int port;
  uint32_t priority;
  char *transport;
  int sdpMid;
  char *type;
  char *raddr;
  int rport;
  uint32_t id;
  int sock_desc;
  char *ufrag;
  char *password;
  struct sockaddr_in *src_socket;
  struct RTCIecCandidates *next_candidate;
};

struct CandidataPair {
  struct RTCIecCandidates *p0;
  struct RTCIecCandidates *p1;
  uint32_t xored_id;
  char *state;
  bool isvalid;
  uint32_t request_sent_count;
  uint32_t priority;
  struct CandidataPair *next_pair;
};

void gather_ice_candidate(struct RTCPeerConnection *peer);
bool parse_ice_candidate(struct RTCIecCandidates *candidate);
void listen_for_ice_handshake(struct RTCIecCandidates *local_candidate);
guint make_candidate_pair(struct args *arg);
void add_candidate_for_each_transiver(struct RTCPeerConnection *peer,
                                      struct RTCIecCandidates *candidate);

guint do_ice_handshake(struct RTCRtpTransceivers *transceiver);
void ice_handshake_ended(struct RTCIecCandidates *local_candidate,
                         struct RTCIecCandidates *remote_candidate);
struct RTCRtpTransceivers *get_transceiver(struct RTCRtpTransceivers *trans,
                                           int mid);
void add_local_icecandidate(struct RTCPeerConnection *peer,
                            struct RTCIecCandidates *candidate);
int get_type_pref(char *candidate_type);
#endif // !_ICEH_
