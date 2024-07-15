#include "../WebRTC/webrtc.h"
#include "stdbool.h"
#include <glib.h>
#include <json-glib/json-glib.h>
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
struct RTCIecCandidates {
  char *address;
  char *candidate;
  int component_id;
  int foundation;
  int port;
  int priority;
  char *transport;
  int sdpMid;
  char *type;
  char *raddr;
  int rport;
  char *uuid;
  struct RTCIecCandidates *next_candidate;
};

struct CandidataPair {
  struct RTCIecCandidates *p0;
  struct RTCIecCandidates *p1;
  int id;
  char *state;
  bool isvalid;
  int request_sent_count;
  struct CandidataPair *next_pair;
};

void gather_ice_candidate(struct RTCPeerConnection *peer);
bool parse_ice_candidate(struct RTCIecCandidates *candidate);
void listen_for_ice_handshake(struct RTCIecCandidates *local_candidate);
guint do_ice_handshake(struct args *arg);
void add_candidate_for_each_transiver(struct RTCPeerConnection *peer,
                                      struct RTCIecCandidates *candidate);
void ice_handshake_ended(struct RTCIecCandidates *local_candidate,
                         struct RTCIecCandidates *remote_candidate);
struct RTCRtpTransceivers *get_transceiver(struct RTCRtpTransceivers *trans,
                                           int mid);

#endif // !_ICEH_
