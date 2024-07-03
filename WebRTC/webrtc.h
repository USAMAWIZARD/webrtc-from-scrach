#include <stdbool.h>

#ifndef _WEBRTCH_
#define _WEBRTCH_

#define  SEND_ONLY "sendonly"
#define RECV_ONLY "recvonly"
#define SEND_RECV "sendrecv"

enum RTC_CONNECTION_STATE {
  PEER_CONNECTION_NEW,
  PEER_CONNECTION_CONNECTING,
  PEER_CONNECTED,
  PEER_DISCONNECTED,
  PEER_CLOSED
};

struct RTCPeerConnection {
  char *connection_state;
  struct RTCSessionDescription *current_local_desc;
  struct RTCSessionDescription *current_remote_desc;
  char *ice_connection_state;
  char *signalling_state;
  struct MediaStreamTrack *media_tracks;
  struct RTCRtpTransceivers *transceiver;
};

struct MediaStreamTrack {
  char *kind;
  char *label;
  bool *muted;
  void *get_data_callback;
  int id;
  void *userdata;
  struct MediaStreamTrack *next_track;
  struct RtpStream *rtp_stream; 
};
struct RTCRtpSender{
   
  struct RtpStream *transport;
};

struct RTCRtpTransceivers{
  char *currentDirection;
  char *direction;
  char *mid;
  struct RtpStream *sender;
  struct RtpStream *recvier;
  bool stoped;
  struct RTCRtpTransceivers *next_trans;
};

struct RTCPeerConnection *NEW_RTCPeerConnection();

bool add_track(struct RTCPeerConnection *peer,struct MediaStreamTrack *track);

struct RTCSessionDescription *create_offer(struct RTCPeerConnection *peer);
struct MediaStreamTrack *NEW_MediaTrack(char *kind, char *label,
                                        void *get_data_callback,
                                        void *userdata);
 struct RTCRtpTransceivers *add_transceivers(struct RTCPeerConnection *peer,struct MediaStreamTrack *track);


#endif
