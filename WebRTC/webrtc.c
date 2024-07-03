#include "./webrtc.h"
#include "../ICE/ice.h"
#include "../SDP/sdp.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

struct RTCPeerConnection *NEW_RTCPeerConnection() {
  struct RTCPeerConnection *peer =
      (struct RTCPeerConnection *)calloc(1, sizeof(struct RTCPeerConnection));
  if (peer == NULL) {
    perror("Failed to allocate memory for RTCPeerConnection");
    return NULL;
  }
  return peer;
}

struct MediaStreamTrack *NEW_MediaTrack(char *kind, char *label,
                                        void *get_data_callback,
                                        void *userdata) {
  struct MediaStreamTrack *track =
      (struct MediaStreamTrack *)malloc(sizeof(struct MediaStreamTrack));
  track->get_data_callback = get_data_callback;
  track->kind = kind;
  track->label = label;
  track->next_track = NULL;
  track->id = random();
  track->userdata = userdata;
  return track;
}

bool add_track(struct RTCPeerConnection *peer, struct MediaStreamTrack *track) {
  if (peer->media_tracks == NULL) {
    peer->media_tracks = track;
    printf("New Track Added to WebRTC Session id:%d Kind: %s Label: %s\n",
           track->id, track->kind, track->label);
    add_transceivers(peer, peer->media_tracks);
  } else {
    peer->media_tracks->next_track = track;
  }
  return true;
}
struct RTCRtpTransceivers *add_transceivers(struct RTCPeerConnection *peer,
                                            struct MediaStreamTrack *track) {
  struct RTCRtpTransceivers *transceiver = peer->transceiver;

  if (transceiver == NULL) {
  new_trans:
    transceiver = malloc(sizeof(struct RTCRtpTransceivers));
  settrans:
    transceiver->mid = transceiver != NULL ? transceiver->mid + 1 : 0;
    transceiver->direction = SEND_RECV;
    transceiver->next_trans = NULL;
    //transceiver->sender = ;

  } else {
    while (transceiver != NULL) {
      transceiver = peer->transceiver;
      if (transceiver->sender == NULL) {
        goto settrans;
      }
      goto new_trans;
    }
  }
  return transceiver;
}

struct RTCSessionDescription *create_offer(struct RTCPeerConnection *peer) {
  struct RTCRtpTransceivers *transceiver = peer->transceiver;
  static char *offer_constants = "";
  while (transceiver != NULL) {

    transceiver = transceiver->next_trans;
  }
  return NULL;
}

struct RTCSessionDescription *
create_answer(struct RTCSessionDescription *peer) {

  return NULL;
}
void *set_local_description(struct RTCSessionDescription *peer) { return NULL; }
void *set_remote_discription(struct RTCSessionDescription *peer) {

  return NULL;
}
void *add_ice_candidates() { return NULL; }
void on_ice_candidate() {}
