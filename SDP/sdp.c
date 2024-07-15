
#include "./sdp.h"
#include "../WebRTC/webrtc.h"
#include "glib.h"
#include <json-glib/json-glib.h>
#include <stdio.h>
char *get_sdp_constants() {
  char *sdp_header = g_strdup_printf("v=0\n"
                                     "o=- %d 2 IN IP4 %s\ns=-\nt= 0 0\n"
                                     "a=group:BUNDLE 0\n"
                                     "a=msid-semantic: WMS\n",
                                     rand(), "127.0.0.1");
  return sdp_header;
}

char *get_ice_auth(struct RTCRtpTransceivers *transceiver) {
  char *ice_auth =
      g_strdup_printf("a=ice-ufrag:%s\n"
                      "a=ice-pwd:%s\n"
                      "a=ice_option:trickle\n",
                      transceiver->ice_ufrag, transceiver->ice_password);
  return ice_auth;
}

char *get_dtls_sdp_param(struct RTCRtpTransceivers *transceiver) {
  char *dtls_auth_param = g_strdup_printf("a=fingerprint:sha-256 %s\n"
                                          "a=setup:actpass\n",
                                          transceiver->dtls_fingeprint);
  return dtls_auth_param;
}
char *get_transceiver_info(struct RTCRtpTransceivers *transceiver) {

  char *transceiver_info = g_strdup_printf("a=mid:%d\n"
                                           "a=%s\n"
                                           "a=msid:- %s\n"
                                           "a=rtcp-mux\n"
                                           "a=rtcp-rsize\n",
                                           transceiver->mid, "sendrecv",
                                           transceiver->sender->track->id);

  return transceiver_info;
}
char *get_media_line(struct RTCRtpTransceivers *transceiver) {}
char *get_encoding_info(struct RTCRtpTransceivers *transceiver) {
  char *encoding_info = g_strdup_printf(
      "a=rtpmap:102 H264/90000\n"
      "a=fmtp:102 "
      "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id="
      "42001f\n"
      "a=rtpmap:103 rtx/90000\n"
      "a=fmtp:103 apt=102\n"
      "a=ssrc:1044859037 cname:Dp9Bc6LU+k7YLLrs\n"
      "a=ssrc:1044859037 msid:- %s\n",
      transceiver->sender->track->id);
  return encoding_info;
}

char *generate_unmached_desc(struct RTCRtpTransceivers *transceiver) {
  char *media_descriptions = "";
  while (transceiver != NULL) {
    if (transceiver->sender != NULL) {
      get_media_line(transceiver);
      get_ice_auth(transceiver);
      get_dtls_sdp_param(transceiver);
      get_encoding_info(transceiver);
    }
    transceiver = transceiver->next_trans;
  }

  return NULL;
}

JsonObject *get_test_ofer() {
  char *sdp =
      "v=0\n"
      "o=- 4395291772417888753 2 IN IP4 127.0.0.1\n"
      "s=-\n"
      "t=0 0\n"
      "a=group:BUNDLE 0\n"
      "a=msid-semantic: WMS\n"

      "m=video 9 UDP/TLS/RTP/SAVPF 102 103\n"
      "c=IN IP4 0.0.0.0\n"
      "a=rtcp:9 IN IP4 0.0.0.0\n"

      "a=ice-ufrag:H0Tz\n"
      "a=ice-pwd:HXeKrqNxtoH7MLYV/gQXytWJ\n" // this is used
      "a=ice-options:trickle\n"

      "a=fingerprint:sha-256 "
      "3C:4A:AA:DA:3A:F5:7F:B1:60:B2:1A:BB:59:20:22:DB:FC:44:FB:71:BB:88:"
      "6D:E5:"
      "BB:2E:C6:7F:6A:9E:0B:83\n"
      "a=setup:actpass\n"

      "a=mid:0\n"
      "a=sendrecv\n"
      "a=msid:- 665d1bfb-1759-44c8-92d4-c1b6aaad5892\n"
      "a=rtcp-mux\n"
      "a=rtcp-rsize\n"

      "a=rtpmap:102 H264/90000\n"
      "a=fmtp:102 "
      "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id="
      "42001f\n"
      "a=rtpmap:103 rtx/90000\n"
      "a=fmtp:103 apt=102\n"
      "a=ssrc:1044859037 cname:Dp9Bc6LU+k7YLLrs\n"
      "a=ssrc:1044859037 msid:- 665d1bfb-1759-44c8-92d4-c1b6aaad5892\n";

  JsonObject *sdp_object = json_object_new();

  json_object_set_string_member(sdp_object, "sdp", sdp);
  json_object_set_string_member(sdp_object, "type", "offer");
  return sdp_object;
}

void create_offer_sdp() {}

void create_answer_sdp() {}
