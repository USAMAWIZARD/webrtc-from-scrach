#include "../WebRTC/webrtc.h"
#include <json-glib/json-glib.h>
#ifndef _SDPH_
#define _SDPH_
struct RTCSessionDescription {
  char *type;
  char *sdp;
};

JsonObject *get_test_ofer();
char *get_sdp_constants();
char *generate_unmached_desc(struct RTCRtpTransceivers *transceiver);
bool parse_sdp_string(struct RTCPeerConnection *peer,
                      struct RTCSessionDescription *sdp);
JsonObject *sdp_to_json_object(struct RTCSessionDescription *sdp);
struct RTCSessionDescription *json_object_to_sdp(JsonObject *sdp_json);
#endif // !_SDPH_
