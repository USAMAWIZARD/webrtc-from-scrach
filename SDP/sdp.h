#include "../WebRTC/webrtc.h"
#include <json-glib/json-glib.h>
#ifndef _SDPH_
#define _SDPH_
struct RTCSessionDescription{
  char *type;
  char *sdp;
};

JsonObject *get_test_ofer();
char *get_sdp_constants();
char *generate_unmached_desc(struct RTCRtpTransceivers *transceiver);

#endif // !_SDPH_
