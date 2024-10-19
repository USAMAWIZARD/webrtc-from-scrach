#include "./ICE/ice.h"
#include "./Network/network.h"
#include "./RTP/rtp.h"
#include "./SDP/sdp.h"
#include "./SignallingClient/signalling_client.h"
#include "./Utils/utils.h"
#include "./WebRTC/webrtc.h"
#include "./parser/h264_parser/h264_parser.h"
#include "json-glib/json-glib.h"
#include <glib.h>
#include <libavcodec/avcodec.h>
#include <libavcodec/codec.h>
#include <libavcodec/codec_par.h>
#include <libavcodec/packet.h>
#include <libavformat/avformat.h>
#include <libsoup/soup.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

struct RTCPeerConnection *peer;
SoupWebsocketConnection *ws_conn;
const gchar *peer_pair;

static gchar *get_string_from_json_object(JsonObject *object) {
  JsonNode *root;
  JsonGenerator *generator;
  gchar *text;
  /* Make it the root node */
  root = json_node_init_object(json_node_alloc(), object);
  generator = json_generator_new();
  json_generator_set_root(generator, root);
  text = json_generator_to_data(generator, NULL);

  /* Release everything */
  g_object_unref(generator);
  json_node_free(root);
  return text;
}

extern FILE *fptr;
void user_defined_read_data(char *file_name,
                            void(send_rtp_packet)(struct RtpStream *,
                                                  unsigned char *, int),
                            struct RtpStream *rtpStream) {

  AVFormatContext *ctx = avformat_alloc_context();
  if (avformat_open_input(&ctx, file_name, NULL, NULL)) {
    exit(0);
  }
  avformat_find_stream_info(ctx, NULL);

  AVCodecParameters *codec_par = ctx->streams[0]->codecpar;

  AVCodec *dec = avcodec_find_decoder(codec_par->codec_id);

  AVCodecContext *codec_ctx = avcodec_alloc_context3(dec);
  avcodec_parameters_to_context(codec_ctx, codec_par);
  avcodec_open2(codec_ctx, dec, NULL);

  AVPacket *pkt = av_packet_alloc();

  fptr = fopen("sample.h264", "rb");
  g_assert(fptr);

  while (av_read_frame(ctx, pkt) >= 0) {
    static int i = 1;
    h264_parser_get_nal_unit(pkt->data, pkt->size, send_rtp_packet, rtpStream);
    rtpStream->timestamp += 3000;

    // if(i==4)
    // exit(0);
    //
    // i++;
  }
}
void on_ice_candidate(struct RTCPeerConnection *peer,
                      struct RTCIecCandidates *candidate) {

  JsonObject *candidate_message = json_object_new();
  json_object_set_string_member(candidate_message, "command", "candidate");
  json_object_set_string_member(candidate_message, "peer", peer_pair);

  JsonObject *candidate_obj = NULL;
  if (candidate != NULL) {

    candidate_obj = json_object_new();
    json_object_set_string_member(candidate_obj, "candidate",
                                  candidate->candidate);
    char *sdpmid = g_strdup_printf("%d", candidate->sdpMid);
    json_object_set_string_member(candidate_obj, "sdpMid", sdpmid);
    json_object_set_int_member(candidate_obj, "sdpMLineIndex", 0);
  }

  json_object_set_object_member(candidate_message, "candidate", candidate_obj);

  char *candidate_message_str = get_string_from_json_object(candidate_message);
  printf("send %s\n", candidate_message_str);
  soup_websocket_connection_send_text(ws_conn, candidate_message_str);
}
void on_remote_ice_candidate(JsonObject *object, const gchar *webrtcbin_id) {

  struct RTCIecCandidates *remote_candidate = NULL;

  if (object != NULL) {
    remote_candidate = calloc(1, sizeof(struct RTCIecCandidates));
    remote_candidate->candidate =
        (char *)json_object_get_string_member(object, "candidate");
    remote_candidate->sdpMid =
        atoi(json_object_get_string_member(object, "sdpMid"));
  }
  add_ice_candidate(peer, remote_candidate);
}
void on_remote_description(JsonObject *object, const gchar *type,
                           const gchar *webrtcbin_id) {

  gchar *sdp_string = (gchar *)json_object_get_string_member(object, "sdp");

  if (strncmp(type, "answer", 6) == 0) {

    struct RTCSessionDescription *session_desc = json_object_to_sdp(object);
    if (session_desc == NULL) {
      printf("invalid sdp");
      return;
    }
    set_remote_discription(peer, session_desc);
  }
  if (strncmp(type, "offer", 5)) {
  }
}

void on_websocket_connected(SoupWebsocketConnection *conn) { ws_conn = conn; }

void on_websocket_disconnected(SoupWebsocketConnection *conn) {
  printf("websocket disconected");
  exit(0);
}

void on_start(JsonObject *object) {
  if (ws_conn == NULL) {
    printf("websocket is not connected");
    return;
  }

  peer_pair = json_object_get_string_member(object, "peer");
  peer = NEW_RTCPeerConnection();
  peer->bundle_policy = BUNDLE_MAX_BUNDLE;
  peer->on_ice_candidate = &on_ice_candidate;

  struct MediaStreamTrack *video_track =
      NEW_MediaTrack("video", "video NEW_MediaTrack", &user_defined_read_data,
                     "./sample.h264");
  add_track(peer, video_track);

  JsonObject *offer_message = json_object_new();
  JsonObject *sdp = get_test_ofer();
  json_object_set_object_member(offer_message, "offer", sdp);

  json_object_set_string_member(offer_message, "command", "offer");
  json_object_set_string_member(offer_message, "peer", peer_pair);

  char *str_offer_message = get_string_from_json_object(offer_message);
  printf("%s\n", str_offer_message);

  soup_websocket_connection_send_text(ws_conn, str_offer_message);
  // create_offer(peer);
  struct RTCSessionDescription *local_sdp = json_object_to_sdp(sdp);

  set_local_description(peer, local_sdp);
}

gint main(gint argc, gchar **argv) {

  static GMainLoop *main_loop;
  //  struct RtpSession *rtpSession = create_rtp_session();
  // char *loopback_ip = "127.0.0.1";
  // void *filePtr = fopen("./sample.h264", "rb");
  // if (filePtr == NULL) {
  //   printf("file not found ");
  // }

  // struct MediaStreamTrack *video_track = NEW_MediaTrack(
  //     "video", "video_1", &user_defined_read_data, "sample.h264");
  // struct RtpStream *rtpStream = create_rtp_stream(NULL, video_track, 1244,
  // 98); struct CandidataPair *pair = malloc(sizeof(struct CandidataPair));
  // pair->p0 = malloc(sizeof(struct RTCIecCandidates));
  // pair->p1 = malloc(sizeof(struct RTCIecCandidates));
  // pair->p0->sock_desc = get_udp_sock_desc();
  // pair->p1->src_socket = get_network_socket("127.0.0.1", 5001);
  // init_rtp_stream(rtpStream, pair, NULL);
  // start_rtp_stream(rtpStream);

  websocket_connect("127.0.0.1", 3001);

  main_loop = g_main_loop_new(NULL, FALSE);
  g_main_loop_run(main_loop);
  g_main_loop_unref(main_loop);
}


