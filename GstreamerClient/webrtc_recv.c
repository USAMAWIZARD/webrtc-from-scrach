#include "glib-object.h"
#include "gst/gstbin.h"
#include "gst/gstelement.h"
#include "gst/gstpromise.h"
#include <stdbool.h>
#include <string.h>
#if __APPLE__
#define VIDEO_SINK "osxaudiosink"
#else
#define VIDEO_SINK "autovideosink"
#endif
#define GST_USE_UNSTABLE_API
#define STUN_SERVER "stun://stun.l.google.com:19302"
#define TURN_SERVER ""
#define AUDIO_ENCODE                                                           \
  "  ! audioconvert ! audioresample   ! opusenc bitrate=192000  ! rtpopuspay "
#define VIDEO_ENCODE                                                           \
  " ! timeoverlay time-mode=2 halignment=right valignment=bottom   ! "         \
  "videoconvert ! video/x-raw,format=I420 ! x264enc  speed-preset=3 "          \
  "tune=zerolatency ! rtph264pay "
#define RTP_CAPS_H264                                                          \
  " application/"                                                              \
  "x-rtp,media=video,encoding-name=H264,payload=96,clock-rate=90000 "
#define RTP_CAPS_OPUS                                                          \
  " application/x-rtp,media=audio,encoding-name=OPUS,payload=97 "

#include "../SignallingClient/signalling_client.h"
#include <glib.h>
#include <gst/gst.h>
#include <gst/webrtc/webrtc.h>
#include <json-glib/json-glib.h>
#include <libsoup/soup.h>
#include <stdio.h>
#include <stdlib.h>

gboolean is_joined = FALSE;
gchar *myid;
GstElement *gst_pipe;
static gchar *ws_server_addr = "";
static gint ws_server_port = 3001;
static SoupWebsocketConnection *ws_conn = NULL;
gchar *mode = "publish";
gchar **play_streamids = NULL;
gchar *filename = "";
gchar *stream_token = NULL;

static GOptionEntry entries[] = {
    {"ip", 's', 0, G_OPTION_ARG_STRING, &ws_server_addr,
     "ip address of websocket server", NULL},
    {"port", 'p', 0, G_OPTION_ARG_INT, &ws_server_port,
     "WebSocket server Port default : 5080", NULL},
    {"filename", 'f', 0, G_OPTION_ARG_STRING, &filename,
     "specify file path which you want to stream", NULL},
    {"streamids", 'i', 0, G_OPTION_ARG_STRING_ARRAY, &play_streamids,
     "you can pass n number of streamid to play like this -i streamid -i "
     "streamid ....",
     NULL},
    {NULL}};

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
static void on_answer_created(GstPromise *promise, gpointer webrtcbin_id) {
  gchar *sdp_text;
  JsonObject *sdp_answer_json;
  GstWebRTCSessionDescription *answer = NULL;
  const GstStructure *reply;
  GstElement *webrtc;
  g_assert_cmphex(gst_promise_wait(promise), ==, GST_PROMISE_RESULT_REPLIED);
  reply = gst_promise_get_reply(promise);
  gst_structure_get(reply, "answer", GST_TYPE_WEBRTC_SESSION_DESCRIPTION,
                    &answer, NULL);
  gst_promise_unref(promise);
  promise = gst_promise_new();
  webrtc = gst_bin_get_by_name(GST_BIN(gst_pipe), (gchar *)webrtcbin_id);
  g_signal_emit_by_name(webrtc, "set-local-description", answer, promise);
  gst_promise_interrupt(promise);
  gst_promise_unref(promise);

  /* Send answer to peer */
  sdp_text = gst_sdp_message_as_text(answer->sdp);
  printf("answer : %s", sdp_text);

  JsonObject *sdp_json_info = json_object_new();
  json_object_set_string_member(sdp_json_info, "peer", myid);
  json_object_set_string_member(sdp_json_info, "command", "answer");

  sdp_answer_json = json_object_new();
  json_object_set_string_member(sdp_answer_json, "sdp", sdp_text);
  json_object_set_string_member(sdp_answer_json, "type", "answer");

  json_object_set_object_member(sdp_json_info, "answer", sdp_answer_json);

  sdp_text = get_string_from_json_object(sdp_json_info);
  soup_websocket_connection_send_text(ws_conn, sdp_text);

  gst_webrtc_session_description_free(answer);
}

static void send_ice_candidate_message(GstElement *webrtcbin, guint mline_index,
                                       gchar *candidate, gpointer streamid) {
  gchar *json_string;
  char *mid;
  mid = g_strdup_printf("%d", mline_index);
  JsonObject *candidate_info = json_object_new();

  json_object_set_string_member(candidate_info, "peer", myid);
  json_object_set_string_member(candidate_info, "command", "candidate");

  JsonObject *candidate_json = json_object_new();
  json_object_set_string_member(candidate_json, "candidate", candidate);
  json_object_set_string_member(candidate_json, "sdpMid", mid);

  json_object_set_object_member(candidate_info, "candidate", candidate_json);

  json_string = get_string_from_json_object(candidate_info);
  soup_websocket_connection_send_text(ws_conn, json_string);

  json_object_unref(candidate_info);
  g_free(json_string);
}
static void handle_media_stream(GstPad *pad, GstElement *gst_pipe,
                                gchar *convert_name, char *sink_name) {
  GstPad *qpad;
  GstElement *q, *conv, *resample, *sink, *toverlay;
  GstPadLinkReturn ret;

  g_print("Trying to handle stream with %s ! %s ", convert_name, sink_name);
  q = gst_element_factory_make("queue", NULL);
  sink = gst_element_factory_make(sink_name, NULL);
  g_object_set(G_OBJECT(sink), "sync", FALSE, NULL);
  conv = gst_element_factory_make(convert_name, NULL);

  if (g_strcmp0(convert_name, "audioconvert") == 0) {
    g_print("audio stream");
    resample = gst_element_factory_make("audioresample", NULL);
    gst_bin_add_many(GST_BIN(gst_pipe), q, conv, resample, sink, NULL);
    gst_element_sync_state_with_parent(q);
    gst_element_sync_state_with_parent(sink);
    gst_element_sync_state_with_parent(resample);
    gst_element_sync_state_with_parent(conv);
    gst_element_link_many(q, conv, resample, sink, NULL);
  } else {
    g_print("video stream");
    toverlay = gst_element_factory_make("timeoverlay", NULL);
    gst_bin_add_many(GST_BIN(gst_pipe), q, conv, toverlay, sink, NULL);
    gst_element_sync_state_with_parent(q);
    gst_element_sync_state_with_parent(conv);
    gst_element_sync_state_with_parent(sink);
    gst_element_sync_state_with_parent(toverlay);
    gst_element_link_many(q, conv, toverlay, sink, NULL);
  }
  qpad = gst_element_get_static_pad(q, "sink");
  ret = gst_pad_link(pad, qpad);
  g_assert_cmphex(ret, ==, GST_PAD_LINK_OK);
}
void on_incoming_stream(GstElement *webrtc, GstPad *pad) {
  GstElement *decode, *depay, *parse, *rtpjitterbuffer;
  GstPad *sinkpad, *srcpad, *decoded_pad;
  GstCaps *caps;
  const gchar *mediatype;
  gchar *convert_name, *sink_name;

  caps = gst_pad_get_current_caps(pad);
  mediatype =
      gst_structure_get_string(gst_caps_get_structure(caps, 0), "media");
  printf("--------------------------%s stream recived "
         "----------------------------------",
         mediatype);

  if (g_str_has_prefix(mediatype, "video")) {
    decode = gst_element_factory_make("avdec_h264", NULL);
    depay = gst_element_factory_make("rtph264depay", NULL);
    parse = gst_element_factory_make("h264parse", NULL);
    convert_name = "videoconvert";
    sink_name = VIDEO_SINK;
  } else if (g_str_has_prefix(mediatype, "audio")) {
    decode = gst_element_factory_make("opusdec", NULL);
    depay = gst_element_factory_make("rtpopusdepay", NULL);
    parse = gst_element_factory_make("opusparse", NULL);
    convert_name = "audioconvert";
    sink_name = "autoaudiosink";
  } else {
    g_printerr("Unknown pad %s, ignoring", GST_PAD_NAME(pad));
  }

  rtpjitterbuffer = gst_element_factory_make("rtpjitterbuffer", NULL);
  gst_bin_add_many(GST_BIN(gst_pipe), rtpjitterbuffer, depay, parse, decode,
                   NULL);
  sinkpad = gst_element_get_static_pad(rtpjitterbuffer, "sink");
  g_assert(gst_pad_link(pad, sinkpad) == GST_PAD_LINK_OK);
  gst_element_link_many(rtpjitterbuffer, depay, parse, decode, NULL);
  decoded_pad = gst_element_get_static_pad(decode, "src");
  gst_element_sync_state_with_parent(depay);
  gst_element_sync_state_with_parent(parse);
  gst_element_sync_state_with_parent(decode);
  gst_element_sync_state_with_parent(rtpjitterbuffer);

  handle_media_stream(decoded_pad, gst_pipe, convert_name, sink_name);
}
static void on_offer_created(GstPromise *promise, const gchar *stream_id) {
  GstWebRTCSessionDescription *offer = NULL;
  const GstStructure *reply;
  gchar *sdp_string;
  GstPad *sinkpad, *srcpad;

  reply = gst_promise_get_reply(promise);
  GstElement *webrtc;
  webrtc = gst_bin_get_by_name(GST_BIN(gst_pipe), myid);
  g_assert_nonnull(webrtc);
  gst_structure_get(reply, "offer", GST_TYPE_WEBRTC_SESSION_DESCRIPTION, &offer,
                    NULL);
  gst_promise_unref(promise);
  g_signal_emit_by_name(webrtc, "set-local-description", offer, NULL);
  sdp_string = gst_sdp_message_as_text(offer->sdp);

  g_print(" offer created:\n%s\n", sdp_string);
  gchar *json_string;
  JsonObject *offer_info;
  offer_info = json_object_new();
  json_object_set_string_member(offer_info, "command", "offer");
  json_object_set_string_member(offer_info, "peer", myid);

  JsonObject *offer_json = json_object_new();
  json_object_set_string_member(offer_json, "type", "offer");
  json_object_set_string_member(offer_json, "sdp", sdp_string);

  json_string = get_string_from_json_object(offer_info);

  g_print("sending offer to %s", stream_id);
  printf("\n%s\n", json_string);
  soup_websocket_connection_send_text(ws_conn, json_string);
  gst_webrtc_session_description_free(offer);
}

static void on_negotiation_needed(GstElement *webrtc, gpointer user_data) {
  GstPromise *promise;
  g_print("negotiation  needed");
  gchar *to = gst_element_get_name(webrtc);
  promise = gst_promise_new_with_change_func(
      (GstPromiseChangeFunc)on_offer_created, (gpointer)to, NULL);
  g_signal_emit_by_name(webrtc, "create-offer", NULL, promise);
}

static void on_key_set(GstElement *element, gpointer *udata) {}
static void dtls_element_added(GstBin *webrtcbin, GstBin subbin,
                               GstElement *element, gpointer *data) {
  gchar *element_name = gst_element_get_name(element);
  printf("\nelement Name -----%s\n", element_name);

  if (strncmp(element_name, "dtlssrt", 6) == 0) {
  }
}

static void create_webrtc(const gchar *webrtcbin_id, gboolean send_offer) {

  GstElement *tee, *audio_q, *video_q, *webrtc;
  GstPad *sinkpad, *srcpad;
  GstPadLinkReturn ret;
  printf("\ncreated webrtc bin with id %s \n", webrtcbin_id);
  webrtc = gst_element_factory_make("webrtcbin", webrtcbin_id);
  g_signal_connect(webrtc, "deep-element-added", G_CALLBACK(dtls_element_added),
                   NULL);

  GST_IS_ELEMENT(webrtc);

  g_object_set(G_OBJECT(webrtc), "bundle-policy",
               GST_WEBRTC_BUNDLE_POLICY_MAX_BUNDLE, NULL);
  // g_object_set(G_OBJECT(webrtc), "turn-server", TURN_SERVER, NULL);
  g_object_set(G_OBJECT(webrtc), "stun-server", STUN_SERVER, NULL);
  gst_bin_add_many(GST_BIN(gst_pipe), webrtc, NULL);

  video_q = gst_element_factory_make("queue", NULL);
  gst_bin_add_many(GST_BIN(gst_pipe), video_q, NULL);
  srcpad = gst_element_get_static_pad(video_q, "src");
  g_assert_nonnull(srcpad);
  sinkpad = gst_element_request_pad_simple(
      webrtc, "sink_%u"); // linking video to webrtc element
  g_assert_nonnull(sinkpad);
  ret = gst_pad_link(srcpad, sinkpad);
  g_assert_cmpint(ret, ==, GST_PAD_LINK_OK);
  gst_object_unref(srcpad);
  gst_object_unref(sinkpad);

  tee = gst_bin_get_by_name(GST_BIN(gst_pipe), "video_tee");
  g_assert_nonnull(tee);
  srcpad = gst_element_request_pad_simple(
      tee, "src_%u"); // linking video to webrtc element
  g_assert_nonnull(srcpad);
  sinkpad = gst_element_get_static_pad(video_q, "sink");
  g_assert_nonnull(sinkpad);
  ret = gst_pad_link(srcpad, sinkpad);
  g_assert_cmpint(ret, ==, GST_PAD_LINK_OK);
  gst_object_unref(srcpad);
  gst_object_unref(sinkpad);

  audio_q = gst_element_factory_make("queue", NULL);
  gst_bin_add_many(GST_BIN(gst_pipe), audio_q, NULL);
  srcpad = gst_element_get_static_pad(audio_q, "src");
  g_assert_nonnull(srcpad);
  sinkpad = gst_element_request_pad_simple(
      webrtc, "sink_%u"); // linking audio to webrtc element
  g_assert_nonnull(sinkpad);
  ret = gst_pad_link(srcpad, sinkpad);
  g_assert_cmpint(ret, ==, GST_PAD_LINK_OK);
  gst_object_unref(srcpad);
  gst_object_unref(sinkpad);

  tee = gst_bin_get_by_name(GST_BIN(gst_pipe), "audio_tee");
  g_assert_nonnull(tee);
  srcpad = gst_element_request_pad_simple(
      tee, "src_%u"); // linking audio to webrtc element
  g_assert_nonnull(srcpad);
  sinkpad = gst_element_get_static_pad(audio_q, "sink");
  g_assert_nonnull(sinkpad);
  ret = gst_pad_link(srcpad, sinkpad);
  g_assert_cmpint(ret, ==, GST_PAD_LINK_OK);
  gst_object_unref(srcpad);
  gst_object_unref(sinkpad);

  g_signal_connect(webrtc, "on-ice-candidate",
                   G_CALLBACK(send_ice_candidate_message),
                   (gpointer)webrtcbin_id);
  if (send_offer)
    g_signal_connect(webrtc, "on-negotiation-needed",
                     G_CALLBACK(on_negotiation_needed), (gpointer)NULL);
  g_signal_connect(webrtc, "pad-added", G_CALLBACK(on_incoming_stream), NULL);

  ret = gst_element_sync_state_with_parent(audio_q);
  g_assert_true(ret);
  ret = gst_element_sync_state_with_parent(video_q);
  g_assert_true(ret);
  ret = gst_element_sync_state_with_parent(webrtc);
  g_assert_true(ret);
}

void on_websocket_disconnected(SoupWebsocketConnection *conn) {
  g_print("WebSocket connection closed\n");
}

void on_websocket_connected(SoupWebsocketConnection *conn) {
  ws_conn = conn;
  printf("websocket connected");
  gchar *json_string;
  JsonArray *array = json_array_new();
  gchar pipeline_str[1000];

  if (g_strcmp0(filename, "") == 0) {
    printf("test video sharing");
    gst_pipe = gst_parse_launch(
        " tee name=video_tee ! queue ! fakesink  sync=true  tee name=audio_tee "
        "! queue ! fakesink sync=true videotestsrc is-live=true " VIDEO_ENCODE
        " ! " RTP_CAPS_H264 " !  queue ! video_tee. audiotestsrc  is-live=true "
        "wave=red-noise " AUDIO_ENCODE " ! " RTP_CAPS_OPUS
        " !  queue ! audio_tee. ",
        NULL);
  } else {
    printf("file  sharing");
    sprintf(pipeline_str,
            " tee name=video_tee ! queue ! fakesink  sync=true  tee "
            "name=audio_tee ! queue ! fakesink sync=true filesrc location=%s  "
            "! qtdemux name=demuxtee  demuxtee. ! decodebin " VIDEO_ENCODE
            " ! " RTP_CAPS_H264
            " !  queue ! video_tee. demuxtee. ! decodebin " AUDIO_ENCODE
            " ! " RTP_CAPS_OPUS " !  queue ! audio_tee. ",
            filename);
    gst_pipe = gst_parse_launch(pipeline_str, NULL);
  }
  gst_element_set_state(gst_pipe, GST_STATE_READY);
  gst_element_set_state(gst_pipe, GST_STATE_PLAYING);
}
void on_start(JsonObject *object) {
  myid = (gchar *)json_object_get_string_member(object, "peer");
}
void on_remote_description(JsonObject *jsonobject, const gchar *type,
                           const gchar *webrtcbin_id) {

  GstPromise *promise;
  GstElement *webrtc;
  GstWebRTCSessionDescription *sdp_object;
  GstSDPMessage *sdp_message;

  gchar *sdp_string = (gchar *)json_object_get_string_member(jsonobject, "sdp");

  int ret = gst_sdp_message_new(&sdp_message);
  g_assert_cmphex(ret, ==, GST_SDP_OK);

  ret = gst_sdp_message_parse_buffer((guint8 *)sdp_string, strlen(sdp_string),
                                     sdp_message);

  if (ret != GST_SDP_OK) {
    g_error("Could not parse SDP string\n");
    return;
  }

  if (g_strcmp0(type, "offer") == 0) {

    sdp_object = gst_webrtc_session_description_new(GST_WEBRTC_SDP_TYPE_OFFER,
                                                    sdp_message);
    create_webrtc(webrtcbin_id, FALSE);
    webrtc = gst_bin_get_by_name(GST_BIN(gst_pipe), webrtcbin_id);
    g_assert_nonnull(webrtc);

    sdp_object = gst_webrtc_session_description_new(GST_WEBRTC_SDP_TYPE_OFFER,
                                                    sdp_message);
    promise = gst_promise_new();
    g_signal_emit_by_name(webrtc, "set-remote-description", sdp_object,
                          promise);
    gst_promise_interrupt(promise);
    gst_promise_unref(promise);
    promise = gst_promise_new_with_change_func(on_answer_created,
                                               (gpointer *)webrtcbin_id, NULL);
    g_signal_emit_by_name(webrtc, "create-answer", NULL, promise);
  }
  if (g_strcmp0(type, "answer") == 0) {
    webrtc = gst_bin_get_by_name(GST_BIN(gst_pipe), webrtcbin_id);
    g_assert_nonnull(webrtc);

    sdp_object = gst_webrtc_session_description_new(GST_WEBRTC_SDP_TYPE_ANSWER,
                                                    sdp_message);
    promise = gst_promise_new();
    g_signal_emit_by_name(webrtc, "set-remote-description", sdp_object,
                          promise);
    gst_promise_interrupt(promise);
  }
}
void on_remote_ice_candidate(JsonObject *object, const gchar *webrtcbin_id) {
  GstElement *webrtc;
  gchar *candidate;
  int mid;
  if (object != NULL) {
    candidate = (gchar *)json_object_get_string_member(object, "candidate");
    char *mid_str = (gchar *)json_object_get_string_member(object, "sdpMid");
    mid = atoi(mid_str);
    g_print("ice %s %s\n", candidate, webrtcbin_id);
  }
  webrtc = gst_bin_get_by_name(GST_BIN(gst_pipe), webrtcbin_id);
  g_assert_nonnull(webrtc);
  g_signal_emit_by_name(webrtc, "add-ice-candidate", mid, candidate);
}

gint main(gint argc, gchar **argv) {
  static GMainLoop *main_loop;
  gst_init(&argc, &argv);

  GError *error = NULL;
  GOptionContext *context;

  context = g_option_context_new("- Gstreamer Client");
  g_option_context_add_main_entries(context, entries, NULL);
  if (!g_option_context_parse(context, &argc, &argv, &error)) {
    g_print("option parsing failed: %s\n", error->message);
    exit(1);
  }
  ws_server_addr = "127.0.0.1";
  if (g_strcmp0(ws_server_addr, "") == 0) {
    printf("please enter the ws server  ip address --ip IP_ADDRESS\n");
    exit(0);
  }

  printf("start %s  %d ", ws_server_addr, ws_server_port);

  main_loop = g_main_loop_new(NULL, FALSE);

  websocket_connect(ws_server_addr, ws_server_port);
  g_main_loop_run(main_loop);
  g_main_loop_unref(main_loop);
  return 0;
}
