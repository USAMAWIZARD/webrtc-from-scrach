#include "../ICE/ice.h"
#include "../SDP/sdp.h"
#include "../WebRTC/webrtc.h"
#include "libsoup/soup-types.h"
#include <glib.h>
#include <json-glib/json-glib.h>
#include <libsoup/soup.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

const gchar *peer_pair;
struct RTCPeerConnection *peer;
SoupWebsocketConnection *ws_conn;
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

static void on_message(SoupWebsocketConnection *conn, gint type,
                       GBytes *message, gpointer data) {
  printf("message\n");
  if (type == SOUP_WEBSOCKET_DATA_TEXT) {
    gsize sz;
    const gchar *ptr;
    ptr = g_bytes_get_data(message, &sz);

    g_print("Received : %s\n", ptr);

    JsonParser *json_parser = json_parser_new();
    JsonNode *root;
    JsonObject *object;
    gboolean is_parsed = json_parser_load_from_data(json_parser, ptr, -1, NULL);
    if (!is_parsed)
      return;

    root = json_parser_get_root(json_parser);
    object = json_node_get_object(root);
    const gchar *command = json_object_get_string_member(object, "command");
    if (strcmp(command, "start") == 0) {

      peer_pair = json_object_get_string_member(object, "peer");
      peer = NEW_RTCPeerConnection();
      peer->on_ice_candidate = &on_ice_candidate;

      struct MediaStreamTrack *video_track =
          NEW_MediaTrack("video", "video NEW_MediaTrack", NULL, NULL);
      add_track(peer, video_track);

      JsonObject *offer_message = json_object_new();
      json_object_set_object_member(offer_message, "offer", get_test_ofer());

      json_object_set_string_member(offer_message, "command", "offer");
      json_object_set_string_member(offer_message, "peer", peer_pair);

      char *str_offer_message = get_string_from_json_object(offer_message);
      printf("%s\n", str_offer_message);

      soup_websocket_connection_send_text(conn, str_offer_message);
      //create_offer(peer);

      set_local_description(peer, NULL);

    } else if (strcmp(command, "answer") == 0) {

    } else if (strcmp(command, "candidate") == 0) {
      JsonObject *candidate_obj =
          json_object_get_object_member(object, "candidate");
      struct RTCIecCandidates *remote_candidate = NULL;

      if (candidate_obj != NULL) {
        remote_candidate = calloc(1,sizeof(struct RTCIecCandidates));
        remote_candidate->candidate =
            (char *)json_object_get_string_member(candidate_obj, "candidate");
        remote_candidate->sdpMid =
            atoi(json_object_get_string_member(candidate_obj, "sdpMid"));
      }
      add_ice_candidate(peer, remote_candidate);
    }
  }
}

static void on_close(SoupWebsocketConnection *conn, gpointer data) {
  soup_websocket_connection_close(conn, SOUP_WEBSOCKET_CLOSE_NORMAL, NULL);
  g_print("WebSocket connection closed\n");
}

static void on_connection(SoupSession *session, GAsyncResult *res,
                          gpointer data) {

  SoupWebsocketConnection *conn;
  GError *error = NULL;

  conn = soup_session_websocket_connect_finish(session, res, &error);
  if (error) {
    g_print("Error: %s\n", error->message);
    g_error_free(error);
    return;
  }
  ws_conn = conn;
  g_signal_connect(conn, "message", G_CALLBACK(on_message), NULL);
  g_signal_connect(conn, "closed", G_CALLBACK(on_close), NULL);

  printf("websocket connectet\n");
}

void websocket_connect(char *ip, int port) {

  gchar *uri = NULL;
  SoupMessage *msg;
  SoupSession *session;
  session = soup_session_new();
  uri = g_strdup_printf("%s://%s:%d", "ws", ip, port);
  msg = soup_message_new(SOUP_METHOD_GET, uri);
  g_free(uri);
  char *wsproto = "echo-protocol";

  soup_session_websocket_connect_async(
      session, msg, NULL, NULL, NULL, (GAsyncReadyCallback)on_connection, NULL);
}
