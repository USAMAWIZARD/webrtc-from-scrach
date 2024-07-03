#include <glib.h>
#include <json-glib/json-glib.h>
#include <libsoup/soup.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
const gchar *peer;
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
static void on_message(SoupWebsocketConnection *conn, gint type,
                       GBytes *message, gpointer data) {
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

      peer = json_object_get_string_member(object, "peer");

      JsonObject *offer_message = json_object_new();
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
          "a=ice-pwd:HXeKrqNxtoH7MLYV/gQXytWJ\n"
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

      json_object_set_string_member(offer_message, "command", "offer");
      json_object_set_string_member(offer_message, "peer", peer);
      JsonObject *sdp_object = json_object_new();

      json_object_set_string_member(sdp_object, "sdp", sdp);
      json_object_set_string_member(sdp_object, "type", "offer");
      json_object_set_object_member(offer_message, "offer", sdp_object);

      char *str_offer_message = get_string_from_json_object(offer_message);
      printf("%s\n", str_offer_message);
      soup_websocket_connection_send_text(conn, str_offer_message);
    } else if (strcmp(command, "answer")) {

    } else if (strcmp(command, "candidate")) {
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
