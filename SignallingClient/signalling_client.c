#include "signalling_client.h"
#include "libsoup/soup-types.h"
#include <glib.h>
#include <json-glib/json-glib.h>
#include <libsoup/soup.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern void on_websocket_connected(SoupWebsocketConnection *conn);
extern void on_websocket_disconnected(SoupWebsocketConnection *conn);
extern void on_start(JsonObject *object);
extern void on_remote_ice_candidate(JsonObject *object,
                                    const gchar *webrtcbin_id);
extern void on_remote_description(JsonObject *jsonobject, const gchar *type,
                                  const gchar *webrtcbin_id);

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
    const char *peerid = json_object_get_string_member(object, "peer");
    const gchar *command = json_object_get_string_member(object, "command");

    if (strcmp(command, "start") == 0) {
      on_start(object);
    } else if (strcmp(command, "answer") == 0 ||
               strcmp(command, "offer") == 0) {
      on_remote_description(json_object_get_object_member(object, command),
                            command, peerid);
    } else if (strcmp(command, "candidate") == 0) {
      on_remote_ice_candidate(
          json_object_get_object_member(object, "candidate"), peerid);
    }
  }
}

static void on_close(SoupWebsocketConnection *conn, gpointer data) {
  soup_websocket_connection_close(conn, SOUP_WEBSOCKET_CLOSE_NORMAL, NULL);
  on_websocket_disconnected(conn);
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
  on_websocket_connected(conn);
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

  soup_session_websocket_connect_async(
      session, msg, NULL, NULL, NULL, (GAsyncReadyCallback)on_connection, NULL);
}
