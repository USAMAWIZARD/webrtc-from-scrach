#pragma once
#ifndef _DTLSH_
#define _DTLSH_

#include "../WebRTC/webrtc.h"
#include <glib.h>
#include <stdbool.h>
#include <stdint.h>

#define DTLS_1_2 0xfefd
#define DTLS_1_0 0xfeff

#define CIPHER_SUITE_LEN 1
#define TLS_RSA_WITH_AES_128_CBC_SHA 0x2f00 // big endian

#define SRTP_AES128_CM_HMAC_SHA1_80 0x0100

#define TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA255

#define SRTP_EXT 0x000e
#define SIGN_ALGO_EXT 0x000d
#define SESS_TICKET_EXT 0x0023
#define EXTEND_MASTER_SEC_EXT 0x0017
struct NetworkPacket;

enum DtlsState {
  DTLS_CONNECTION_STATE_NEW,
  DTLS_CONNECTION_STATE_CONNECTING,
  DTLS_CONNETION_STATE_CONNECTED,
  DTLS_CONNECTION_STATE_FAILED,
  DTLS_CONNECTION_STATE_CLOSED
};
enum DTLS_MODE {
  DTLS_ACTIVE, // only client is supported
  DTLS_ACTPASS
};
enum HandshakeType {
  hello_request = 0,
  client_hello,
  server_hello,
  hello_verify_request, // New field
  certificate = 11,
  server_key_exchange,
  certificate_request,
  server_hello_done,
  certificate_verify,
  client_key_exchange,
  finished = 255
};

struct RTCDtlsTransport {
  enum DTLS_MODE mode;
  char *fingerprint;
  enum DtlsState state;
  struct CandidataPair *pair;
  struct DtlsParsedPacket *last_dtl_packet;
  gchar *current_seq_no;
  uint16_t epoch;
  int cookie;
  int cookie_len;
  guchar random[32];
};

struct __attribute__((packed)) HandshakeHeader {
  uint8_t type : 8;
  uint32_t length : 24;
  uint16_t message_seq;
  uint32_t fragment_offset : 24;
  uint32_t fragment_length : 24;
};

struct __attribute__((packed)) DtlsHello {
  uint16_t client_version;
  gchar random[32];
  uint8_t session_id;
  uint8_t cookie_len;
  uint16_t cipher_suite_len;
  uint16_t cipher_suite[CIPHER_SUITE_LEN];
  uint8_t compression_method_len;
  uint8_t compression_method;
  uint16_t extention_len;
  uint16_t extentions[];
};
struct __attribute__((packed)) DtlsServerHello {
  uint16_t client_version;
  gchar random[32];
  uint8_t session_id;
  uint16_t cipher_suite;
  uint8_t compression_method;
  uint16_t extention_len;
  uint16_t extentions[];
};
struct __attribute__((packed)) Certificate {
  uint32_t certificate_len : 24;
  guchar *certificate[];
};

struct __attribute__((packed)) CertificateRequest {
  uint8_t certificate_types_count;
  uint8_t **certificate_types;
  uint16_t signature_hash_algo_len;
  uint16_t **signature_hash_algo;
  uint16_t distiguished_name_len;
};

struct __attribute__((packed)) HelloVerifyRequest {
  uint16_t server_version;
  uint16_t cookie_len;
};

struct __attribute__((packed)) DtlsHeader {
  uint8_t type;
  uint16_t version;
  uint16_t epoch;
  guchar sequence_number[6];
  uint16_t length;
};

struct __attribute__((packed)) dtls_ext {
  uint16_t type;
  uint16_t ext_length;
  guchar value[];
};

union ParsedHandshakePayload {
  struct DtlsServerHello *hello;
  struct Certificate *certificate;
};

struct DtlsParsedPacket {
  bool isfragmented;
  uint8_t handshake_type;
  uint32_t fragment_length : 24;
  uint32_t fragment_offset : 24;
  uint32_t handshake_length : 24;
  struct DtlsHeader *dtls_header;
  struct HandshakeHeader *handshake_header;
  guchar *handshake_payload;
  union ParsedHandshakePayload parsed_handshake_payload;
  struct DtlsParsedPacket *next_record;
};

struct RTCDtlsTransport *create_dtls_transport();
void start_dtls_negosiation(struct RTCPeerConnection *peer,
                            struct CandidataPair *pair);

void send_dtls_client_hello(struct RTCPeerConnection *peer,
                            struct CandidataPair *pair, bool with_cookie);
bool check_if_dtls(uint8_t);

int make_dtls_packet(guchar **dtls_packet, struct DtlsHeader *dtls_header,
                     struct HandshakeHeader *handshake,
                     struct DtlsHello *client_hello);
uint16_t add_dtls_extention(struct DtlsHello **dtls_packet,
                            struct dtls_ext *extention, uint16_t extention_len);
uint16_t make_extentention(struct dtls_ext **ext, uint16_t extention_type,
                           guchar *data, uint16_t data_len, guchar *extradata,
                           uint16_t extra_data_len);
void on_dtls_packet(struct NetworkPacket *dtls_packet,
                    struct RTCPeerConnection *peer);
#endif
