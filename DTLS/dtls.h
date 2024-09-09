#pragma once
#ifndef _DTLSH_
#define _DTLSH_

#include "../WebRTC/webrtc.h"
#include "Encryptions/encryption.h"
#include "json-glib/json-glib.h"
#include <glib.h>
#include <openssl/bn.h>
#include <openssl/types.h>
#include <stdbool.h>
#include <stdint.h>

#define DTLS_1_2 0xfefd
#define DTLS_1_0 0xfeff

#define CIPHER_SUITE_LEN 1
// #define TLS_RSA_WITH_AES_128_CBC_SHA 0x2f00 // big endian

#define SRTP_AES128_CM_HMAC_SHA1_80 0x0100

#define SRTP_EXT 0x000e
#define SIGN_ALGO_EXT 0x000d
#define SESS_TICKET_EXT 0x0023
#define EXTEND_MASTER_SEC_EXT 0x0017

enum cipher_suite { TLS_RSA_WITH_AES_128_CBC_SHA = 0x2f00 };
enum key_exchange { RSA_KEY_EXCHANGE };
enum cipher { AES_128_CBC = 128 };

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
  handshake_type_hello_request = 0,
  handshake_type_client_hello,
  handshake_type_server_hello,
  handshake_type_hello_verify_request, // New field
  handshake_type_certificate = 11,
  handshake_type_server_key_exchange,
  handshake_type_certificate_request,
  handshake_type_server_hello_done,
  handshake_type_certificate_verify,
  handshake_type_client_key_exchange,
  handshake_type_finished = 20,
  handshake_type_change_cipher_spec = 233,
};

struct RTCDtlsTransport {
  enum DTLS_MODE mode;
  char *fingerprint;
  enum DtlsState state;
  struct CandidataPair *pair;
  struct DtlsParsedPacket *last_dtl_packet;
  JsonObject *dtls_flights;
  uint16_t current_seq_no;
  uint16_t epoch;
  int cookie;
  int cookie_len;
  guchar my_random[32];
  guchar peer_random[32];
  BIGNUM *rand_sum;
  uint16_t selected_cipher_suite;
  uint16_t selected_signatuire_hash_algo;
  X509 *server_certificate;
  X509 *client_certificate;
  struct encryption_keys *encryption_keys;
  union symmetric_encrypt symitric_encrypt_ctx;
  struct ALLDtlsMessages *all_previous_handshake_msgs;
  EVP_PKEY *pub_key;
  EVP_PKEY *my_private_key;
  EVP_PKEY *my_public_key;
};

struct __attribute__((packed)) HandshakeHeader {
  uint8_t type : 8;
  uint32_t length : 24;
  uint16_t message_seq;
  uint32_t fragment_offset : 24;
  uint32_t fragment_length : 24;
};

struct __attribute__((packed)) DtlsClientHello {
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
  uint8_t session_id_len;
  gchar *session_id;
  uint16_t cipher_suite;
  uint8_t compression_method;
  uint16_t extention_len;
  uint16_t *extentions;
};
struct __attribute__((packed)) Certificate {
  uint32_t certificate_len : 24;
  guchar certificate[];
};

struct __attribute__((packed)) CertificateRequest {
  uint8_t certificate_types_count;
  uint8_t *certificate_types;
  uint16_t signature_hash_algo_len;
  uint16_t *signature_hash_algo;
  uint16_t distiguished_name_len;
};

struct __attribute__((packed)) CertificateVerify {
  uint16_t signature_algorithms;
  uint16_t signature_len;
  guchar signature[];
};

struct __attribute__((packed)) HelloVerifyRequest {
  uint16_t server_version;
  uint16_t cookie_len;
};

struct __attribute__((packed)) DtlsHeader {
  uint8_t type;
  uint16_t version;
  uint16_t epoch;
  uint64_t sequence_number : 48;
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
  bool islastfragment;
  uint8_t handshake_type;
  struct DtlsHeader *dtls_header;
  struct HandshakeHeader *handshake_header;
  guchar *handshake_payload;
  guchar *all_fragmented_payload;
  union ParsedHandshakePayload parsed_handshake_payload;
  struct DtlsParsedPacket *next_record;
};

struct ServerHelloFlight {
  struct DtlsServerHello *server_hello;
  struct Certificate *certificate;
  struct CertificateRequest *certificate_request;
};

struct ClientKeyExchange {
  uint16_t key_len;
  gchar encrypted_premaster_key[];
};

struct encryption_keys {
  BIGNUM *master_secret;
  BIGNUM *my_private_key;
  BIGNUM *client_write_mac_key;
  BIGNUM *server_write_mac_key;
  BIGNUM *client_write_key;
  BIGNUM *server_wirte_key;
  BIGNUM *client_write_IV;
  BIGNUM *server_write_IV;
};

struct ALLDtlsMessages {
  bool isfragmented;
  struct ALLDtlsMessages *next_message;
  struct HandshakeHeader *handshake_header;
  uint32_t payload_len;
  guchar *payload;
};

struct RTCDtlsTransport *create_dtls_transport();
void start_dtls_negosiation(struct RTCPeerConnection *peer,
                            struct CandidataPair *pair);

void send_dtls_client_hello(struct RTCPeerConnection *peer,
                            struct CandidataPair *pair, bool with_cookie);
bool check_if_dtls(uint8_t);
uint32_t make_dtls_packet(guchar **dtls_packet, struct DtlsHeader *dtls_header,
                          struct HandshakeHeader *handshake,
                          guchar *dtls_payload, uint32_t payload_len);
bool send_dtls_packet(struct RTCDtlsTransport *dtls_transport,
                      uint8_t handshake_type, guchar *dtls_payload,
                      uint32_t dtls_payload_len);
uint16_t add_dtls_extention(struct DtlsClientHello **dtls_packet,
                            struct dtls_ext *extention, uint16_t extention_len);

uint16_t make_extentention(struct dtls_ext **ext, uint16_t extention_type,
                           guchar *data, uint16_t data_len, guchar *extradata,
                           uint16_t extra_data_len);
void on_dtls_packet(struct NetworkPacket *dtls_packet,
                    struct RTCPeerConnection *peer);
void handle_server_hello(struct RTCDtlsTransport *transport,
                         struct DtlsServerHello *hello);
void handle_certificate(struct RTCDtlsTransport *transport,
                        struct Certificate *certificate);
void handle_certificate_request(struct RTCDtlsTransport *transport,
                                struct CertificateRequest *certificate_request);

struct DtlsServerHello *parse_server_hello(guchar *handshake_payload,
                                           uint32_t length);

uint32_t get_client_certificate(guchar **certificate,
                                struct CertificateRequest *certificate_request);

bool do_client_key_exchange(struct RTCDtlsTransport *transport);
bool do_change_cipher_spec(struct RTCDtlsTransport *transport);
bool do_client_finished(struct RTCDtlsTransport *transport);
bool send_certificate(struct RTCDtlsTransport *transport);
bool do_certificate_verify(struct RTCDtlsTransport *transport);
void store_concated_handshake_msgs(struct RTCDtlsTransport *transport,
                                   struct HandshakeHeader *handshake_header,
                                   guchar *payload, uint32_t payload_len,
                                   bool isfragmented);
#endif
