
#include "dtls.h"
#include "../Network/network.h"
#include "../STUN/stun.h"
#include "../WebRTC/webrtc.h"
#include "glibconfig.h"
#include "json-glib/json-glib.h"
#include <glib.h>
#include <malloc.h>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/types.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

gchar *my_rsa_public_cert =
    "MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgGpMr0YKNVMgfHyXHheUGlsAdEQ7\
P6Fd75nVsdxelyVNokubJ9NiSAtG03x35xiGo6zASpi8vzjslArGczuwsdMAescr\
tREGoJxphqnoO1eaPUh2Nr7OU06X+SeB3Ooem5JTJO7F8jg9TohDsvN+RnSHRE4P\
FDZfrv9gRGK9qz9lAgMBAAE=";

uint16_t cipher_suite_list[CIPHER_SUITE_LEN] = {TLS_RSA_WITH_AES_128_CBC_SHA};
uint16_t srtp_supported_profiles[] = {SRTP_AES128_CM_HMAC_SHA1_80};
uint16_t signature_algorithms[] = {0x0102, 0x0104};

struct RTCDtlsTransport *create_dtls_transport() {
  struct RTCDtlsTransport *dtls_transport =
      calloc(1, sizeof(struct RTCDtlsTransport));

  dtls_transport->dtls_flights = json_object_new();

  dtls_transport->state = DTLS_CONNECTION_STATE_NEW;
  dtls_transport->fingerprint =
      "3C:4A:AA:DA:3A:F5:7F:B1:60:B2:1A:BB:59:20:22:DB:FC:44:FB:71:BB:88:"
      "6D:E5:";
  dtls_transport->mode = DTLS_ACTIVE;
  dtls_transport->pair = NULL;
  strncpy(dtls_transport->my_random, g_uuid_string_random(), 32);
  dtls_transport->cookie = 1213;

  return dtls_transport;
}

void send_dtls_client_hello(struct RTCPeerConnection *peer,
                            struct CandidataPair *pair, bool with_cookie) {

  struct DtlsHello *dtls_client_hello = malloc(sizeof(struct DtlsHello));

  dtls_client_hello->client_version = htons(DTLS_1_2);
  memcpy(dtls_client_hello->random, peer->dtls_transport->my_random, 32);
  dtls_client_hello->cookie_len =
      with_cookie ? peer->dtls_transport->cookie : with_cookie;
  dtls_client_hello->cipher_suite_len = sizeof(cipher_suite_list);
  dtls_client_hello->compression_method_len = 1;
  dtls_client_hello->compression_method = 0;
  dtls_client_hello->session_id = 0;
  dtls_client_hello->extention_len = 0;

  memcpy(dtls_client_hello->cipher_suite, cipher_suite_list,
         dtls_client_hello->cipher_suite_len);
  dtls_client_hello->cipher_suite_len =
      htons(dtls_client_hello->cipher_suite_len);

  // printf("\nlen %x %x\n", cipher_suite_list[0],
  //        (uint16_t)dtls_client_hello->cipher_suite[0]);
  // print_hex(dtls_client_hello->cipher_suite,
  //           dtls_client_hello->cipher_suite_len);

  struct dtls_ext *srtp_extention;
  uint8_t mki_len = 0;
  uint16_t ext_len =
      make_extentention(&srtp_extention, SRTP_EXT, srtp_supported_profiles,
                        sizeof(srtp_supported_profiles), &mki_len, 1);
  add_dtls_extention(&dtls_client_hello, srtp_extention, ext_len);
  free(srtp_extention);

  struct dtls_ext *supported_signature_algorithms;
  ext_len = make_extentention(&supported_signature_algorithms, SIGN_ALGO_EXT,
                              signature_algorithms,
                              sizeof(signature_algorithms), 0, 0);
  add_dtls_extention(&dtls_client_hello, supported_signature_algorithms,
                     ext_len);
  free(supported_signature_algorithms);

  struct dtls_ext *other_extention;
  ext_len =
      make_extentention(&other_extention, EXTEND_MASTER_SEC_EXT, 0, 0, 0, 0);
  add_dtls_extention(&dtls_client_hello, other_extention, ext_len);

  dtls_client_hello->extention_len = htons(dtls_client_hello->extention_len);
  free(other_extention);

  // session ticket extention
  //  ext_len = make_extentention(&other_extention, SESS_TICKET_EXT, 0, 0, 0,
  //  0); add_dtls_extention(&dtls_client_hello, other_extention, ext_len);
  //  free(other_extention);

  // printf("\n%d %d %u %d %d\n", handshake->length, sizeof(struct DtlsHello),
  //        dtls_client_hello->cipher_suite_len, dtls_header->length,
  //        handshake->type);
  //

  send_dtls_packet(peer->dtls_transport, (gchar *)dtls_client_hello,
                   sizeof(struct DtlsServerHello) +
                       ntohs(dtls_client_hello->extention_len));
  printf("DTLS hello sent\n");
  // exit(0);
}
bool send_dtls_packet(struct RTCDtlsTransport *dtls_transport,
                      gchar *dtls_payload, uint32_t dtls_payload_len) {

  struct DtlsHeader *dtls_header = malloc(sizeof(struct DtlsHeader));
  dtls_header->type = 22;
  dtls_header->version = htons(DTLS_1_0);
  dtls_header->epoch = dtls_transport->epoch;
  // dtls_header->sequence_number

  struct HandshakeHeader *handshake = malloc(sizeof(struct HandshakeHeader));
  handshake->type = handshake_type_client_hello;
  handshake->message_seq = dtls_transport->current_seq_no;
  handshake->fragment_length = dtls_payload_len;
  handshake->length = dtls_payload_len;
  handshake->fragment_offset = 0;

  guchar *dtls_packet;
  int packet_len = make_dtls_packet(&dtls_packet, dtls_header, handshake,
                                    dtls_payload, dtls_payload_len);

  struct CandidataPair *pair = dtls_transport->pair;
  int bytes = sendto(pair->p0->sock_desc, dtls_packet, packet_len, 0,
                     (struct sockaddr *)pair->p1->src_socket,
                     sizeof(struct sockaddr_in));
  if (bytes < 0) {
    printf("cannot send DTLS packet\n");
    exit(0);
  }
  return true;
}
uint32_t make_dtls_packet(guchar **dtls_packet, struct DtlsHeader *dtls_header,
                          struct HandshakeHeader *handshake,
                          guchar *dtls_payload, uint32_t payload_len) {

  int total_packet_len =
      sizeof(struct DtlsHeader) + sizeof(struct HandshakeHeader) + payload_len;

  guchar *packet = malloc(total_packet_len);
  printf("total size of packet dtls  %d \n", total_packet_len);

  handshake->length = payload_len;
  dtls_header->length = handshake->length + sizeof(struct HandshakeHeader);

  dtls_header->length = htons(dtls_header->length);
  handshake->length = htons(handshake->length) << 8;
  // remove from here and add this in add_dtls_extentio funciton

  handshake->fragment_length = handshake->length;

  memcpy(packet, dtls_header, sizeof(struct DtlsHeader));
  memcpy(packet + sizeof(struct DtlsHeader), handshake,
         sizeof(struct HandshakeHeader));
  memcpy(packet + sizeof(struct DtlsHeader) + sizeof(struct HandshakeHeader),
         dtls_payload, payload_len);
  print_hex(packet, total_packet_len);
  *dtls_packet = packet;

  return total_packet_len;
}
uint16_t add_dtls_extention(struct DtlsHello **dtls_hello,
                            struct dtls_ext *extention,
                            uint16_t extention_len) {
  uint16_t old_ext_len = (*dtls_hello)->extention_len;
  uint16_t new_len = sizeof(struct DtlsHello) + old_ext_len + extention_len;

  *dtls_hello = realloc(*dtls_hello, new_len);
  // printf("old ext lend %d \n", (*dtls_hello)->extention_len);
  memcpy((char *)(*dtls_hello)->extentions + old_ext_len, extention,
         extention_len);

  (*dtls_hello)->extention_len += extention_len;

  return new_len;
}
void start_dtls_negosiation(struct RTCPeerConnection *peer,
                            struct CandidataPair *pair) {
  if (peer == NULL || peer->dtls_transport->pair == NULL) {
    return;
  }
  printf("starting DTLS Negosiation on pair %s %d %s %d \n", pair->p0->address,
         pair->p0->port, pair->p1->address, pair->p1->port);
  send_dtls_client_hello(peer, pair, false);
}

bool check_if_dtls(uint8_t first_byte) {
  return (first_byte > 19 && first_byte < 34);
}

uint16_t make_extentention(struct dtls_ext **ext, uint16_t extention_type,
                           guchar *data, uint16_t data_len, guchar *extradata,
                           uint16_t extra_data_len) {
  struct dtls_ext *extention =
      malloc(sizeof(struct dtls_ext) + data_len + extra_data_len + 2);

  extention->type = htons(extention_type);
  extention->ext_length = 0;

  if (data_len != 0) {
    extention->ext_length = (data_len + 2);
    uint16_t len = htons(data_len);
    memcpy(extention->value, &len, sizeof(uint16_t));
    memcpy(extention->value + sizeof(uint16_t), data, data_len);
  }
  if (extra_data_len != 0) {
    memcpy(extention->value + extention->ext_length, extradata, extra_data_len);
    extention->ext_length += extra_data_len;
  }

  *ext = extention;
  // print_hex(extention, (sizeof(struct dtls_ext) + extention->ext_length));

  extention->ext_length = htons(extention->ext_length);
  return (sizeof(struct dtls_ext) + ntohs(extention->ext_length));
}

void on_dtls_packet(struct NetworkPacket *netowrk_packet,
                    struct RTCPeerConnection *peer) {

  JsonObject *flight = peer->dtls_transport->dtls_flights;
  struct DtlsParsedPacket *dtls_packet = netowrk_packet->payload.dtls_parsed;

  while (dtls_packet != NULL) {

    uint32_t total_fragment_len = dtls_packet->handshake_header->length;
    uint32_t fragment_length = dtls_packet->handshake_header->fragment_length;
    uint32_t fragment_offset = dtls_packet->handshake_header->fragment_offset;
    guchar *handshake_payload = dtls_packet->handshake_payload;
    gchar *handshake_type_str =
        g_strdup_printf("%d", dtls_packet->handshake_type);

    bool was_last_pkt_fragmented = false;
    bool is_this_last_fragment = false;

    if (dtls_packet->isfragmented) {
      printf("fragmented \n");
      struct DtlsParsedPacket *last_similar_packet = NULL;

      if (json_object_has_member(flight, handshake_type_str)) {
        last_similar_packet =
            (struct DtlsParsedPacket *)(json_object_get_int_member(
                flight, handshake_type_str));

        // printf("ptr2  %p  %d\n", last_similar_packet,
        //        last_similar_packet->handshake_type);
      } else {
        json_object_set_int_member(flight, handshake_type_str,
                                   (guint64)dtls_packet);
        dtls_packet->all_fragmented_payload = malloc(total_fragment_len);
        memcpy(dtls_packet->all_fragmented_payload,
               dtls_packet->handshake_payload, fragment_length);

        //        printf("ptr1 %d %p\n", GPOINTER_TO_INT(dtls_packet),
        //        dtls_packet);
        return;
      }
      if (last_similar_packet && last_similar_packet->isfragmented) {

        uint16_t last_packet_seqno =
            last_similar_packet->handshake_header->message_seq;

        uint16_t this_packet_seqno = dtls_packet->handshake_header->message_seq;

        if (last_packet_seqno == this_packet_seqno) {
          memcpy(last_similar_packet->all_fragmented_payload + fragment_offset,
                 dtls_packet->handshake_payload, fragment_length);

          printf("fragment continue type: %s seq %d %d flen %d\n ",
                 handshake_type_str, last_packet_seqno, fragment_offset,
                 fragment_length);
        }
      }

      if (!dtls_packet->islastfragment)
        return;

      handshake_payload = last_similar_packet->all_fragmented_payload;

      printf("all fragments aseembedled \n");

    } else {
      printf("non fragmented \n");
    }

    switch (dtls_packet->handshake_type) {
    case handshake_type_server_hello:
      printf("server hello \n");
      uint16_t dtls_hello_size = fragment_length;

      struct DtlsServerHello *server_hello =
          parse_server_hello(handshake_payload, total_fragment_len);

      dtls_packet->parsed_handshake_payload.hello = server_hello;

      handle_server_hello(peer->dtls_transport, server_hello);
      break;

    case handshake_type_certificate:
      if (total_fragment_len < sizeof(uint32_t))
        return;
      printf("certificate \n");

      uint32_t total_certificates_len =
          ntohl(*((uint32_t *)handshake_payload)) >> 8;

      if (total_fragment_len < total_certificates_len)
        return;

      handshake_payload += 3;

      uint32_t certificate_len = ntohl(*((uint32_t *)handshake_payload)) >> 8;

      struct Certificate *certificate = malloc(certificate_len);
      certificate->certificate_len = certificate_len;

      handshake_payload += 3;

      if (total_fragment_len <
          sizeof(struct Certificate) + certificate->certificate_len)
        return;

      memcpy(certificate->certificate, handshake_payload,
             certificate->certificate_len);

      dtls_packet->parsed_handshake_payload.certificate = certificate;

      handle_certificate(peer->dtls_transport, certificate);

      break;
    case handshake_type_server_key_exchange:

      break;
    case handshake_type_certificate_request:
      printf("certificate request \n");
      struct CertificateRequest *certificate_request =
          malloc(sizeof(struct CertificateRequest));

      certificate_request->certificate_types_count =
          *((uint8_t *)handshake_payload);

      handshake_payload += sizeof(uint8_t);

      certificate_request->certificate_types =
          malloc(certificate_request->certificate_types_count);

      memcpy(certificate_request->certificate_types, handshake_payload,
             certificate_request->certificate_types_count);

      handshake_payload += certificate_request->certificate_types_count;

      certificate_request->signature_hash_algo_len =
          ntohs(*((uint16_t *)handshake_payload));
      handshake_payload += sizeof(uint16_t);

      certificate_request->signature_hash_algo =
          malloc(certificate_request->signature_hash_algo_len);

      memcpy(certificate_request->signature_hash_algo, handshake_payload,
             certificate_request->signature_hash_algo_len);

      break;
    case handshake_type_server_hello_done:
      printf("server hello done \n");

      // do_client_key_exchange();
      // client_finished();
      break;
    default:
      break;
    }
  next_dtls_packet:
    dtls_packet = dtls_packet->next_record;
  }
}

void handle_server_hello(struct RTCDtlsTransport *transport,
                         struct DtlsServerHello *hello) {

  memcpy(transport->peer_random, hello->random, sizeof(hello->random));
  transport->selected_cipher_suite = hello->cipher_suite;
}
void handle_certificate(struct RTCDtlsTransport *transport,
                        struct Certificate *certificate) {
  printf("%d cert len\n", certificate->certificate_len);
  print_hex(certificate->certificate, certificate->certificate_len);

  X509 *cert;
  cert =
      d2i_X509(NULL, &(certificate->certificate), certificate->certificate_len);

  if (!cert) {
    printf("unable to parse certificate\n");
    exit(0);
    return;
  }

  transport->server_certificate = cert;

  EVP_PKEY *pub_key = X509_get_pubkey(cert);
  transport->pub_key = pub_key;
}

void handle_certificate_request(
    struct RTCDtlsTransport *transport,
    struct CertificateRequest *certificate_request) {}

void send_alert() {}
struct DtlsServerHello *parse_server_hello(guchar *handshake_payload,
                                           uint32_t length) {
  if (length < sizeof(struct DtlsServerHello))
    return NULL;

  struct DtlsServerHello *server_hello = malloc(sizeof(struct DtlsServerHello));
  guchar *ptr = handshake_payload;

  server_hello->client_version = ntohs(*((uint16_t *)ptr));

  ptr = handshake_payload + sizeof(uint16_t);

  memcpy(server_hello->random, ptr, sizeof(server_hello->random));

  ptr += sizeof(server_hello->random);

  server_hello->session_id_len = *((uint8_t *)ptr);

  ptr += sizeof(uint8_t);

  if (ptr + server_hello->session_id_len - handshake_payload < 0)
    return NULL;

  server_hello->session_id = malloc(server_hello->session_id_len);

  memcpy(server_hello->session_id, ptr, server_hello->session_id_len);

  ptr += server_hello->session_id_len;

  server_hello->cipher_suite = ntohs(*(uint16_t *)ptr);
  ptr += sizeof(uint16_t);

  server_hello->compression_method = *(uint8_t *)ptr;
  ptr += sizeof(uint8_t);

  server_hello->extention_len = ntohs(*(uint16_t *)ptr);

  if ((ptr + server_hello->extention_len - handshake_payload) < 0)
    return NULL;

  server_hello->extentions = malloc(server_hello->extention_len);
  memcpy(server_hello->extentions, ptr, server_hello->extention_len);

  return server_hello;
}

struct Certificate *
get_client_certificate(struct RTCDtlsTransport *transport,
                       struct CertificateRequest *certificate_request) {

  struct Certificate *client_certificate = malloc(sizeof(struct Certificate));

  uint32_t certificate_len = strlen(my_rsa_public_cert);
  client_certificate->certificate = malloc(certificate_len);
  client_certificate->certificate_len = certificate_len;

  return client_certificate;
}

bool do_client_key_exchange(struct RTCDtlsTransport *transport) {
  uint16_t selected_cipher_suite = transport->selected_cipher_suite;
  // also
  if (selected_cipher_suite == cipher_suite_list[0]) { // rsa key change
    FILE *randomData = fopen("/dev/urandom", "r");
    if (randomData == NULL) {
      printf("random nubmer generateion failed for rsa\n");
      exit(0);
    }
    gchar premaster_key[48];
    memcpy(premaster_key, (guchar *)DTLS_1_2, sizeof(uint16_t));

    fread(premaster_key + sizeof(uint16_t), 1, 46, randomData);

  } else {
    printf("only rsa key exchagge suported ");
    exit(0);
  }
}
