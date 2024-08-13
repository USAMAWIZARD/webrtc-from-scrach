#include "../Network/network.h"
#include "../STUN/stun.h"
#include "../WebRTC/webrtc.h"
#include <glib.h>
#include <malloc.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

uint16_t cipher_suite_list[CIPHER_SUITE_LEN] = {TLS_RSA_WITH_AES_128_CBC_SHA};
uint16_t srtp_supported_profiles[] = {SRTP_AES128_CM_HMAC_SHA1_80};
uint16_t signature_algorithms[] = {0x0102, 0x0104};

struct RTCDtlsTransport *create_dtls_transport() {
  struct RTCDtlsTransport *dtls_transport =
      calloc(1, sizeof(struct RTCDtlsTransport));

  dtls_transport->state = DTLS_CONNECTION_STATE_NEW;
  dtls_transport->fingerprint =
      "3C:4A:AA:DA:3A:F5:7F:B1:60:B2:1A:BB:59:20:22:DB:FC:44:FB:71:BB:88:"
      "6D:E5:";
  dtls_transport->mode = DTLS_ACTIVE;
  dtls_transport->pair = NULL;
  strncpy(dtls_transport->random, g_uuid_string_random(), 32);
  dtls_transport->cookie = 1213;

  return dtls_transport;
}

void send_dtls_client_hello(struct RTCPeerConnection *peer,
                            struct CandidataPair *pair, bool with_cookie) {

  struct DtlsHello *dtls_client_hello = malloc(sizeof(struct DtlsHello));

  dtls_client_hello->client_version = htons(DTLS_1_2);
  memcpy(dtls_client_hello->random, peer->dtls_transport->random, 32);
  dtls_client_hello->cookie_len =
      with_cookie ? peer->dtls_transport->cookie : with_cookie;
  dtls_client_hello->cipher_suite_len = sizeof(cipher_suite_list);
  dtls_client_hello->compression_method_len = 1;
  dtls_client_hello->compression_method = 0;
  dtls_client_hello->session_id = 0;
  dtls_client_hello->extention_len = 0;

  memcpy(dtls_client_hello->cipher_suite, cipher_suite_list,
         dtls_client_hello->cipher_suite_len);

  // printf("\nlen %x %x\n", cipher_suite_list[0],
  //        (uint16_t)dtls_client_hello->cipher_suite[0]);
  // print_hex(dtls_client_hello->cipher_suite,
  //           dtls_client_hello->cipher_suite_len);
  struct DtlsHeader *dtls_header = malloc(sizeof(struct DtlsHeader));
  dtls_header->type = 22;
  dtls_header->version = htons(DTLS_1_0);
  dtls_header->epoch = peer->dtls_transport->epoch;
  // dtls_header->sequence_number

  struct HandshakeHeader *handshake = malloc(sizeof(struct HandshakeHeader));
  handshake->type = client_hello;
  handshake->message_seq = peer->dtls_transport->current_seq_no;
  handshake->fragment_length = sizeof(struct DtlsHello);

  handshake->length = sizeof(struct DtlsHello);
  handshake->fragment_offset = 0;

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
  free(other_extention);

  ext_len = make_extentention(&other_extention, SESS_TICKET_EXT, 0, 0, 0, 0);
  add_dtls_extention(&dtls_client_hello, other_extention, ext_len);
  free(other_extention);

  // printf("\n%d %d %u %d %d\n", handshake->length, sizeof(struct DtlsHello),
  //        dtls_client_hello->cipher_suite_len, dtls_header->length,
  //        handshake->type);

  guchar *dtls_packet;
  int packet_len =
      make_dtls_packet(&dtls_packet, dtls_header, handshake, dtls_client_hello);

  int bytes = sendto(pair->p0->sock_desc, dtls_packet, packet_len, 0,
                     (struct sockaddr *)pair->p1->src_socket,
                     sizeof(struct sockaddr_in));
  if (bytes < 0) {
    printf("cannot send DTLS packet\n");
    exit(-1);
  }

  printf("DTLS hello sent\n");
  // exit(0);
}
int make_dtls_packet(guchar **dtls_packet, struct DtlsHeader *dtls_header,
                     struct HandshakeHeader *handshake,
                     struct DtlsHello *client_hello) {

  int total_packet_len = sizeof(struct DtlsHeader) +
                         sizeof(struct HandshakeHeader) +
                         sizeof(struct DtlsHello) + client_hello->extention_len;

  guchar *packet = malloc(total_packet_len);
  printf("total size of packet dtls  %d \n", total_packet_len);

  handshake->length = sizeof(struct DtlsHello) + client_hello->extention_len;
  dtls_header->length = handshake->length + sizeof(struct HandshakeHeader);

  printf("%d %d afdsfasdf\n", sizeof(struct DtlsHello),
         client_hello->extention_len);

  dtls_header->length = htons(dtls_header->length);
  handshake->length = htons(handshake->length) << 8;
  // remove from here and add this in add_dtls_extentio funciton
  //
  handshake->fragment_length = handshake->length;
  client_hello->cipher_suite_len = htons(client_hello->cipher_suite_len);
  client_hello->extention_len = htons(client_hello->extention_len);

  memcpy(packet, dtls_header, sizeof(struct DtlsHeader));
  memcpy(packet + sizeof(struct DtlsHeader), handshake,
         sizeof(struct HandshakeHeader));
  memcpy(packet + sizeof(struct DtlsHeader) + sizeof(struct HandshakeHeader),
         client_hello,
         sizeof(struct DtlsHello) + ntohs(client_hello->extention_len));
  // print_hex(packet, total_packet_len);
  *dtls_packet = packet;

  return total_packet_len;
}
uint16_t add_dtls_extention(struct DtlsHello **dtls_hello,
                            struct dtls_ext *extention,
                            uint16_t extention_len) {
  uint16_t old_ext_len = (*dtls_hello)->extention_len;
  uint16_t new_len = sizeof(struct DtlsHello) + old_ext_len + extention_len;

  *dtls_hello = realloc(*dtls_hello, new_len);
  printf("old ext lend %d \n", (*dtls_hello)->extention_len);
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
  printf("%d-- %d\n", data_len, extention->ext_length);
  print_hex(extention, (sizeof(struct dtls_ext) + extention->ext_length));

  extention->ext_length = htons(extention->ext_length);
  return (sizeof(struct dtls_ext) + ntohs(extention->ext_length));
}

void on_dtls_packet(struct NetworkPacket *netowrk_packet,
                    struct RTCPeerConnection *peer) {
  struct DtlsParsedPacket *dtls_packet = netowrk_packet->payload.dtls_parsed;

  while (dtls_packet != NULL) {

    uint32_t fragment_length = dtls_packet->fragment_length;
    guchar *handshake_payload = dtls_packet->handshake_payload;

    bool is_this_pkt_fragmented = dtls_packet->isfragmented;
    bool was_last_pkt_fragmented = false;
    bool is_packet_continued = false;

    if (peer->dtls_transport->last_dtl_packet != NULL)
      was_last_pkt_fragmented =
          peer->dtls_transport->last_dtl_packet->isfragmented;

    if (was_last_pkt_fragmented) {
      uint16_t last_packet_seqno =
          peer->dtls_transport->last_dtl_packet->handshake_header->message_seq;
      uint16_t this_packet_seqno =
          last_packet_seqno == dtls_packet->handshake_header->message_seq;

      if (last_packet_seqno == this_packet_seqno)
        is_packet_continued = true;
    }

    switch (dtls_packet->handshake_type) {
    case server_hello:

      uint16_t dtls_hello_size = sizeof(struct DtlsServerHello);
      if (dtls_packet->fragment_length < dtls_hello_size)
        return;

      struct DtlsServerHello *server_hello_payload = malloc(dtls_hello_size);
      memcpy(server_hello_payload, handshake_payload,
             sizeof(struct DtlsServerHello));

      uint16_t extentions_size = ntohs(server_hello_payload->extention_len);
      printf("%d  len of ext %d \n", extentions_size, dtls_hello_size);

      if (extentions_size != 0) {
        struct DtlsServerHello *new_hello_payload =
            realloc(server_hello_payload, dtls_hello_size + extentions_size);

        server_hello_payload = new_hello_payload;

        memcpy(server_hello_payload->extentions,
               handshake_payload + dtls_hello_size, extentions_size);
      }

      dtls_packet->parsed_handshake_payload.hello = server_hello_payload;

      break;
    case certificate:
      struct Certificate *certificate = malloc(sizeof(struct Certificate));
      certificate = (struct Certificate *)handshake_payload;

      memcpy(certificate, handshake_payload, fragment_length);
      dtls_packet->parsed_handshake_payload.certificate = certificate;

      break;
    case server_key_exchange:

      break;
    case certificate_request:
      struct CertificateRequest *certificate_request =
          malloc(sizeof(struct CertificateRequest));

      uint8_t certificate_type_count;
      memcpy(&certificate_type_count, handshake_payload, 1);
      certificate_request->certificate_types = malloc(certificate_type_count);
      certificate_request->certificate_types_count = certificate_type_count;
      handshake_payload = handshake_payload + 1;

      memcpy(certificate_request->certificate_types, handshake_payload,
             certificate_type_count);

      uint16_t signature_algo_len;
      memcpy(&signature_algo_len, handshake_payload, 2);
      signature_algo_len = ntohs(signature_algo_len);
      certificate_request->signature_hash_algo = malloc(signature_algo_len);
      certificate_request->signature_hash_algo_len = signature_algo_len;
      handshake_payload = handshake_payload + 2;

      memcpy(certificate_request->signature_hash_algo, handshake_payload,
             signature_algo_len);

      break;
    case server_hello_done:

      break;
    default:
      return;
    }
    dtls_packet = dtls_packet->next_record;
  }

  peer->dtls_transport->last_dtl_packet = dtls_packet;
}

void send_alert() {}
