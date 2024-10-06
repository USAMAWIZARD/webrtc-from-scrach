
#include "./encryption.h"
#include "../../DTLS/dtls.h"
#include "../../SRTP/srtp.h"
#include "../../Utils/utils.h"
#include <glib.h>
#include <math.h>
#include <openssl/bn.h>
#include <openssl/types.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
guchar *PRF(BIGNUM *secret, guchar *label, BIGNUM *seed,
            GChecksumType checksum_type, uint16_t num_bytes) {

  uint16_t total_itration_required =
      ceil((float)num_bytes / g_checksum_type_get_length(checksum_type));
  printf("\n% d\n", total_itration_required);

  uint16_t secret_size = BN_num_bytes(secret);
  guchar secret_str[secret_size];
  guchar seed_str[BN_num_bytes(seed)];
  BN_bn2bin(secret, secret_str);
  BN_bn2bin(seed, seed_str);

  uint8_t label_len = strlen(label);
  gsize label_seed_len = label_len + BN_num_bytes(seed);

  guchar label_seed[label_seed_len];
  memcpy(label_seed, label, label_len);
  memcpy(label_seed + label_len, seed_str, label_seed_len);

  gsize checksum_len = g_checksum_type_get_length(checksum_type);
  guchar a_concat_seed[checksum_len + label_seed_len];
  gsize a_concat_seed_len = checksum_len + label_seed_len;
  memcpy(a_concat_seed + checksum_len, label_seed, label_seed_len);

  guchar *ALL_hmac = malloc(checksum_len * total_itration_required);
  for (int i = 1; i <= total_itration_required; i++) {

    guchar *A_seed = a_concat_seed + checksum_len;
    uint16_t A_seed_len = label_seed_len;
    for (int j = 0; j <= i - 1; j++) {

      GHmac *a_hmac = g_hmac_new(checksum_type, secret_str, secret_size);
      g_hmac_update(a_hmac, A_seed, A_seed_len);
      g_hmac_get_digest(a_hmac, a_concat_seed, &checksum_len);

      A_seed = a_concat_seed;
      A_seed_len = checksum_len;

      print_hex(a_concat_seed, checksum_len);
      g_hmac_unref(a_hmac);
    }

    GHmac *hmac = g_hmac_new(G_CHECKSUM_SHA256, secret_str, secret_size);
    g_hmac_update(hmac, a_concat_seed, a_concat_seed_len);
    g_hmac_get_digest(hmac, ALL_hmac + ((i - 1) * checksum_len), &checksum_len);
    g_hmac_unref(hmac);
  }

  printf("all hmacs \n");

  return ALL_hmac;
}

bool copy_key_block(guchar *key_block, ...) {

  va_list arg_list;
  va_start(arg_list, key_block);

  guchar **data_ptr;

  while ((data_ptr = va_arg(arg_list, guchar **)) != NULL) {

    int size = va_arg(arg_list, int);
    memcpy(*data_ptr, key_block, size);

    key_block += size;
  }
  va_end(arg_list);
  return true;
}

struct encryption_keys *
get_srtp_enryption_keys(struct RTCDtlsTransport *transport, guchar *key_block) {

  uint16_t selected_cipher_suite =
      transport->srtp_cipher_suite->selected_cipher_suite;
  struct encryption_keys *encryption_keys = transport->encryption_keys;
  struct cipher_suite_info *cipher_info = transport->srtp_cipher_suite;
  encryption_keys->cipher_suite_info = cipher_info;

  g_assert(encryption_keys != NULL && cipher_info != NULL);

  encryption_keys->client_write_key = malloc(cipher_info->key_size);
  encryption_keys->server_write_key = malloc(cipher_info->key_size);

  encryption_keys->client_write_SRTP_salt = malloc(cipher_info->salt_key_len);
  encryption_keys->server_write_SRTP_salt = malloc(cipher_info->salt_key_len);

  encryption_keys->client_write_IV = malloc(cipher_info->iv_size);
  encryption_keys->server_write_IV = malloc(cipher_info->iv_size);

  gsize srtp_key_size = cipher_info->key_size,
        salt_size = cipher_info->salt_key_len, mac_size = cipher_info->hmac_len,
        mac_key_size = cipher_info->hmac_key_len;

  copy_key_block(key_block, &encryption_keys->client_write_key, srtp_key_size,
                 &encryption_keys->server_write_key, srtp_key_size,
                 &encryption_keys->client_write_SRTP_salt, salt_size,
                 &encryption_keys->server_write_SRTP_salt, salt_size, NULL);

  return encryption_keys;
}
struct encryption_keys *
get_dtls_encryption_keys(struct RTCDtlsTransport *transport,
                         guchar *key_block) {
  uint16_t selected_cipher_suite = transport->selected_cipher_suite;
  struct encryption_keys *encryption_keys = transport->encryption_keys;
  struct cipher_suite_info *cipher_info = transport->dtls_cipher_suite;
  encryption_keys->cipher_suite_info = cipher_info;

  encryption_keys->client_write_mac_key = malloc(cipher_info->hmac_len);
  encryption_keys->server_write_mac_key = malloc(cipher_info->hmac_len);

  encryption_keys->client_write_key = malloc(cipher_info->key_size);
  encryption_keys->server_write_key = malloc(cipher_info->key_size);

  encryption_keys->client_write_IV = malloc(cipher_info->iv_size);
  encryption_keys->server_write_IV = malloc(cipher_info->iv_size);

  gsize key_size = cipher_info->key_size, iv_size = cipher_info->iv_size,
        hash_size = cipher_info->hmac_len;

  printf("key expanstion block\n");
  copy_key_block(key_block, &encryption_keys->client_write_mac_key, hash_size,
                 &encryption_keys->server_write_mac_key, hash_size,
                 &encryption_keys->client_write_key, hash_size,
                 &encryption_keys->server_write_key, hash_size,
                 &encryption_keys->client_write_IV, iv_size,
                 &encryption_keys->server_write_IV, iv_size, NULL);

  return encryption_keys;
}
bool init_client_server_encryption_ctx(union symmetric_encrypt *encryption_ctx,
                                       struct encryption_keys *encryption_keys,
                                       struct cipher_suite_info *cipher_info) {

  switch (cipher_info->symitric_algo) {
  case AES:
    struct aes_ctx *client_server_aes_ctx = malloc(sizeof(struct aes_ctx));
    init_aes(&client_server_aes_ctx->client, encryption_keys->client_write_key,
             cipher_info->key_size, encryption_keys->client_write_mac_key,
             cipher_info->hmac_len, encryption_keys->client_write_IV,
             cipher_info->mode);

    init_aes(&client_server_aes_ctx->server, encryption_keys->server_write_key,
             cipher_info->key_size, encryption_keys->server_write_mac_key,
             cipher_info->hmac_len, encryption_keys->server_write_IV,
             cipher_info->mode);

    encryption_ctx->aes = client_server_aes_ctx;
    break;
  }
  return true;
}

bool init_enryption_ctx(union symmetric_encrypt *symitric_encrypt,
                        struct encryption_keys *encryption_keys,
                        struct cipher_suite_info *cipher_info) {

  switch (cipher_info->selected_cipher_suite) {
  case TLS_RSA_WITH_AES_128_CBC_SHA:
    init_client_server_encryption_ctx(symitric_encrypt, encryption_keys,
                                      cipher_info);

    break;
  case SRTP_AES128_CM_HMAC_SHA1_80:
    init_srtp(&symitric_encrypt->srtp,
              encryption_keys); // srtp ctx containes an aes context

    union symmetric_encrypt srtp_aes;
    init_client_server_encryption_ctx(&srtp_aes, encryption_keys, cipher_info);
    symitric_encrypt->srtp->client->aes = srtp_aes.aes->client;
    symitric_encrypt->srtp->server->aes = srtp_aes.aes->server;

    break;
  default:
    printf("no  such cipher sute supported \n");
    exit(0);
    break;
  }
  return true;
}

bool init_symitric_encryption(struct RTCDtlsTransport *transport) {
  BIGNUM *master_secret = transport->encryption_keys->master_secret;

  guchar *key_block =
      PRF(master_secret, "key expansion",
          get_dtls_rand_appended(transport->peer_random, transport->my_random),
          G_CHECKSUM_SHA256, 128);

  struct encryption_keys *encryption_keys =
      get_dtls_encryption_keys(transport, key_block);

  init_enryption_ctx(&transport->dtls_symitric_encrypt, encryption_keys,
                     transport->dtls_cipher_suite);

  // check if srtp is required SRTP

  key_block =
      PRF(master_secret, "EXTRACTOR-dtls_srtp",
          get_dtls_rand_appended(transport->my_random, transport->peer_random),
          G_CHECKSUM_SHA256, 128);

  encryption_keys = get_srtp_enryption_keys(transport, key_block);

  init_enryption_ctx(&transport->srtp_symitric_encrypt, encryption_keys,
                     transport->srtp_cipher_suite);

  return true;
}
