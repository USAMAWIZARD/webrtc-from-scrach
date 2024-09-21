
#include "./encryption.h"
#include "../../DTLS/dtls.h"
#include "../../Utils/utils.h"
#include "glibconfig.h"
#include <glib.h>
#include <math.h>
#include <openssl/bn.h>
#include <openssl/types.h>
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
    print_hex(ALL_hmac, checksum_len * 2);
    g_hmac_unref(hmac);
  }

  printf("all hmacs \n");

  return ALL_hmac;
}

bool init_enryption_ctx(struct RTCDtlsTransport *transport, guchar *key_block) {
  uint16_t selected_cipher_suite = transport->selected_cipher_suite;
  struct encryption_keys *encryption_keys = transport->encryption_keys;
  // ideallly get it from a hash map all the len of the fields

  encryption_keys->client_write_mac_key = BN_new();
  encryption_keys->server_write_mac_key = BN_new();

  encryption_keys->client_write_key = BN_new();
  encryption_keys->server_write_key = BN_new();

  encryption_keys->client_write_IV = BN_new();
  encryption_keys->server_write_IV = BN_new();

  int key_size, iv_size, hash_size;

  if (!get_cipher_suite_info(selected_cipher_suite, &key_size, &iv_size,
                             &hash_size)) {
    return false;
  }

  printf("key expanstion block\n");
  print_hex(key_block, ((key_size * 2) + (iv_size * 2) + (20 * 2)));

  BN_bin2bn(key_block, hash_size, encryption_keys->client_write_mac_key);
  key_block += hash_size;

  BN_bin2bn(key_block, hash_size, encryption_keys->server_write_mac_key);
  key_block += hash_size;

  BN_bin2bn(key_block, key_size, encryption_keys->client_write_key);
  key_block += key_size;

  BN_bin2bn(key_block, key_size, encryption_keys->server_write_key);
  key_block += key_size;

  BN_bin2bn(key_block, iv_size, encryption_keys->client_write_IV);
  key_block += iv_size;

  BN_bin2bn(key_block, iv_size, encryption_keys->server_write_IV);

  encryption_keys->key_size = key_size;
  encryption_keys->mac_key_size = hash_size;

  switch (selected_cipher_suite) {
  case TLS_RSA_WITH_AES_128_CBC_SHA:
    init_aes(&transport->symitric_encrypt_ctx.aes, encryption_keys);
  default:

    break;
  }

  return true;
}
bool get_cipher_suite_info(enum cipher_suite cs, int *key_size, int *iv_size,
                           int *hash_size) {
  switch (cs) {
  case TLS_RSA_WITH_AES_128_CBC_SHA:
    *key_size = 16;  // 128 bits
    *iv_size = 16;   // 128 bits
    *hash_size = 20; // SHA-1, 160 bits
    return true;

  default:
    *key_size = 0;
    *iv_size = 0;
    *hash_size = 0;
    printf("Unknown cipher suite\n");
    exit(0);
    break;
  }
  return false;
}

bool init_symitric_encryption(struct RTCDtlsTransport *transport) {
  BIGNUM *master_secret = transport->encryption_keys->master_secret;

  guchar *key_block =
      PRF(master_secret, "key expansion",
          get_dtls_rand_appended(transport->peer_random, transport->my_random),
          G_CHECKSUM_SHA256, 128);
  printf("tls prf key blcok for key expnsion ");
  print_hex(key_block, 128);

  if (!init_enryption_ctx(transport, key_block))
    return false;

  return true;
}
