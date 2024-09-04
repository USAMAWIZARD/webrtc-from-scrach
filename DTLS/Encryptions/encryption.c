
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

gchar *PRF(BIGNUM *secret, guchar *label, BIGNUM *seed,
           GChecksumType checksum_type, uint16_t num_bytes) {

  uint16_t secret_size = BN_num_bytes(secret);
  guchar secret_str[secret_size];
  guchar seed_str[BN_num_bytes(seed)];
  BN_bn2bin(secret, secret_str);
  BN_bn2bin(seed, seed_str);

  uint8_t label_len = strlen(label);
  uint16_t label_seed_len = label_len + BN_num_bytes(seed);

  guchar label_seed[label_seed_len];
  memcpy(label_seed, label, label_len);
  memcpy(label_seed + label_len, seed_str, label_seed_len);

  uint16_t checksum_len = g_checksum_type_get_length(checksum_type);
  guchar A_seed_concat[checksum_len + label_seed_len];
  guint16 A_seed_concat_len = label_seed_len;
  memcpy(A_seed_concat, label_seed, label_seed_len);

  gchar *ALL_hmac = calloc(1, 1);
  gchar *previous;

  // one extra loop because of PRF
  // https://www.ietf.org/rfc/rfc5246.html#section-5

  for (int i = 0; i <= num_bytes; i++) {
    gchar *computed_hmac =
        g_compute_hmac_for_data(checksum_type, secret_str, secret_size,
                                A_seed_concat, A_seed_concat_len);

    guchar *hmac_bin;
    hexstr_to_char_2(&hmac_bin, computed_hmac);

    memcpy(A_seed_concat, hmac_bin, checksum_len);
    memcpy(A_seed_concat + checksum_len, label_seed, label_seed_len);

    A_seed_concat_len = label_seed_len + checksum_len;

    previous = ALL_hmac;
    ALL_hmac = g_strdup_printf("%s%s", ALL_hmac, computed_hmac);
    free(previous);

    printf("\n computer hmac %s\n", computed_hmac);

    // print_hex(A_seed_concat, A_seed_concat_len);
  }
  printf("checksum len %d\n", checksum_len);
  printf("all hmacs %ld %s  \n\n", strlen(ALL_hmac), ALL_hmac);

  previous = ALL_hmac;
  hexstr_to_char_2(&ALL_hmac, ALL_hmac);
  ALL_hmac = ALL_hmac + checksum_len;
  free(previous);

  return ALL_hmac;
}

bool init_enryption_ctx(struct RTCDtlsTransport *transport, gchar *key_block) {
  uint16_t selected_cipher_suite = transport->selected_cipher_suite;
  struct encryption_keys *encryption_keys = transport->encryption_keys;
  // ideallly get it from a hash map all the len of the fields

  encryption_keys->client_write_mac_key = BN_new();
  encryption_keys->server_write_mac_key = BN_new();

  encryption_keys->client_write_key = BN_new();
  encryption_keys->server_write_mac_key = BN_new();

  encryption_keys->client_write_IV = BN_new();
  encryption_keys->server_write_IV = BN_new();

  guchar *bin_key_block;
  uint16_t total_size = hexstr_to_char_2(&bin_key_block, key_block);

  int key_size, iv_size, hash_size;
  if (!get_cipher_suite_info(selected_cipher_suite, &key_size, &iv_size,
                             &hash_size)) {
    return false;
  }

  encryption_keys->client_write_mac_key = BN_new();
  BN_bin2bn(bin_key_block, hash_size, encryption_keys->client_write_mac_key);
  bin_key_block += hash_size;

  encryption_keys->server_write_mac_key = BN_new();
  BN_bin2bn(bin_key_block, hash_size, encryption_keys->server_write_mac_key);
  bin_key_block += hash_size;

  encryption_keys->client_write_key = BN_new();
  BN_bin2bn(bin_key_block, key_size, encryption_keys->client_write_key);
  bin_key_block += key_size;

  encryption_keys->server_wirte_key = BN_new();
  BN_bin2bn(bin_key_block, key_size, encryption_keys->server_wirte_key);
  bin_key_block += key_size;

  encryption_keys->client_write_IV = BN_new();
  BN_bin2bn(bin_key_block, iv_size, encryption_keys->client_write_IV);
  bin_key_block += iv_size;

  encryption_keys->server_write_IV = BN_new();
  BN_bin2bn(bin_key_block, iv_size, encryption_keys->server_write_IV);

  switch (selected_cipher_suite) {
  case TLS_RSA_WITH_AES_128_CBC_SHA:
    init_aes(transport, key_size, encryption_keys->client_write_key,
             encryption_keys->client_write_IV);
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
    break;
  }
  return false;
}

bool init_symitric_encryption(struct RTCDtlsTransport *transport) {
  BIGNUM *master_secret = transport->encryption_keys->master_secret;

  uint16_t total_itration_required =
      ceil(128 / g_checksum_type_get_length(G_CHECKSUM_SHA256));
  printf("\n% d\n", total_itration_required);

  gchar *key_block =
      PRF(master_secret, (guchar *)"key expanstion", transport->rand_sum,
          G_CHECKSUM_SHA256, total_itration_required);

  if (!init_enryption_ctx(transport, key_block))
    return false;

  return true;
}
