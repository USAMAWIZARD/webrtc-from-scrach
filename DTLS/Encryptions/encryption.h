#include "../dtls.h"
#include <glib.h>
#include <gmp.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/types.h>
#include <stdint.h>

#pragma once

#ifndef _ENRYPTIONH_
#define _ENRYPTIONH_

union symmetric_encrypt {
  struct RsaEnryptionCtx *rsa_ctx;
};

// 128 10
// 256 12
// 256 14

struct RsaEnryptionCtx {
  BIGNUM *initial_key_bn;
  uint8_t row_size;
  uint8_t initial_key[7][7];

  uint8_t key_size_bytes;
  uint8_t no_rounds;

  uint8_t input_text[8][8];
  uint8_t IV[8][8];
  uint8_t roundkeys[15][8][8];
};
#define MASTER_SECRET_LEN 48.0

uint16_t encrypt_rsa(guchar **pp_encrypted_premaster_secret, EVP_PKEY *pub_key,
                     guchar *premaster_secret, BIGNUM *random_hello_sum);

BIGNUM *calcualte_master_secret(BIGNUM *premaster_secret);
BIGNUM *get_dtls_rand_hello_sum(struct RTCDtlsTransport *transport);

gchar *PRF(BIGNUM *secret, guchar *label, BIGNUM *seed,
           GChecksumType checksum_type, uint16_t num_bytes);

BIGNUM *generate_master_key(guchar *premaster_key, BIGNUM *seed);
gchar *generate_encryption_key_block(BIGNUM *master_secret, BIGNUM *seed,
                                     guint16 selected_cipher_suite);
bool parse_encryption_key_block(struct RTCDtlsTransport *transport,
                                gchar *key_block);
bool get_cipher_suite_info(enum cipher_suite cs, int *key_size, int *iv_size,
                           int *hash_size);

bool init_symitric_encryption(struct RTCDtlsTransport *transport);
bool init_enryption_ctx(struct RTCDtlsTransport *transport, gchar *key_block);
bool init_aes(struct RTCDtlsTransport *transport, uint8_t key_size,
              BIGNUM *init_aes_key, BIGNUM *IV);

bool aes_expand_key(struct RsaEnryptionCtx *ctx);
#endif // !_ENRYPTIONH_
