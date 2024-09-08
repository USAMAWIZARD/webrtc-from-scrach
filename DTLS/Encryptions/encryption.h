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

// 128 10
// 256 12
// 256 14

struct AesEnryptionCtx {
  BIGNUM *initial_key_bn;
  uint8_t row_size;
  uint8_t initial_key[7][7];

  uint8_t key_size_bytes;
  uint8_t no_rounds;

  uint8_t input_text[4][4];
  uint8_t IV[8][8];
  gchar *roundkeys[14];
};
#define MASTER_SECRET_LEN 48.0

uint16_t encrypt_rsa(guchar **encrypted_data, EVP_PKEY *pub_key, guchar *data,
                     uint16_t data_len, GChecksumType hash);

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

bool aes_expand_key(struct AesEnryptionCtx *ctx);

void sub_bytes(uint8_t (*block)[4]);

void shift_rows(uint8_t (*block)[4]);

void mix_columns(uint8_t (*matrix)[4]);

void encrypt_aes(struct AesEnryptionCtx *ctx, uint8_t (*block)[4],
                 uint32_t data_len);

#endif // !_ENRYPTIONH_
