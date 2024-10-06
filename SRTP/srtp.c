#include "./srtp.h"
#include "../DTLS/Encryptions/encryption.h"
#include "../RTP/rtp.h"
#include "../Utils/utils.h"
#include <arpa/inet.h>
#include <glib.h>
#include <openssl/bn.h>
#include <openssl/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct srtp_ext parse_srtp_ext(guchar *value, uint16_t len) {
  struct srtp_ext ext;
  memcpy(&ext, value, sizeof(struct srtp_ext));
  ext.profile_len = ntohs(ext.profile_len);
  ext.encryption_profile = ntohs(ext.encryption_profile);
  printf("%x\n", ext.encryption_profile);

  return ext;
}

guchar *compute_srtp_iv(guchar **pp_iv, guchar *salting_key,
                        uint32_t salting_key_len, guchar *ssrc,
                        uint64_t packet_index) {
  // IV = (k_s * 2 ^ 16) XOR(SSRC * 2 ^ 64) XOR(i * 2 ^ 16)

  BIGNUM *ks_pow = BN_new();
  BIGNUM *ssrc_pow = BN_new();
  BIGNUM *seq_pow = BN_new();

  BIGNUM *ks_pow_bn = BN_new();
  BIGNUM *ssrc_pow_bn = BN_new();
  BIGNUM *seq_pow_bn = BN_new();

  BIGNUM *d_num = BN_new();
  BIGNUM *p_num = BN_new();
  BIGNUM *r = BN_new();

  BN_hex2bn(&p_num, "10");
  BN_hex2bn(&d_num, "2");

  BN_CTX *ctx = BN_CTX_new();
  BN_exp(r, d_num, p_num, ctx);

  BN_bin2bn(salting_key, salting_key_len, ks_pow);
  BN_mul(ks_pow_bn, ks_pow, r, ctx);

  BN_bin2bn((guchar *)&packet_index, 4, seq_pow);
  BN_mul(seq_pow_bn, seq_pow, r, ctx);
  printf("%s", BN_bn2hex(seq_pow_bn));
  BN_hex2bn(&p_num, "64");
  BN_exp(r, d_num, p_num, ctx);

  BN_bin2bn(ssrc, 4, ssrc_pow);
  BN_mul(ssrc_pow_bn, ssrc_pow, r, ctx);

  *pp_iv = calloc(1, 16);
  guchar *all_xorded = *pp_iv;

  uint16_t data_len = BN_num_bytes(ks_pow_bn);

  guchar *data = malloc(data_len);
  BN_bn2bin(ks_pow_bn, data);
  data_len = (data_len < 16) ? data_len : 16;
  memcpy(all_xorded, data, data_len);

  free(data);

  data_len = BN_num_bytes(ssrc_pow_bn);
  data = malloc(data_len);
  BN_bn2bin(ssrc_pow_bn, data);
  data_len = (data_len < 16) ? data_len : 16;

  for (int i = 0; i < data_len; i++) {
    all_xorded[i] = all_xorded[i] ^ data[i];
  }

  free(data);

  data_len = BN_num_bytes(seq_pow_bn);
  data_len = (data_len < 16) ? data_len : 16;
  data = malloc(data_len);
  BN_bn2bin(seq_pow_bn, data);

  for (int i = 0; i < data_len; i++) {
    all_xorded[i] = all_xorded[i] ^ data[i];
  }

  free(data);

  return all_xorded;
}
void calculate_x_and_to_encrypt(struct SrtpEncryptionCtx *srtp_encrption_ctx,
                                guchar *x, guchar *toencrypt, uint8_t lable) {
  uint64_t key_id = 0;
  memset(x, 0, 16);
  memset(toencrypt, 0, 16);

  uint64_t r = 0;
  if (srtp_encrption_ctx->kdr)
    r = srtp_encrption_ctx->index / srtp_encrption_ctx->kdr;

  memcpy(((guchar *)&key_id), (guchar *)&r, 48 / 8);
  memcpy(((guchar *)&key_id) + 7, &lable, 1);

  memcpy(x, srtp_encrption_ctx->master_salt_key,
         srtp_encrption_ctx->cipher_suite_info->salt_key_len);

  for (int i = 0; i < 8; i++)
    x[i] = ((guchar *)&key_id)[i] ^ srtp_encrption_ctx->master_salt_key[i];

  // memcpy(toencrypt, x, 16);
}

struct AesEnryptionCtx *srtp_prf(struct SrtpEncryptionCtx *srtp_encrption_ctx,
                                 uint8_t lable, guchar **pp_data,
                                 uint32_t data_len) {

  struct AesEnryptionCtx *aes;
  guchar x[16];
  guchar toencrypt[16] = {0};
  guchar iv[16];

  *pp_data = malloc(data_len + 16);
  guchar *i_data = *pp_data;
  int32_t i = data_len;
  if (data_len > 40)
    exit(0);

  calculate_x_and_to_encrypt(srtp_encrption_ctx, x, toencrypt, lable);
  memcpy(iv, x, 16);

  init_aes(&aes, srtp_encrption_ctx->master_write_key,
           srtp_encrption_ctx->cipher_suite_info->key_size, x,
           srtp_encrption_ctx->cipher_suite_info->hmac_key_len, iv, CM);

  while (i > 0) {
    printf("to encrypt\n");
    print_hex(toencrypt, 16);
    calculate_x_and_to_encrypt(srtp_encrption_ctx, x, toencrypt, lable);
    encrypt_aes(aes, toencrypt, 0, 16);
    memcpy(i_data, toencrypt, 16);
    i -= 16;
    i_data += 16;
  }

  return aes;
}

void srtp_key_derivation(struct SrtpEncryptionCtx *srtp_encrption_ctx,
                         struct cipher_suite_info *cipher_suite_info) {
  srtp_encrption_ctx->cipher_suite_info = cipher_suite_info;

  srtp_prf(srtp_encrption_ctx, lable_k_e, &srtp_encrption_ctx->k_e,
           cipher_suite_info->key_size);

  srtp_prf(srtp_encrption_ctx, lable_k_s, &srtp_encrption_ctx->k_s,
           cipher_suite_info->salt_key_len);

  srtp_prf(srtp_encrption_ctx, lable_k_a, &srtp_encrption_ctx->k_a,
           srtp_encrption_ctx->cipher_suite_info->hmac_key_len);

  print_hex(srtp_encrption_ctx->k_a,
            srtp_encrption_ctx->cipher_suite_info->hmac_key_len);

  struct AesEnryptionCtx *aes;
  init_aes(&aes, srtp_encrption_ctx->k_e, cipher_suite_info->key_size, NULL, 0,
           NULL, CM);

  srtp_encrption_ctx->aes = aes;
}

void init_srtp(struct srtp_ctx **pp_srtp_ctx,
               struct encryption_keys *encryption_keys) {

  struct srtp_ctx *srtp_ctx = malloc(sizeof(struct srtp_ctx));
  srtp_ctx->client = calloc(1, sizeof(struct SrtpEncryptionCtx));
  srtp_ctx->server = calloc(1, sizeof(struct SrtpEncryptionCtx));

  srtp_ctx->client->master_salt_key = encryption_keys->client_write_SRTP_salt;
  srtp_ctx->server->master_salt_key = encryption_keys->server_write_SRTP_salt;

  srtp_ctx->client->master_write_key = encryption_keys->client_write_key;
  srtp_ctx->server->master_write_key = encryption_keys->server_write_key;

  srtp_key_derivation(srtp_ctx->client, encryption_keys->cipher_suite_info);
  srtp_key_derivation(srtp_ctx->server, encryption_keys->cipher_suite_info);

  *pp_srtp_ctx = srtp_ctx;
}

void encrypt_srtp(struct SrtpEncryptionCtx *srtp_context,
                  struct Rtp *rtp_packet, uint32_t *payloadlen) {

  srtp_context->index = (65536 * srtp_context->roc) + ntohs(rtp_packet->seq_no);

  guchar *iv;
  uint32_t ssrc = ntohl(rtp_packet->ssrc);
  guchar rtp_mac[50];

  compute_srtp_iv(&iv, srtp_context->k_s,
                  srtp_context->cipher_suite_info->salt_key_len,
                  (guchar *)&ssrc, srtp_context->index);
  srtp_context->aes->IV = iv;

  gsize hmac_len = 20;
  printf("%p\n", srtp_context->k_a);
  GHmac *srtp_hmac = g_hmac_new(G_CHECKSUM_SHA1, srtp_context->k_a,
                                srtp_context->cipher_suite_info->hmac_key_len);
  g_hmac_update(srtp_hmac, rtp_packet, 12);
  g_hmac_update(srtp_hmac, rtp_packet->payload, *payloadlen);
  g_hmac_get_digest(srtp_hmac, rtp_mac, &hmac_len);

  uint32_t encrypt_aes_len =
      encrypt_aes(srtp_context->aes, rtp_packet->payload, 0, *payloadlen);
  memcpy(rtp_packet->payload + encrypt_aes_len, rtp_mac, 20);

  *payloadlen = encrypt_aes_len + srtp_context->cipher_suite_info->hmac_len;

  g_hmac_unref(srtp_hmac);
}
