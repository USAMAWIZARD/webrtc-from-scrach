#include "./srtp.h"
#include "../DTLS/Encryptions/encryption.h"
#include "../RTP/rtp.h"
#include "../Utils/utils.h"
#include <arpa/inet.h>
#include <glib.h>
#include <openssl/bn.h>
#include <openssl/types.h>
#include <stdint.h>
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

  data_len = (data_len < 16) ? data_len : 16;

  guchar *data = malloc(data_len);
  BN_bn2bin(ks_pow_bn, data);
  memcpy(all_xorded, data, data_len);

  free(data);

  data_len = BN_num_bytes(ssrc_pow_bn);
  data_len = (data_len < 16) ? data_len : 16;
  data = malloc(data_len);
  BN_bn2bin(ssrc_pow_bn, data);

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

  uint64_t r = 0;
  if (srtp_encrption_ctx->kdr)
    r = srtp_encrption_ctx->index / srtp_encrption_ctx->kdr;

  memcpy(((guchar *)&key_id), (guchar *)&r, 48 / 8);
  memcpy(((guchar *)&key_id) + 7, &lable, 1);

  memcpy(x, srtp_encrption_ctx->master_salt_key,
         srtp_encrption_ctx->salt_key_len);

  for (int i = 0; i < 8; i++)
    x[i] = ((guchar *)&key_id)[i] ^ srtp_encrption_ctx->master_salt_key[i];

  memcpy(toencrypt, x, 16);
  print_hex(x, 16);
}

void srtp_key_derivation(struct SrtpEncryptionCtx *srtp_encrption_ctx) {

  guchar x[16];
  guchar toencrypt[16];

  calculate_x_and_to_encrypt(srtp_encrption_ctx, x, toencrypt, lable_k_e);
  struct AesEnryptionCtx *aes;
  init_aes(&aes, srtp_encrption_ctx->master_write_key,
           srtp_encrption_ctx->write_key_len, NULL, 0, x, CM);

  encrypt_aes(aes, toencrypt, 0, 16);
  print_hex(toencrypt, 16);

  srtp_encrption_ctx->k_e = malloc(srtp_encrption_ctx->write_key_len);
  memcpy(srtp_encrption_ctx->k_e, toencrypt, srtp_encrption_ctx->write_key_len);

  calculate_x_and_to_encrypt(srtp_encrption_ctx, x, toencrypt, lable_k_s);
  init_aes(&aes, srtp_encrption_ctx->master_write_key,
           srtp_encrption_ctx->write_key_len, NULL, 0, x, CM);
  encrypt_aes(aes, toencrypt, 0, 16);

  srtp_encrption_ctx->k_s = malloc(srtp_encrption_ctx->salt_key_len);
  memcpy(srtp_encrption_ctx->k_s, toencrypt, srtp_encrption_ctx->salt_key_len);

  init_aes(&aes, srtp_encrption_ctx->k_e, srtp_encrption_ctx->write_key_len,
           NULL, 0, x, CM);

  srtp_encrption_ctx->aes = aes;

  print_hex(toencrypt, 16);
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

  srtp_ctx->client->salt_key_len = encryption_keys->salt_size;
  srtp_ctx->server->salt_key_len = encryption_keys->salt_size;

  srtp_ctx->client->write_key_len = encryption_keys->key_size;
  srtp_ctx->server->write_key_len = encryption_keys->key_size;

  srtp_key_derivation(srtp_ctx->client);
  srtp_key_derivation(srtp_ctx->server);

  *pp_srtp_ctx = srtp_ctx;
}

void encrypt_srtp(struct SrtpEncryptionCtx *srtp_context,
                  struct Rtp *rtp_packet, uint32_t payloadlen) {

  srtp_context->index = (65536 * srtp_context->roc) + ntohs(rtp_packet->seq_no);

  guchar *iv;
  uint32_t ssrc = ntohl(rtp_packet->ssrc);
  compute_srtp_iv(&iv, srtp_context->k_s, srtp_context->salt_key_len,
                  (guchar *)&ssrc, srtp_context->index);
  srtp_context->aes->IV = iv;

  encrypt_aes(srtp_context->aes, &rtp_packet->payload[0], 0, payloadlen);
}
