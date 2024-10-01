#include "./srtp.h"
#include "../DTLS/Encryptions/encryption.h"
#include "../RTP/rtp.h"
#include "../Utils/utils.h"
#include <arpa/inet.h>
#include <glib.h>
#include <openssl/bn.h>
#include <openssl/types.h>
#include <stdint.h>
#include <string.h>

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
void init_srtp(struct srtp_ctx **pp_srtp_ctx,
               struct encryption_keys *encryption_keys) {

  struct srtp_ctx *srtp_ctx = malloc(sizeof(struct srtp_ctx));
  srtp_ctx->client = malloc(sizeof(struct SrtpEncryptionCtx));
  srtp_ctx->server = malloc(sizeof(struct SrtpEncryptionCtx));

  srtp_ctx->client->salt_key = encryption_keys->client_write_SRTP_salt;
  srtp_ctx->server->salt_key = encryption_keys->server_write_SRTP_salt;

  *pp_srtp_ctx = srtp_ctx;
}

void encrypt_srtp(struct SrtpEncryptionCtx *srtp_context,
                  struct Rtp *rtp_packet, uint32_t payloadlen) {

  srtp_context->index = (65536 * srtp_context->roc) + rtp_packet->seq_no;

  guchar *iv;
  uint32_t ssrc = rtp_packet->ssrc;
  compute_srtp_iv(&iv, srtp_context->salt_key, 10, (guchar *)&ssrc,
                  srtp_context->index);

  srtp_context->encrypt.aes->IV = iv;
  encrypt_aes(srtp_context->encrypt.aes, rtp_packet->payload, 0, payloadlen);
}
