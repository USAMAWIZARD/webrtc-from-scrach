#include "../DTLS/Encryptions/encryption.h"
#include "../RTP/rtp.h"
#include <glib.h>
#include <openssl/bn.h>
#include <openssl/types.h>
#include <stdint.h>

#define lable_k_e 0x00
#define lable_k_s 0x02

union symmetric_encrypt;

struct __attribute__((packed)) srtp_ext {
  uint16_t profile_len;
  uint16_t encryption_profile;
  uint8_t mki_len;
};

struct SrtpEncryptionCtx {
  uint32_t roc;
  uint16_t mki;
  guchar *master_salt_key;
  uint32_t salt_key_len;
  guchar *master_write_key;
  uint32_t write_key_len;
  guchar *k_e;
  guchar *k_s;
  uint16_t ssrc;
  uint64_t index : 48;
  uint32_t kdr;

  union {
    struct AesEnryptionCtx *aes;
  };
};

struct srtp_ext parse_srtp_ext(guchar *value, uint16_t len);
guchar *compute_srtp_iv(guchar **pp_iv, guchar *salting_key,
                        uint32_t salting_key_len, guchar *ssrc,
                        uint64_t packet_index);
void srtp_key_derivation(struct SrtpEncryptionCtx *srtp_encrption_ctx);
void init_srtp(struct srtp_ctx **pp_srtp_ctx,
               struct encryption_keys *encryption_keys);
void encrypt_srtp(struct SrtpEncryptionCtx *srtp_context,
                  struct Rtp *rtp_packet, uint32_t payloadlen);
