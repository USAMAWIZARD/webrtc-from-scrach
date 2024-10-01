#include "../DTLS/Encryptions/encryption.h"
#include <glib.h>
#include <openssl/bn.h>
#include <openssl/types.h>
#include <stdint.h>
union symmetric_encrypt;
struct __attribute__((packed)) srtp_ext {
  uint16_t profile_len;
  uint16_t encryption_profile;
  uint8_t mki_len;
};

struct SrtpEncryptionCtx {
  uint32_t roc;
  uint16_t mki;
  guchar *salt_key;
  uint64_t index : 48;
  union {
    struct AesEnryptionCtx *aes;
  } encrypt;
};

struct srtp_ext parse_srtp_ext(guchar *value, uint16_t len);
guchar *compute_srtp_iv(guchar **pp_iv, guchar *salting_key,
                        uint32_t salting_key_len, guchar *ssrc,
                        uint64_t packet_index);
void init_srtp(struct srtp_ctx **pp_srtp_ctx,
               struct encryption_keys *encryption_keys);
