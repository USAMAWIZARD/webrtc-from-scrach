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
struct srtp_ctx {
  uint32_t ssrca;
  uint32_t roc;
  uint16_t mki;
};

struct srtp_ext parse_srtp_ext(guchar *value, uint16_t len);
guchar *compute_srtp_iv(guchar **pp_iv, guchar *salting_key,
                        uint32_t salting_key_len, guchar *ssrc,
                        uint32_t packet_index);
