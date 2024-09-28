#include <glib.h>
#include <openssl/bn.h>
#include <stdint.h>

struct __attribute__((packed)) srtp_ext {
  uint16_t profile_len;
  uint16_t encryption_profile;
  uint8_t mki_len;
};
struct srtp_ctx {};

struct srtp_ext parse_srtp_ext(guchar *value, uint16_t len);
