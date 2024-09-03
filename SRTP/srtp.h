#include <glib.h>
#include <openssl/bn.h>
#include <stdint.h>

struct SRTPEnryptionCtx {
  BIGNUM *initial_key_bn;
  uint8_t row_size;
  uint8_t initial_key[7][7];

  uint8_t key_size_bytes;
  uint8_t no_rounds;

  uint8_t input_text[4][4];
  uint8_t IV[8][8];
  gchar *roundkeys[14];
};
