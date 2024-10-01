#include "../DTLS/Encryptions/encryption.h"
#include "../SRTP/srtp.h"
#include "../Utils/utils.h"
#include <assert.h>
#include <glib.h>
#include <openssl/bn.h>
#include <openssl/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <strings.h>

void aes_test() {

  // to encrypt
  // 14 00 00 0c 00 05 00 00 00 00 00 0c d7 7f a4 a3 2a d1 d6 bc 76 2e 0a fb
  // ------------IV
  // c8 7c bb fd 9e 77 77 05 2c 74 25 5e 4a 74 92 51
  // -------------initial key
  // 0c cb 1d 0c 65 cb 44 48 3e 45 74 b8 fb 95 3d 63
  //
  // encrypted
  // 1d 36 dd bb 3d e6 42 3f 64 f4 f3 ba 81 54 f6 b6 9a 27 b7 c8 28 41 71 b7 9e
  // b2 36 17 4f 6b 0a 88

  printf("testing AES encryption\n");
  printf("test AES Mode :CBC \n");
  guchar *key, *iv;
  uint16_t key_size =
      hexstr_to_char_2(&key, "aaf5f65767682a3c62ca89863926f24d");
  uint16_t iv_size = hexstr_to_char_2(&iv, "cc681eaa679a4d70bd2e6a1099eb6a6d");
  struct encryption_keys encryption_key;
  encryption_key.client_write_key = key;
  encryption_key.client_write_IV = iv;
  encryption_key.client_write_mac_key = iv;

  encryption_key.key_size = key_size;
  encryption_key.iv_size = iv_size;
  encryption_key.mac_key_size = 14;

  encryption_key.server_write_IV = key;
  encryption_key.server_write_key = iv;
  encryption_key.server_write_mac_key = iv;

  union symmetric_encrypt symmetric_encrypt;
  init_client_server_encryption_ctx(&symmetric_encrypt, &encryption_key, AES);

  struct aes_ctx *ctx = symmetric_encrypt.aes;
  uint8_t *block_hex = "1400000c000500000000000c4366e450f4d5828d2e5341a6";
  uint8_t *block;

  uint32_t len = hexstr_to_char_2(&block, block_hex);
  block = realloc(block, len + 300);

  len = encrypt_aes(ctx->client, &block, 0, len);

  uint8_t *encrypted_bloc = block;
  printf("after encryption \n");

  print_hex(encrypted_bloc, len);

  guchar *bin_test_encrypted;
  hexstr_to_char_2(
      &bin_test_encrypted,
      "07a240b00d520ea32d22e8ace7c55f9085f7709ccb816b308b6be928201d669f");

  assert(memcmp(encrypted_bloc, bin_test_encrypted, len) == 0);
  printf("encryption with AES CBC TEST successfull \n");

  /////
  printf("Test AES Mode : CM");
  hexstr_to_char_2(&ctx->client->IV, "cc681eaa679a4d70bd2e6a1099eb6a6d");
  block_hex = "1400000c000500000000000c4366e450f4d5828d2e5341a6";
  ctx->client->mode = CM;

  len = hexstr_to_char_2(&block, block_hex);
  block = realloc(block, len + 300);

  len = encrypt_aes(ctx->client, &block, 0, len);

  encrypted_bloc = block;
  printf("after encryption \n");

  print_hex(encrypted_bloc, len);

  hexstr_to_char_2(&bin_test_encrypted, "B7E1D5643D675A6319D0829BB9B399D67AF43E"
                                        "6E6319B7F8E3AB538EA47DB047");

  assert(memcmp(encrypted_bloc, bin_test_encrypted, len) == 0);
  printf("encryption with AES CM TEST successfull ");
}

void prf_test() {

  printf("starting prf test \n");
  BIGNUM *secret = BN_new();

  BIGNUM *client_hello = BN_new();
  BIGNUM *server_hello = BN_new();

  BN_hex2bn(&secret, "FEFD7D4F93402EAC6C6D875E9A8EE8B8CC9CDCBC03D2E661CC75214B7"
                     "9F1C938A20215621987912ED841E68B770D3427");
  BN_hex2bn(&client_hello,
            "34323532313133382d313163362d343132612d386531382d3835346361616134");
  BN_hex2bn(&server_hello,
            "6ba317d2c22dbc6310c03f82d657002658823f15d9923eb7aae0dd5f7acca2d8");

  guchar *master_secret =
      PRF(secret, "master secret",
          get_dtls_rand_appended(client_hello, server_hello), G_CHECKSUM_SHA256,
          48);

  guchar *expected;
  hexstr_to_char_2(&expected,
                   "29273fd9c595b788a2c3abfb8e172ba0c4430859083820bb50fd77c4a"
                   "b0cd290f10219ac5627d788d3c1af2885b03262b11a");
  assert(memcmp(master_secret, expected, 48) == 0);
  printf("prf test success full\n");
  //  29273fd9c595b788a2c3abfb8e172ba0c4430859083820bb50fd77c4ab0cd290
}

void key_generate_keystream(guchar *counter) {}
void test_srtp_iv() {
  printf("testing srtp iv generateiton \n");

  guchar *iv;
  uint32_t ssrc = 0x00000000;
  gchar *salt_key = "f0f1f2f3f4f5f6f7f8f9fafbfcfd0000";
  guchar *salt_key_bin;
  uint32_t key_len = hexstr_to_char_2(&salt_key_bin, salt_key);

  compute_srtp_iv(&iv, salt_key_bin, key_len, &ssrc, 0);
  print_hex(iv, 16);
  compute_srtp_iv(&iv, salt_key_bin, key_len, &ssrc, 1);

  print_hex(iv, 16);
}

int main() {

  test_srtp_iv();
  // aes_test();
  //  prf_test();
}
