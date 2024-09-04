#include "../../Utils/utils.h"
#include "../dtls.h"
#include "./encryption.h"
#include "glibconfig.h"
#include <glib.h>
#include <gmp.h>
#include <math.h>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pkcs7.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/types.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

guchar *get_padded_message(guchar *premaster_secret, uint32_t key_size) {
  guchar *padded_premaster_secret = malloc(key_size + 1);
  guchar *ptr = padded_premaster_secret;
  uint16_t pad = htons(0x0002);
  uint32_t random_padding_len = key_size - 48 - 3;
  gchar *random_padding;

  get_random_string(&random_padding, random_padding_len, RANDOM_CHAR_STRING);

  memcpy(ptr, &pad, sizeof(uint16_t));
  ptr += sizeof(uint16_t);

  memcpy(ptr, random_padding, random_padding_len);

  ptr += random_padding_len;

  memcpy(ptr, &pad, sizeof(uint8_t));

  ptr += sizeof(uint8_t);

  uint32_t premaster_secret_len = 48;

  memcpy(ptr, premaster_secret, premaster_secret_len);

  ptr += premaster_secret_len;

  printf("%s", padded_premaster_secret);
  free(random_padding);

  return padded_premaster_secret;
}
uint16_t encrypt_rsa(guchar **pp_encrypted_premaster_secret, EVP_PKEY *pub_key,
                     guchar *premaster_secret, BIGNUM *random_hello_sum) {

  if (!pub_key) {
    printf("public key null");
    exit(0);
  }

  RSA *rsa = EVP_PKEY_get1_RSA(pub_key);
  if (!rsa) {
    printf("cannot get public key frmo rsa certificate \n");
    exit(0);
  }

  BIGNUM *xponent = RSA_get0_e(rsa);
  BIGNUM *modulus = RSA_get0_n(rsa);

  uint32_t key_size = RSA_size(rsa);
  printf("\nexponent %s\n\n", BN_bn2hex(xponent));
  printf("modulus %s\n", BN_bn2hex(modulus));
  printf("key_size %d\n", key_size);

  guchar *padded_premaster_secret =
      get_padded_message(premaster_secret, key_size);
  printf("\n");

  BIGNUM *padded_premaster_secret_bn = BN_new();
  BN_bin2bn(padded_premaster_secret, key_size, padded_premaster_secret_bn);

  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *encrypted_premaster_secret = BN_new();
  BN_mod_exp(encrypted_premaster_secret, padded_premaster_secret_bn, xponent,
             modulus, ctx);

  uint16_t encrypted_premaster_secret_bin_len =
      BN_num_bytes(encrypted_premaster_secret);

  guchar *encrypted_premaster_secret_bin =
      malloc(encrypted_premaster_secret_bin_len);

  printf("unencrypted padded premaster key %s\n\n",
         BN_bn2hex(padded_premaster_secret_bn));
  printf("encrypted premaster premaster key %s\n",
         BN_bn2hex(encrypted_premaster_secret));
  BN_bn2bin(encrypted_premaster_secret, encrypted_premaster_secret_bin);

  //  print_hex(encrypted_premaster_secret_bin,
  //  encrypted_premaster_secret_bin_len);

  *pp_encrypted_premaster_secret = encrypted_premaster_secret_bin;

  return encrypted_premaster_secret_bin_len;
}

BIGNUM *generate_master_key(guchar *premaster_secret, BIGNUM *seed) {
  BIGNUM *unpadded_premaster_secret_bn = BN_new();
  BN_bin2bn(premaster_secret, 48, unpadded_premaster_secret_bn);

  printf("unpadded premaster key %s\n",
         BN_bn2hex(unpadded_premaster_secret_bn));

  uint16_t checksum_len = g_checksum_type_get_length(G_CHECKSUM_SHA1);

  uint16_t total_itration_required = ceil(MASTER_SECRET_LEN / checksum_len);

  gchar *master_secret =
      PRF(unpadded_premaster_secret_bn, (guchar *)"master secret", seed,
          G_CHECKSUM_SHA256, total_itration_required);

  BIGNUM *master_secret_bn = BN_new();
  BN_bin2bn((guchar *)master_secret, 48, master_secret_bn);
  return master_secret_bn;
}

BIGNUM *get_dtls_rand_hello_sum(struct RTCDtlsTransport *transport) {
  BIGNUM *r1 = BN_new();
  BN_bin2bn(transport->my_random, 32, r1);
  BIGNUM *r2 = BN_new();
  BN_bin2bn(transport->peer_random, 32, r2);

  BIGNUM *r = BN_new();
  BN_add(r, r1, r2);

  printf("client random %s\n", BN_bn2hex(r1));
  printf("server random %s\n", BN_bn2hex(r2));
  printf("sum random %s", BN_bn2hex(r));

  return r;
}
