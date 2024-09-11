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
#include <openssl/x509v3.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint8_t sha256_representation[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60,
                                   0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                                   0x01, 0x05, 0x00, 0x04, 0x20};

uint8_t get_hash_representation(uint8_t **hash_representation,
                                int16_t checksum_type) {
  switch (checksum_type) {
  case G_CHECKSUM_SHA256:
    *hash_representation = sha256_representation;
    return 19;
  default:
    return NULL;
  }
}
guchar *get_padded_message(guchar *message, uint16_t message_len,
                           uint32_t key_size, int16_t hash_name) {

  guchar *padded_message = malloc(key_size);
  gchar *random_padding;
  uint16_t pad;
  uint16_t padding_len;

  if (hash_name == -1) {
    padding_len = key_size - message_len - 3;
    pad = htons(0x0002);
    get_random_string(&random_padding, padding_len, RANDOM_CHAR_STRING);
  } else {

    uint8_t *hash_representation;
    uint8_t hash_representation_len =
        get_hash_representation(&hash_representation, hash_name);
    padding_len = key_size - hash_representation_len - message_len - 3;
    random_padding = malloc(padding_len);
    for (int i = 0; i < padding_len; i++) {
      random_padding[i] = 0xFF;
    }
    pad = htons(0x0001);
    guchar *hashrep_message_concat =
        malloc(message_len + hash_representation_len);
    memcpy(hashrep_message_concat, hash_representation,
           hash_representation_len);
    memcpy(hashrep_message_concat + hash_representation_len, message,
           message_len);

    message = hashrep_message_concat;
    message_len = message_len + hash_representation_len;
  }

  guchar *ptr = padded_message;

  memcpy(ptr, &pad, sizeof(uint16_t));
  ptr += sizeof(uint16_t);

  memcpy(ptr, random_padding, padding_len);

  ptr += padding_len;

  memcpy(ptr, &pad, sizeof(uint8_t));

  ptr += sizeof(uint8_t);

  memcpy(ptr, message, message_len);

  ptr += message_len;

  printf("%s", padded_message);
  free(random_padding);

  return padded_message;
}

uint16_t encrypt_rsa(guchar **p_enrypted_data, EVP_PKEY *pub_key, guchar *data,
                     uint16_t data_len, GChecksumType hash) {
  // for signing pass private key for encrypting pass public key
  if (!pub_key) {
    printf(" key null \n");
    exit(0);
  }

  RSA *rsa = EVP_PKEY_get1_RSA(pub_key);
  if (!rsa) {
    printf("cannot get public key frmo rsa certificate \n");
    exit(0);
  }

  const BIGNUM *xponent;
  const BIGNUM *modulus;
  guchar *paddedmsg;

  uint32_t key_size = RSA_size(rsa);

  if (RSA_get0_d(rsa)) {
    xponent = RSA_get0_d(rsa);
    printf("using private key fro signing \n");
    paddedmsg = get_padded_message(data, data_len, key_size, hash);
  } else if (RSA_get0_e(rsa)) {
    xponent = RSA_get0_e(rsa);
    printf("using publick key fro encryption \n");
    paddedmsg = get_padded_message(data, data_len, key_size, -1);
  }
  modulus = RSA_get0_n(rsa);

  printf("\nexponent %s\n\n", BN_bn2hex(xponent));
  printf("modulus %s\n", BN_bn2hex(modulus));
  printf("key_size %d\n", key_size);

  BIGNUM *paddedmsg_bn = BN_new();
  BN_bin2bn(paddedmsg, key_size, paddedmsg_bn);

  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *encrypted_premaster_secret = BN_new();
  BN_mod_exp(encrypted_premaster_secret, paddedmsg_bn, xponent, modulus, ctx);

  uint16_t encrypted_premaster_secret_bin_len =
      BN_num_bytes(encrypted_premaster_secret);

  guchar *encrypted_premaster_secret_bin =
      malloc(encrypted_premaster_secret_bin_len);

  printf("unencrypted padded premaster key %s\n\n", BN_bn2hex(paddedmsg_bn));
  print_hex(paddedmsg, BN_num_bytes(paddedmsg_bn));
  printf("encrypted premaster premaster key %s\n",
         BN_bn2hex(encrypted_premaster_secret));
  BN_bn2bin(encrypted_premaster_secret, encrypted_premaster_secret_bin);

  //  print_hex(encrypted_premaster_secret_bin,
  //  encrypted_premaster_secret_bin_len);

  *p_enrypted_data = encrypted_premaster_secret_bin;

  return encrypted_premaster_secret_bin_len;
}

BIGNUM *generate_master_key(guchar *premaster_secret, BIGNUM *seed) {
  BIGNUM *unpadded_premaster_secret_bn = BN_new();
  BN_bin2bn(premaster_secret, 48, unpadded_premaster_secret_bn);

  printf("unpadded premaster key %s\n",
         BN_bn2hex(unpadded_premaster_secret_bn));

  gchar *master_secret = PRF(unpadded_premaster_secret_bn, "master secret",
                             seed, G_CHECKSUM_SHA256, MASTER_SECRET_LEN);

  BIGNUM *master_secret_bn = BN_new();
  BN_bin2bn(master_secret, 48, master_secret_bn);
  free(master_secret);
  return master_secret_bn;
}

BIGNUM *get_dtls_rand_appended(BIGNUM *r1, BIGNUM *r2) {
  gchar *appended = g_strdup_printf("%s%s", BN_bn2hex(r1), BN_bn2hex(r2));
  BIGNUM *r = BN_new();

  BN_hex2bn(&r, appended);

  printf("apppended random %s\n", BN_bn2hex(r));
  return r;
}
