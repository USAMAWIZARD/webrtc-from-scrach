#include "utils.h"
#include <ctype.h>
#include <fcntl.h>
#include <glib.h>
#include <json-glib/json-glib.h>
#include <openssl/bn.h>
#include <openssl/types.h>
#include <openssl/x509v3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static gchar *get_string_from_json_object(JsonObject *object) {
  JsonNode *root;
  JsonGenerator *generator;
  gchar *text;
  /* Make it the root node */
  root = json_node_init_object(json_node_alloc(), object);
  generator = json_generator_new();
  json_generator_set_root(generator, root);
  text = json_generator_to_data(generator, NULL);

  /* Release everything */
  g_object_unref(generator);
  json_node_free(root);
  return text;
}
int strcicmp(char const *a, char const *b) {
  for (;; a++, b++) {
    int d = tolower((unsigned char)*a) - tolower((unsigned char)*b);
    if (d != 0 || !*a)
      return d;
  }
}

uint32_t hton_24(uint32_t no) { return NULL; }

void get_random_string(gchar **data_pointer, uint32_t length, uint8_t type) {
  guchar *random_data;

  random_data = malloc(length);

  int f_random = open("/dev/random", O_RDONLY);

  read(f_random, random_data, length);

  for (int i = 0; i < length; i++) {
    int temp = random_data[i];
    if (type == RANDOM_NUMBER_STRING)
      random_data[i] = random_data[i] % (57 - 48 + 1) + 48;

    else if (type == RANDOM_CHAR_STRING) {
      if (random_data[i] == 0)
        random_data[i] = random_data[i] + 10;
    }
  }

  *data_pointer = (gchar *)random_data;

  close(f_random);
}
void print_hex(const unsigned char *data, size_t length) {
  for (size_t i = 0; i < length; i++) {
    printf("%02x ", data[i]);
  }
  printf("\n");
}

uint32_t hexstr_to_char_2(guchar **p_str, guchar *str) {
  BIGNUM *bignum = BN_new();
  BN_hex2bn(&bignum, str);
  uint32_t byte_required = BN_num_bytes(bignum);
  guchar *converted_str = malloc(byte_required);
  BN_bn2bin(bignum, converted_str);
  *p_str = converted_str;

  return byte_required;
}

guchar *hexstr_to_char(const char *hexstr) {
  size_t len = strlen(hexstr);
  if (len % 2 != 0)
    return NULL;
  size_t final_len = len / 2;
  guchar *chrs = (unsigned char *)malloc((final_len + 1) * sizeof(*chrs));
  for (size_t i = 0, j = 0; j < final_len; i += 2, j++)
    chrs[j] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i + 1] % 32 + 9) % 25;

  chrs[final_len] = '\0';
  return chrs;
}
void print_rsa_matrix(uint8_t *ptr, uint8_t numrow) {
  printf("\n\n");

  uint8_t(*matrix)[numrow] = (uint8_t(*)[numrow])ptr;

  for (int i = 0; i < numrow; i++) {
    for (int j = 0; j < numrow; j++) {
      printf(" %x ", matrix[i][j]);
    }
    printf("\n");
  }
}
