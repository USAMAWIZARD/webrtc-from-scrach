#include "../../Utils/utils.h"
#include "encryption.h"
#include <arpa/inet.h>
#include <glib.h>
#include <math.h>
#include <openssl/bn.h>
#include <openssl/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

uint8_t s_box[16][16] = {
    {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
     0xfe, 0xd7, 0xab, 0x76},
    {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf,
     0x9c, 0xa4, 0x72, 0xc0},
    {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
     0x71, 0xd8, 0x31, 0x15},
    {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
     0xeb, 0x27, 0xb2, 0x75},
    {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3,
     0x29, 0xe3, 0x2f, 0x84},
    {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39,
     0x4a, 0x4c, 0x58, 0xcf},
    {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
     0x50, 0x3c, 0x9f, 0xa8},
    {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21,
     0x10, 0xff, 0xf3, 0xd2},
    {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d,
     0x64, 0x5d, 0x19, 0x73},
    {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
     0xde, 0x5e, 0x0b, 0xdb},
    {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62,
     0x91, 0x95, 0xe4, 0x79},
    {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea,
     0x65, 0x7a, 0xae, 0x08},
    {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
     0x4b, 0xbd, 0x8b, 0x8a},
    {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
     0x86, 0xc1, 0x1d, 0x9e},
    {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9,
     0xce, 0x55, 0x28, 0xdf},
    {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
     0xb0, 0x54, 0xbb, 0x16},
};
uint32_t round_constants[] = {0x00000001, 0x00000002, 0x00000004, 0x00000008,
                              0x00000010, 0x00000020, 0x00000040, 0x00000080,
                              0x0000001b, 0x00000036};

uint8_t aes_galois_fild[4][4] = {{0x02, 0x03, 0x01, 0x01},
                                 {0x01, 0x02, 0x03, 0x01},
                                 {0x01, 0x01, 0x02, 0x03},
                                 {0x03, 0x01, 0x01, 0x02}};

uint32_t g_function(uint32_t word, uint16_t round_num);
bool aes_expand_key(struct AesEnryptionCtx *ctx) {
  uint16_t aes_key_len = ctx->key_size_bytes;
  guchar *key = ctx->initial_key;

  //
  // for (int i = 0; i < num_row; i++) {
  //   memcpy(ctx->initial_key[i], key, num_row);
  //   key += num_row;
  // }
  //
  // uint32_t round0_key[num_row];
  // for (int i = 0; i < num_row; i++) {
  //   for (int j = 0; j < num_row; j++) {
  //     round0_key[i] += ctx->initial_key[i][j];
  //   }
  // }

  // key expansion

  uint16_t expand_key_len = (aes_key_len * ctx->no_rounds) + aes_key_len;
  uint32_t expanded_keys[expand_key_len];

  memcpy(expanded_keys, key, aes_key_len);

  uint8_t num_row = ctx->row_size;

  printf("aes key len %d expand key up to %d \n", aes_key_len, expand_key_len);

  for (int i = num_row; i <= expand_key_len; i++) {
    uint16_t round_num = (((int)floor(i / 4)) - 1);

    if ((i % num_row) == 0) {
      expanded_keys[i] = expanded_keys[i - num_row] ^
                         g_function(expanded_keys[i - 1], round_num % 10);
      continue;
    }
    expanded_keys[i] = expanded_keys[i - num_row] ^ expanded_keys[i - 1];
  }

  for (int i = 0; i <= ctx->no_rounds; i++) { // one extran key
    gchar *round_key = malloc(aes_key_len);
    memcpy(round_key, &(expanded_keys[i * 4]), aes_key_len);
    transpose_matrix(round_key);

    printf("\nround %d key ", i);
    print_aes_matrix(round_key, 4);
    ctx->roundkeys[i] = round_key;
  }

  print_hex(expanded_keys, expand_key_len);
  return true;
}

void transpose_matrix(uint8_t (*round_key)[4]) {
  gchar temp;
  for (int i = 0; i < 4; i++) {
    for (int j = i + 1; j < 4; j++) {
      temp = round_key[i][j];
      round_key[i][j] = round_key[j][i];
      round_key[j][i] = temp;
    }
  }
}
uint32_t g_func_sub_byte(uint32_t word) {
  uint8_t first_byte;
  uint32_t mask = 0xFFFFFFFF;

  for (int i = 0; i <= 3; i++) {
    uint8_t byte = ((word & mask) >> (i * 8));

    uint8_t upper4bit = (byte & 0xF0) >> 4;
    uint8_t lower4bit = (byte & 0x0F);

    uint32_t replace_byte =
        (((uint32_t)(s_box[upper4bit][lower4bit])) << (i * 8));

    word = replace_byte | (word & (~((uint32_t)0xFF << (i * 8))));
    // some crazy bit wise shit that I will
    // not remember
  }
  return word;
}

uint32_t g_function(uint32_t word, uint16_t round_num) {
  uint32_t first_byte = (word & 0x000000FF) << (3 * 8);
  // g_debug("\n word %x first bypte %x \n", word, first_byte);
  word = word >> 8;
  word = (word & 0x00FFFFFF) | first_byte;

  // g_debug("rotated %x ", word);

  word = g_func_sub_byte(word);

  // g_debug("subutityed %x %d ", word, round_num);

  return word ^ round_constants[round_num];
}

void sub_bytes(uint8_t (*block)[4]) {
  printf("before sub byte\n");
  print_aes_matrix(block, 4);

  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {

      uint16_t byte = block[i][j];
      uint8_t upper4bit = (byte & 0xF0) >> 4;
      uint8_t lower4bit = (byte & 0x0F);

      block[i][j] = s_box[upper4bit][lower4bit];
    }
  }
  printf("after sub byte\n");
  print_aes_matrix(block, 4);
}

uint8_t gf_mult(uint8_t a, uint8_t b) {
  uint8_t p = 0;
  uint8_t hi_bit_set;
  for (int i = 0; i < 8; i++) {
    if (b & 1) {
      p ^= a;
    }
    hi_bit_set = a & 0x80;
    a <<= 1;
    if (hi_bit_set) {
      a ^= 0x1b; // modulo by irreducible polynomial 0x11b
    }
    b >>= 1;
  }
  return p;
}
void shift_rows(uint8_t (*block)[4]) {

  printf("before shift row\n");
  print_aes_matrix(block, 4);
  for (int i = 1; i < 4; i++) {
    uint32_t block32 = (*(uint32_t(*)[4])block)[i];

    uint32_t right_shifted = (block32) << (32 - (i * 8));
    uint32_t left_shifted = (block32) >> ((i * 8));

    (*(uint32_t(*)[4])block)[i] = right_shifted | left_shifted;
  }

  print_aes_matrix(block, 4);

  printf("after shift row\n");
}
void mix_columns(uint8_t (*matrix)[4]) {
  printf("befroe mix columns\n");
  uint8_t matrix_sum[4][4] = {0};

  print_aes_matrix(matrix, 4);

  print_aes_matrix(aes_galois_fild, 4);

  for (int k = 0; k < 4; k++) {
    for (int i = 0; i < 4; i++) {
      for (int j = 0; j < 4; j++) {
        uint8_t mul = gf_mult(aes_galois_fild[k][j], matrix[j][i]);
        matrix_sum[k][i] = matrix_sum[k][i] ^ mul;
        // printf(" %d %d  %d  %d    \[ %d \] \[ %d \] = %x   \[ %d \] "
        //        "\[ %x \] = %x  sum = %x   %d %d\n",
        //        k, j, j, i, k, j, aes_galois_fild[k][j], j, i, matrix[j][i],
        //        matrix_sum[k][i], k, i);
      }
    }
  }
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      matrix[i][j] = matrix_sum[i][j];
    }
  }

  printf("after mix columns\n");
  print_aes_matrix(matrix, 4);
}
void add_round_key(uint8_t (*roundkey)[4], uint8_t (*block)[4]) {

  printf("add round key before: \n");

  printf("round key:\n");
  print_aes_matrix(roundkey, 4);

  printf("block :\n");
  print_aes_matrix(block, 4);

  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      block[i][j] = block[i][j] ^ roundkey[i][j];
    }
  }

  printf("after round key :\n");
  print_aes_matrix(block, 4);
}

void add_vector(uint8_t (*block)[4], uint8_t (*iv)[4]) {
  add_round_key(iv, block);
}
void add_aes_padding(uint8_t *block, uint16_t data_len, uint8_t padding_size,
                     enum mode mode) {
  block = block + data_len;

  for (int i = 0; i <= padding_size; i++) {
    if (mode == CBC)
      block[i] = padding_size - 1;
    else if (mode == CM)
      block[i] = 0;
  }
}

void aes(struct AesEnryptionCtx *ctx, uint8_t (*block)[4]) {

  add_round_key(ctx->roundkeys[0], block);

  for (int i = 1; i <= ctx->no_rounds; i++) {
    printf("round num :%d", i);
    sub_bytes(block);
    shift_rows(block);

    if (ctx->no_rounds != i)
      mix_columns(block);

    add_round_key(ctx->roundkeys[i], block);
  }
}
uint32_t encrypt_aes(struct AesEnryptionCtx *ctx, uint8_t **block_data,
                     uint16_t block_encrypt_offset, uint32_t total_packet_len) {

  printf("string encryption prooces\n");

  uint16_t block_len = total_packet_len - block_encrypt_offset;
  uint8_t padding_size = 16 - (block_len % 16);
  uint16_t to_encypt_len = block_len + padding_size;

  uint8_t(*block)[4] = block_data;

  block = (*block_data) + block_encrypt_offset;

  uint32_t data_encrytion_itration = (to_encypt_len) / 16;
  printf("%d %d %d %d  %d\n", data_encrytion_itration, padding_size,
         total_packet_len, block_len, block_encrypt_offset);

  add_aes_padding(block, block_len, padding_size, ctx->mode);

  print_hex(block, to_encypt_len);

  memcpy(ctx->recordIV, ctx->IV, ctx->iv_size);

  ctx->recordIV = ctx->IV;
  transpose_matrix(ctx->IV);

  uint8_t *counter;
  if (ctx->mode == CM) {
    counter = malloc(16);
    memcpy(counter, ctx->IV, 16);
  }

  for (int j = 0; j < data_encrytion_itration; j++) {
    transpose_matrix(block);

    if (ctx->mode == CBC) {
      add_vector(block, ctx->IV);
      aes(ctx, block);
      ctx->IV = block;
    }

    if (ctx->mode == CM) {
      aes(ctx, ctx->IV);

      add_vector(block, ctx->IV);
      increment_binary_number(counter, 16);
      memcpy(ctx->IV, counter, 16);
      // exit(0);
    }

    block = block + 4;
  }

  block = (*block_data) + block_encrypt_offset;

  for (int i = 0; i < data_encrytion_itration; i++) {
    transpose_matrix(block);
    block = block + 4;
  }

  get_random_string(&ctx->IV, ctx->iv_size, 1);
  return total_packet_len + padding_size;
}

bool init_aes(struct aes_ctx **encryption_ctx,
              struct encryption_keys *encryption_keys, enum mode mode) {

  struct AesEnryptionCtx *client_aes_ctx =
      calloc(1, sizeof(struct AesEnryptionCtx));
  client_aes_ctx->key_size_bytes = encryption_keys->key_size;
  if (client_aes_ctx->key_size_bytes == 16) {
    client_aes_ctx->no_rounds = 10;
  } else {
    return false;
  }

  client_aes_ctx->mode = mode;
  client_aes_ctx->initial_key = encryption_keys->client_write_key;

  client_aes_ctx->IV = encryption_keys->client_write_IV;

  client_aes_ctx->mac_key = encryption_keys->client_write_mac_key;

  client_aes_ctx->row_size =
      (uint8_t)((float)client_aes_ctx->key_size_bytes / 4.0);

  client_aes_ctx->mac_key_size = encryption_keys->mac_key_size;
  client_aes_ctx->iv_size = encryption_keys->iv_size;
  client_aes_ctx->key_size = encryption_keys->key_size;

  client_aes_ctx->recordIV = calloc(1, client_aes_ctx->iv_size);

  aes_expand_key(client_aes_ctx);

  struct AesEnryptionCtx *server_aes_ctx =
      calloc(1, sizeof(struct AesEnryptionCtx));
  server_aes_ctx->mode = mode;
  server_aes_ctx->key_size_bytes = encryption_keys->key_size;

  if (server_aes_ctx->key_size_bytes == 16) {
    server_aes_ctx->no_rounds = 10;
  } else {
    return false;
  }

  server_aes_ctx->initial_key = encryption_keys->server_write_key;

  server_aes_ctx->IV = encryption_keys->server_write_IV;

  server_aes_ctx->mac_key = encryption_keys->server_write_mac_key;

  server_aes_ctx->row_size =
      (uint8_t)((float)server_aes_ctx->key_size_bytes / 4.0);

  aes_expand_key(server_aes_ctx);

  server_aes_ctx->mac_key_size = encryption_keys->mac_key_size;
  server_aes_ctx->iv_size = encryption_keys->iv_size;
  server_aes_ctx->key_size = encryption_keys->key_size;

  server_aes_ctx->recordIV = calloc(1, server_aes_ctx->iv_size);

  struct aes_ctx *client_server_aes_ctx = malloc(sizeof(struct aes_ctx));
  client_server_aes_ctx->client = client_aes_ctx;
  client_server_aes_ctx->server = server_aes_ctx;

  *encryption_ctx = client_server_aes_ctx;

  return true;
}
