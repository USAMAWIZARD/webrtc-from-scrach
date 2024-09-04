#include "../Utils/utils.h"
#include <glib.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
uint8_t aes_galois_fild[4][4] = {{0x02, 0x03, 0x01, 0x01},
                                 {0x01, 0x02, 0x03, 0x01},
                                 {0x01, 0x01, 0x02, 0x03},
                                 {0x03, 0x01, 0x01, 0x02}};

uint8_t matrix[4][4] = {{0x01, 0x6, 0x61, 0x3c},
                        {0x02, 0x13, 0xe0, 0x82},
                        {0x01, 0x26, 0x85, 0xea},
                        {0x01, 0x8f, 0xf6, 0xc2}};

// void print_rsa_matrix(uint8_t *ptr, uint8_t numrow) {
//   printf("\n\n");
//
//   uint8_t(*matrix)[numrow] = (uint8_t(*)[numrow])ptr;
//
//   for (int i = 0; i < numrow; i++) {
//     for (int j = 0; j < numrow; j++) {
//       printf(" %x ", matrix[i][j]);
//     }
//     printf("\n");
//   }
// }

void main() {
  // uint8_t matrix_sum[4][4] = {0};
  //
  // for (int k = 0; k < 4; k++) {
  //   for (int i = 0; i < 4; i++) {
  //     for (int j = 0; j < 4; j++) {
  //
  //       matrix_sum[k][i] += (aes_galois_fild[k][j] * matrix[j][i]);
  //       printf(" %d %d  %d  %d   sumt %d  %d %d\n", k, j, j, i, k, i,
  //              matrix_sum[k][i]);
  //     }
  //     printf("co\n");
  //   }
  // }
  // print_rsa_matrix(matrix_sum, 4);
  //

  gchar *key =
      "308204bc020100300d06092a864886f70d0101010500048204a6308204a2020100028201"
      "01009da3b942f90af45d38462fade4304c738e6503aee887b41d42c203186fb1eb269b0c"
      "9b779cd9074496cb075659cd9bd7acc208438a97717821625fffb7f761266a7589d04939"
      "8e4dba6eca69692055f57e02871ad99f43bcfbb2e58ca6a14b5a53e1ebd1601ddea42000"
      "84a8d01494dad18f90cb01aa00932eeb93adc345d1742586a54755217c9bebee79c9ecfe"
      "6a3a14d2a0abb7cc1de87341d8cdb451e8a94e6bba08d0e70959f2b8e3b32dce1f951b9d"
      "f1acf0183240c2452ef6c80a4cd988f11d3603b4282513b89a72fda79c8a09aaecd6a8f7"
      "9851f50ace0a33f67172b1d8e9beb2ec71b40a013894d0edef5fad8fb9185ea4ed636f35"
      "ecfe7c25906d0203010001028201000873b6a3567555bc73ca763efabcf389bf3e3f9ace"
      "abe1512fa5a058873b4107925e4982f9c811cc307b95454b7900873ea383f6e9c4e1ed6b"
      "78cf50877d68da3af0af616eb3a5236f6b5b9ded92dc190157185b025a62dd8c99e9c087"
      "4f499a2a64dd69c89f56b31d10cf616510081a780c47054e185e81db0d001f866df00e16"
      "71088b77b8fe39b5b4a901ded5d4c89aae3fd3c2aabd2226068c55620fac98b7dcc83332"
      "be416c5f070fb56a63461aeb8ad1637442d2b0bdecd16048d04396052a48411771823126"
      "42e02f6198a2e236cbc884fa54f18d9363c422af5cfb32c21f702dd236b471e48cb97f57"
      "1dc8e160d92e901228022afcf9e6b050d35dff02818100cfe297e52302d58437c14a8676"
      "26396401970149c3af836847150dde1fceb7c94fc87e5bea6ed9db4aff4518311853b205"
      "205d7efc9af71fe33ddfec3c12c773e079e45c68f3f8472fbb67f86c6b687240985526dd"
      "d9147a8403a6ebf23078e08de3e24b55f033e1092aaa509735f10c00e80eee969c525588"
      "7da57d5abf452302818100c220072dbebb899252da10e17c6100ed3bc356ac37a911f775"
      "fca874ca7514fdd4ed9d0907896d889a7b87ab818c198311056f19ced8e5eb7c03ae34df"
      "af8f554ee17668d2a5be307fd2e8a87522dd14212dbe927aec7f1173492b6ead3bfdcfa4"
      "9de281a68e033ac9155a6cee51227cc8cbfd45b1715c0c14de8d741ff4152f0281801cb8"
      "333fe6ac578f229cc38cfbf99fe81f081b97733f662a1bd7dec8972059e7a7ec0cf8e9d4"
      "52a8a71dc90fe48875d79c39b270feb8f1f727cfbe85c66ed9bb3a81dc789fcf44b7a0f2"
      "85149ef5dfc21906728d220d01754393b595d729b7295eb0e2ec817ce3cded1445df4864"
      "9d5e89298616941c188bd485773d7032087d028180430145191015b155954d79b82af35c"
      "9b861e55a35a0efc899aeb1bc63c3f8f8051e7b66570798a1a35a05fe2ddf35ab6f7c015"
      "6a26108dc3eb6965cf104a8bc1d9594f42bd3ac25c0132ee657f110a98311f9600ff76f4"
      "2134d6d3abff158ef506100d27cd328580dbf987ddc3a0b3b3b8a758839ecccf05c88a4c"
      "ef013c81b70281801796d64f3cc9a8f42f02abd7193432fadcd856fc685dec12f89101b6"
      "10ba8bbf9e49f220b73bcb9afdc57beead41dff2409a8a21cdef7b917eea5312dbce6cde"
      "a4e1ac90a6e915a6011c64f33df1b59e39d944d10f4d88c29fc7e7b8a66836f52b075c42"
      "e80c1c74b2af94c79e3b28a2f98f5929a6fba389dd3c8fb4c90c6c53";

  guchar *key_bin;
  uint32_t key_len = hexstr_to_char_2(&key_bin, key);
  GHmac *hmac = g_hmac_new(G_CHECKSUM_SHA256, key_bin, key_len);

  guchar *st1_bin;
  uint32_t st1_len = hexstr_to_char_2(&st1_bin, "ffff");
  g_hmac_update(hmac, st1_bin, st1_len);

  guchar *st2_bin;
  uint32_t st2_len = hexstr_to_char_2(&st2_bin, "eeee");
  g_hmac_update(hmac, st2_bin, st2_len);

  printf("%s", g_hmac_get_string(hmac));
}
