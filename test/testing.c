#include <stdint.h>
#include <stdio.h>
uint8_t aes_galois_fild[4][4] = {{0x02, 0x03, 0x01, 0x01},
                                 {0x01, 0x02, 0x03, 0x01},
                                 {0x01, 0x01, 0x02, 0x03},
                                 {0x03, 0x01, 0x01, 0x02}};

uint8_t matrix[4][4] = {{0x01, 0x6, 0x61, 0x3c},
                        {0x02, 0x13, 0xe0, 0x82},
                        {0x01, 0x26, 0x85, 0xea},
                        {0x01, 0x8f, 0xf6, 0xc2}};

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

void main() {
  uint8_t matrix_sum[4][4] = {0};

  for (int k = 0; k < 4; k++) {
    for (int i = 0; i < 4; i++) {
      for (int j = 0; j < 4; j++) {
        matrix_sum[k][i] += (aes_galois_fild[k][j] * matrix[j][i]);
        printf(" %d %d  %d  %d   sumt %d  %d %d\n", k, j, j, i, k, i,
               matrix_sum[k][i]);
      }
      printf("co\n");
    }
  }
  print_rsa_matrix(matrix_sum, 4);
}
