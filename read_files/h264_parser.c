#include "../RTP/rtp.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
char *h264_parser_get_nal_unit(void *file,
                               void(rtp_sender_callback)(struct RtpStream *,
                                                         char *),
                               struct RtpStream *rtpStream) {
  int start_code[4] = {0, 0, 0, 1};
  int buffer_size = 10000;
  char buffer[buffer_size];
  char *nal_buffer;
  int start_code_1 = -1;
  int start_code_2 = -1;
  int start_code_index = 0;
  int nal_buffer_index = 0;
  int nal_buffer_size = 1000;
  FILE *filePtr = (FILE *)file;
  nal_buffer = (char *)malloc(buffer_size);
  while (!feof(filePtr)) {
    fread(buffer, 1, buffer_size, filePtr);
    int i = 0;
    for (; i < buffer_size; i++) {
      // printf("%d \n", buffer[i]);
      if ((int)buffer[i] == start_code[start_code_index] || (start_code_index==3 && (int)buffer[i] ==1 )) {
        start_code_index++;
      } else
        start_code_index = 0;

      if (start_code_index == 4) {
        if (start_code_1 < 0) {
          start_code_1 = i + 1;
        } else if (start_code_2 < 0) {
          start_code_2 = i;
          //          printf(" \nstart code one %d start code two %d\n ",
          //          start_code_1,      start_code_2);
          memcpy(nal_buffer + nal_buffer_index, &buffer[0] + (start_code_1),
                 start_code_2 - start_code_1);
          nal_buffer_index += (start_code_2 - 4) - start_code_1;
          nal_buffer[nal_buffer_index + 1] = '\0';
          rtp_sender_callback(rtpStream, nal_buffer);
          printf("\n=---------------------------------------------------\n");
          //for (int b = 0; b <= nal_buffer_index; b++)
          //  printf(" %x", *(nal_buffer + b));
          start_code_1 = start_code_2 + 1;
          start_code_2 = -1;
          nal_buffer_index = 0;
        }
        start_code_index = 0;
      }
    }
    if (i == buffer_size && start_code_2 == -1) {
      memcpy(nal_buffer + nal_buffer_index, &buffer[0] + (start_code_1),
             (buffer_size - 1) - start_code_1);

      nal_buffer_index += (buffer_size - 1) - start_code_1;

      start_code_1 = 0;
    }

    // printf("\n start code one  %d start code two %d\n ", start_code_1,
    //       start_code_1);
  }
  return NULL;
}
