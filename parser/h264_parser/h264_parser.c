#include "../../RTP/rtp.h"
#include <fcntl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
enum NAL_TYPE {
  NAL_NOT_FOUND = -1,
  NAL_BUFFER_END = 0,
  NAL_THREE = 3,
  NAL_FOUR = 4
};
int start_code[4] = {0, 0, 0, 1};

enum NAL_TYPE check_if_nal(unsigned char buffer, int *start_code_index) {
  int nal_type = 0;
  if (buffer == start_code[*start_code_index] ||
      (*start_code_index == 2 && buffer == 1)) {
    if (*start_code_index == 2 && buffer == 1) {
      // printf("got three start index in nal unit %d \n", buffer);
      *start_code_index += 2;
      nal_type = NAL_THREE;
    } else {
      *start_code_index += 1;
      nal_type = NAL_FOUR;
    }
  } else
    *start_code_index = 0;

  if (*start_code_index == 4) {
    *start_code_index = 0;
    return nal_type;
  }
  return NAL_NOT_FOUND;
}
unsigned char get_nal_type(char nal_first_byte) {
  char mask = 0x1F; // 0001 1111
  nal_first_byte = nal_first_byte & mask;
  printf("%u\n", nal_first_byte);
  return nal_first_byte;
}

char *h264_parser_get_nal_unit(char *au_buffer, int buffer_size,
                               void(on_parsed_data)(struct RtpStream *,
                                                    unsigned char *, int),
                               struct RtpStream *rtpStream) {
  unsigned char *nal_buffer;
  int start_code_1 = -1;
  int start_code_2 = -1;
  int start_code_index = 0;

  nal_buffer = (unsigned char *)malloc(buffer_size);

  for (int i = 0; i < buffer_size; i++) {
    int start_code_len = (i == buffer_size - 1)
                             ? NAL_BUFFER_END
                             : check_if_nal(au_buffer[i], &start_code_index);
    if (start_code_len != -1) {
      if (start_code_1 < 0) {
        start_code_1 = i + 1;
      } else if (start_code_2 < 0) {
        start_code_2 = i;

        if (start_code_len == NAL_BUFFER_END) {
          rtpStream->rtp_packet->marker = 1;
          //printf("1 -- %d\n", rtpStream->rtp_packet->marker);
        } else {
          rtpStream->rtp_packet->marker = 0;
          //printf("0 -- %d\n", rtpStream->rtp_packet->marker);
        }

        int nal_size = ((start_code_2 - start_code_1) - start_code_len) + 1;
        memcpy(nal_buffer, &au_buffer[0] + (start_code_1), nal_size);
        // get_nal_type(nal_buffer[-1]);
        on_parsed_data(rtpStream, nal_buffer, nal_size);
        // printf("\n=---------------------------------------------------\n");
        // for (int b = 0; b < nal_size; b++)
        //   printf(" %x ", *(nal_buffer + b));
        //   exit(0);
        //          sleep(4);
        start_code_1 = start_code_2 + 1;
        start_code_2 = -1;
      }
    }
  }
  // printf("-0-00000000000000000000000000000000000000");
  //  printf("\n=---------------------------------------------------\n");
  //        for (int b = 0; b < buffer_size; b++)
  //          printf(" %x ", *(au_buffer + b));
       
  return NULL;
}

void file_parse(void *file,
                void(on_parsed_data)(struct RtpStream *, unsigned char *, int),
                struct RtpStream *rtpStream) {
  int buffer_size = 10000;
  FILE *filePtr = (FILE *)file;
  char buffer[buffer_size];

  while (!feof(filePtr)) {
    fread(buffer, 1, buffer_size, filePtr);
    h264_parser_get_nal_unit(buffer, buffer_size, on_parsed_data, rtpStream);
  }
}