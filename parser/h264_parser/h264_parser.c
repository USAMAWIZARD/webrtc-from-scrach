#include "../../RTP/rtp.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
int get_nal_unit_from_h264_buffer(u_int8_t *buffer, size_t len)
{
  uint8_t start_code[4] = {0, 0, 1};
  for (int i = 0; i < len; i++)
  {
    // TODO: use better comaprison logic
//    if (memcmp(buffer[i], start_code, 3) == 0)
    {
      return i;
    }
  }
  return -1;
}
int test_nalu(uint8_t *buf, size_t len)
{
  int nalu_index = get_nal_unit_from_h264_buffer(buf, len);
  printf("%x\n", *(buf + nalu_index + 1));
  nalu_index = get_nal_unit_from_h264_buffer(buf + nalu_index + 1, len);
  printf("%x\n", *(buf + nalu_index + 1));
  nalu_index = get_nal_unit_from_h264_buffer(buf + nalu_index + 1, len);
  printf("%x\n", *(buf + nalu_index + 1));
}

char *h264_parser_get_nal_unit(void *file,
                               void(rtp_sender_callback)(struct RtpStream *,
                                                         char *, int),
                               struct RtpStream *rtpStream)
{
  int start_code[4] = {0, 0, 0, 1};
  int buffer_size = 10000;
  char buffer[buffer_size];
  char *nal_buffer;
  int start_code_1 = -1;
  int start_code_2 = -1;
  int start_code_index = 0;
  int nal_buffer_index = 0;
  int nal_buffer_size = 1000;
  int nalu_size = 4;
  FILE *filePtr = (FILE *)file;
  nal_buffer = (char *)malloc(buffer_size);
  while (!feof(filePtr))
  {
    fread(buffer, 1, buffer_size, filePtr);
    int i = 0;
    for (; i < buffer_size; i++)
    {
      if ((unsigned char)buffer[i] == start_code[start_code_index] ||
          (start_code_index == 2 && (unsigned char)buffer[i] == 1))
      {
        if (start_code_index == 2 && (unsigned char)buffer[i] == 1)
        {
          printf("got three start index in nal unit %d %d\n", buffer[i], i);
          nalu_size = 3;
          start_code_index++;
        }
        else
        {
          nalu_size = 4;
        }
        start_code_index++;
      }
      else
        start_code_index = 0;
      if (start_code_index == 4)
      {

        if (start_code_1 < 0)
        {
          start_code_1 = i + 1;
        }
        else if (start_code_2 < 0)
        {
          start_code_2 = i;
          memcpy(nal_buffer + nal_buffer_index, &buffer[0] + (start_code_1),
                 start_code_2 - start_code_1);
          nal_buffer_index += (start_code_2 - nalu_size) - start_code_1;
          unsigned char nal_type;
          memcpy(&nal_type, nal_buffer, 1);
          char mask = 0x1F; // 0001 1111
          nal_type = nal_type & mask;
          //printf("%u\n", nal_type);

          if ((unsigned int)nal_type == 8)
          {
             rtpStream->timestamp = rtpStream->timestamp + 1400;
          }

          rtp_sender_callback(rtpStream, nal_buffer, nal_buffer_index + 1);
          // printf("\n=---------------------------------------------------\n");
          // for (int b = 0; b <= nal_buffer_index; b++)
          //   printf(" %x ", *(nal_buffer + b));
          // exit(0);
          start_code_1 = start_code_2 + 1;
          start_code_2 = -1;
          nal_buffer_index = 0;
        }
        start_code_index = 0;
      }
    }
    if (i == buffer_size && start_code_2 == -1)
    {
      memcpy(nal_buffer + nal_buffer_index, &buffer[0] + (start_code_1),
             (buffer_size - 1) - start_code_1);

      nal_buffer_index += (buffer_size - 1) - start_code_1;

      start_code_1 = 0;
    }
  }
  return NULL;
}

