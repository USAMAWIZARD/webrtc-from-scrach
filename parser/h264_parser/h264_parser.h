#pragma once
#ifndef __file_reader__
#define __file_reader__

#include "../../RTP/rtp.h"
char *h264_parser_get_nal_unit(uint8_t *au_buffer, int buffer_size,
                               void(on_parsed_data)(struct RtpStream *,
                                                    unsigned char *, int),
                               struct RtpStream *rtpStream);
void file_parse(void *file,
                void(on_parsed_data)(struct RtpStream *, unsigned char *, int),
                struct RtpStream *rtpStream);

#endif
