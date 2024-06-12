#ifndef __file_reader__
#define __file_reader__
char * h264_parser_get_nal_unit(void *file , void (senderCallback)(struct RtpStream*), struct RtpStream *rtpStream);
#endif