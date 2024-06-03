#include "./RTP/rtp.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "read_files/file_reader.h"

int main(){
  struct RtpSession *rtpSession = create_rtp_session();
  void *filePtr = fopen("./sample.h264", "rb");
  if(filePtr ==NULL){
    printf("file not found ");
  }
  struct RtpStream *rtpStream = create_rtp_stream("127.0.0.1", 5001, rtpSession,&h264_parser_get_nal_unit , filePtr);

  start_rtp_session(rtpSession);   
}
