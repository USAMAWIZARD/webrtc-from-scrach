#include "./RTP/rtp.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "./parser/h264_parser/h264_parser.h"
#include "./STUN/stun.h" 
int main(){
  struct RtpSession *rtpSession = create_rtp_session();
  char* loopback_ip = "127.0.0.1";
  void *filePtr = fopen("./video.h264", "rb");
  if(filePtr ==NULL){
    printf("file not found ");
  }

  struct RtpStream *rtpStream = create_rtp_stream("127.0.0.1", 5001, rtpSession,&h264_parser_get_nal_unit , filePtr);
  stun_bind_request(loopback_ip);
 // start_rtp_session(rtpSession);   
}
