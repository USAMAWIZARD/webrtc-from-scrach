#include "./RTP/rtp.h"
#include <string.h>
#include <stdio.h>
void callback(){

}
int main(){
  struct RtpSession *rtpSession = create_rtp_session();
  struct RtpStream *rtpStream = create_rtp_stream(callback, "127.0.0.1", 5001, rtpSession);

  start_rtp_session(rtpSession);   
}
