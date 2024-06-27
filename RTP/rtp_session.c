#include "rtp.h"
#include <stdbool.h>
#include<stdlib.h>
#include <stdio.h>
struct RtpSession* create_rtp_session(){
  struct RtpSession *newRtpSession;
  newRtpSession = malloc(sizeof(struct RtpSession));
  newRtpSession->totalStreams = -1;
  return  newRtpSession;
}
//number of streams started
bool start_rtp_session(struct RtpSession *rtpSession) {
  if(rtpSession->totalStreams<0){
    printf("\n No RTP Stream in Session\n");
    return false;
  } 
  for(int i=rtpSession->totalStreams ; i>=0;i--){
    if(!start_rtp_stream(rtpSession->streams[i])){
      printf("failed to start RTP Session");
      return false;
    }
    else{
      printf("rtp stream started for session %d ", i);
    }
  }
  return true;
}
