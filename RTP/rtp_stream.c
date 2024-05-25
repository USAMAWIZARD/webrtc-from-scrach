
//https://datatracker.ietf.org/doc/html/rfc3550
/*
RTP Header

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|V=2|P|X|  CC   |M|     PT      |       sequence number       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           timestamp                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           synchronization source (SSRC) identifier          |
+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
|            contributing source (CSRC) identifiers           |
|                             ....                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

RTP payload header.

  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|F|NRI|  Type   |                                               |
+-+-+-+-+-+-+-+-+                                               |
|                                                               |
|               Bytes 2..n of a single NAL unit                 |
|                                                               |
|                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               :...OPTIONAL RTP padding        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
#include <netinet/in.h>
#include<stdbool.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include "rtp.h"
#include "../Network/network.h"

struct __attribute__((packed)) Rtp {
  unsigned int seq_no : 16;
  unsigned int pt : 7;
  unsigned int marker : 1;
  unsigned int csrc_count : 4;
  unsigned int ext : 1;
  unsigned int padding : 1;
  unsigned int v : 2;
  long int timestamp : 32;
  long int ssrc : 32;
  long int csrc : 32;
  char payload[];
};
struct __attribute__((packed)) Rtp_Payload {
    uint8_t F:1;
    uint8_t NRI:2;
    uint8_t type:5;
    char NAL[];
};
struct RtpStream* create_rtp_stream(void *video_data_callback, char* ip, int port ,struct RtpSession *rtp_session){
  struct RtpStream *newRtpStream;
  newRtpStream = malloc(sizeof(struct RtpStream));
  newRtpStream->video_data_callback = video_data_callback;
  newRtpStream->ip = ip;
  newRtpStream->port = port;
  rtp_session->streams[++rtp_session->totalStreams] = newRtpStream;
  return newRtpStream;
}

  //create a new thread and start sending rtp totalStreams
bool start_rtp_stream(struct RtpStream *rtpStream){
  rtpStream->socket_address = get_network_socket(rtpStream->ip,rtpStream->port);
  rtpStream->sockdesc = get_udp_sock_desc();
  int socket_len = sizeof(struct sockaddr_in); 
  int bytes = sendto(rtpStream->sockdesc, "12", 2, 0 ,( struct sockaddr*) (rtpStream->socket_address),socket_len);
  if(bytes == -1){
    printf("failed to send the data %d\n",errno);
  }else {
    printf("send packet\n");
  }

  return true;   
}

bool stop_rtp_stream(struct RtpStream *rtpStream){
  if(close(rtpStream->sockdesc)<0){
    printf("failed to close the RTP");
    return false;
  }
  return true;
}









