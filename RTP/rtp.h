#include<stdbool.h>
#include <arpa/inet.h>


#ifndef _RTPH_
#define _RTPH_


struct RtpStream{
  void (*media_data_callback)(void * , void(*rtp_sender_thread)(struct RtpStream *, char *, int),struct RtpStream *);
  void *callback_data;
  int port;
  char *ip;
  char *streamState;
  struct sockaddr_in *socket_address;
  int sockdesc;
  struct Rtp * rtp_packet; 
  int socket_len; 
};
struct RtpSession{
  struct RtpStream *streams[10];
  int totalStreams;
};

struct RtpSession* create_rtp_session();
struct RtpStream* create_rtp_stream(char* ip, int port ,struct RtpSession *rtp_session,void *video_data_callback,void *callback_data);
bool start_rtp_session(struct RtpSession *rtpSession); 
bool start_rtp_stream(struct RtpStream *rtpStream);
int get_udp_sock_desc();

#endif
