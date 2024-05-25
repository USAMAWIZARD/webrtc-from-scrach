#include<stdbool.h>
#include <arpa/inet.h>
struct RtpStream{
  void *video_data_callback;
  int port;
  char *ip;
  char *streamState;
  struct sockaddr_in *socket_address;
  int sockdesc;
};
struct RtpSession{
  struct RtpStream *streams[10];
  int totalStreams;
};

struct RtpSession* create_rtp_session();
struct RtpStream* create_rtp_stream(void *video_data_callback, char* ip, int port ,struct RtpSession *rtp_session);
bool start_rtp_session(struct RtpSession *rtpSession); 
bool start_rtp_stream(struct RtpStream *rtpStream);
int get_udp_sock_desc();
