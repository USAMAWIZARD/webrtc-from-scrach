
#include "../RTP/rtp.h"
#include "../STUN/stun.h"
#include "../WebRTC/webrtc.h"
#include <arpa/inet.h>
#include <sched.h>
#include <sys/socket.h>

#ifndef _NETWORKH_
#define _NETWORKH_

struct network_socket {};
enum packet_protocol { STUN, RTP, RTCP };
enum subtype { BINDING_REQUEST, BINDING_RESPONSE };

struct sockaddr_in *get_network_socket(char *ip, int port);
union header {
  struct Stun *stun_header;
  struct Rtp *rtp_header;
};
union payload {
  struct StunPayload *stun_payload;
};

struct NetworkPacket {
  char *sender_ip;
  char *receiver_ip;
  int *sender_port;
  int *receiver_port;
  union header header;
  union payload payload;
  enum packet_protocol protocol;
  enum subtype subtype;
  int sock_desc;
  size_t sock_len;
  struct sockaddr *sender_sock;
  struct sockaddr *receiver_sock;
};
char *get_ip_str(const struct sockaddr *sa, char *s_ip, int *port,
                 size_t maxlen);
int get_udp_sock_desc();
void *packet_listner_thread(void *peer_v);

bool check_if_stun(struct Stun *stun_header);
struct NetworkPacket *get_parsed_packet(char *packet, int bytes);

#endif // !_NETWORKH_
