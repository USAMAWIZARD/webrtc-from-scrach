
#include <arpa/inet.h>
#include <sys/socket.h>
struct sockaddr_in * get_network_socket(char *ip , int port);

char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen);
int get_udp_sock_desc();
