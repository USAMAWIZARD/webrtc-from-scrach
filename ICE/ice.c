#include "ice.h"

#include "../Network/network.h"
#include "../STUN/stun.h"
#include <arpa/inet.h>
#include <assert.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
//    candidate-attribute   = "candidate" ":" foundation SP component-id SP
//                            transport SP
//                            priority SP
//                            connection-address SP     ;from RFC 4566
//                            port         ;port from RFC 4566
//                            SP cand-type
//                            [SP rel-addr]
//                            [SP rel-port]
//                            *(SP extension-att-name SP
//                                 extension-att-value)
// candidate:2764676115 1 udp 2122194687 192.168.0.110 37515 typ host generation
// 0 ufrag 0KCc network-id 2 network-cost 10

// not posix complient support ipv4

char *get_candidate_string(int foundation, int component_id, int priority,
                           char *ip, int port);
char *get_running_NIC_IP(struct ifaddrs **network_interface) {

  while (*network_interface != NULL) {
    char *ip = malloc(16);

    ip =
        get_ip_str((*network_interface)->ifa_addr, ip, sizeof(struct sockaddr));
    unsigned int nic_status = (*network_interface)->ifa_flags;
    bool is_running = ((nic_status & IFF_RUNNING) == IFF_RUNNING) &&
                      ((nic_status & IFF_LOOPBACK) != IFF_LOOPBACK);

    if ((*network_interface)->ifa_addr->sa_family == AF_INET6 || ip == NULL ||
        !is_running) {

      *network_interface = (*network_interface)->ifa_next;
      continue;
    }

    *network_interface = (*network_interface)->ifa_next;
    return ip;
  }

  return NULL;
}

void gather_ice_candidate(void *(callback)()) {

  struct ifaddrs *all_network_interface;

  getifaddrs(&all_network_interface);

  if (all_network_interface < 0) {
    printf("something went wrong when gathring candidates");
    exit(0);
  }

  char *local_ip;
  int priority = 0xFFFF;
  int foundation = 0;
  int component_id = 0;
  static int port = 50000;

  // host candidates
  while ((local_ip = get_running_NIC_IP(&all_network_interface)) != NULL) {
    get_candidate_string(foundation, component_id, priority, local_ip, port);
    port++;

    priority--;
  }

  // server reflexive candidate
  struct stun_binding *srflx = stun_bind_request(NULL);
  get_candidate_string(foundation, component_id, priority, srflx->bound_ip,
                       srflx->bound_port);

  // Empty candidate to signal ICE gathring completion
  struct stun_binding *empty_candidate = stun_bind_request(NULL);
  get_candidate_string(foundation, component_id, priority, srflx->bound_ip,
                       srflx->bound_port);


  return;
}

char *get_candidate_string(int foundation, int component_id, int priority,
                           char *ip, int port) {

  char *candidate = malloc(60);
  sprintf(candidate, "candidate:%d %d %s %d %s %d typ %s ", foundation,
          component_id, "udp", priority, ip, port, "srflx");
  printf("%s\n", candidate);

  return candidate;
}

char *pair_local_and_remote_candidates() {
  return NULL;
}

char *fourway_handshake() {

  return NULL;
}
