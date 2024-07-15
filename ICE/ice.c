#include "ice.h"

#include "../Network/network.h"
#include "../STUN/stun.h"
#include "../WebRTC/webrtc.h"
#include "glib.h"
#include "glibconfig.h"
#include <arpa/inet.h>
#include <assert.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

// fix thread safty
bool parse_ice_candidate(struct RTCIecCandidates *candidate) {

  if (candidate == NULL) {
    return false;
  }
  candidate->uuid = g_uuid_string_random();
  if (candidate->candidate == NULL ||
      g_strcmp0(candidate->candidate, "") == 0) {
    char *candidate_str;

    candidate_str = g_strdup_printf(
        "candidate:%d %d %s %d %s %d typ %s generation 0 ufrag %s",
        candidate->foundation, candidate->component_id, "udp",
        candidate->priority, candidate->address, candidate->port,
        candidate->type, "H0Tz");
    candidate->candidate = candidate_str;
    return true;
  }

  char *candidate_cpy = strdup(candidate->candidate);
  char *candidate_colon = strtok(candidate_cpy, ":");
  if (candidate_colon == NULL ||
      strncmp(candidate_colon, "candidate:", 10) == 0)
    return false;

  char *foundation = strtok(0, " ");
  if (foundation == NULL)
    return false;
  candidate->foundation = atoi(foundation);

  char *component_id = strtok(0, " ");
  if (component_id == NULL)
    return false;
  candidate->component_id = atoi(component_id);

  char *transport = strtok(0, " ");
  if (transport == NULL)
    return false;
  candidate->transport = transport;

  char *priority = strtok(0, " ");
  if (priority == NULL)
    return false;
  candidate->priority = atoi(priority);

  char *address = strtok(0, " ");
  if (address == NULL)
    return false;
  candidate->address = address;

  char *port = strtok(0, " ");
  if (port == NULL)
    return false;
  candidate->port = atoi(port);

  char *type = strtok(0, " ");
  type = strtok(0, " ");
  if (type == NULL)
    return false;
  candidate->type = type;

  if (strncmp(type, "srflx", 5) == 0) {
    char *raddr = strtok(0, " ");
    raddr = strtok(0, " ");
    if (raddr == NULL)
      return true;
    candidate->raddr = raddr;

    char *rport = strtok(0, " ");
    rport = strtok(0, " ");
    if (rport == NULL)
      return true;
    candidate->rport = atoi(rport);
  }

  return true;
}

char *get_candidate_string(int foundation, int component_id, int priority,
                           char *ip, int port, char *candidate_type) {

  char *candidate;
  candidate = g_strdup_printf(
      "candidate:%d %d %s %d %s %d typ %s generation 0 ufrag %s", foundation,
      component_id, "udp", priority, ip, port, candidate_type, "H0Tz");

  return candidate;
}

// not posix complient support ipv4
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
struct RTCRtpTransceivers *get_transceiver(struct RTCRtpTransceivers *trans,
                                           int mid) {
  for (; trans != NULL && trans->mid != mid; trans = trans->next_trans) {

    printf("---------------------------------------\n");
  }

  return trans;
}
void add_local_icecandidate(struct RTCPeerConnection *peer,
                            struct RTCIecCandidates *candidate) {
  void (*on_ice_candidate_callback)(struct RTCPeerConnection *,
                                    struct RTCIecCandidates *) =
      peer->on_ice_candidate;
  if (candidate == NULL)
    goto nullcandidate;

  struct RTCRtpTransceivers *transceiver = peer->transceiver;

  transceiver = get_transceiver(transceiver, candidate->sdpMid);
  if (transceiver == NULL) {
    return;
  }

  if (transceiver->local_ice_candidate == NULL) {
    transceiver->local_ice_candidate = candidate;
    transceiver->local_ice_candidate->next_candidate = NULL;
  } else {
    struct RTCIecCandidates *last_candidate;
    for (last_candidate = transceiver->local_ice_candidate;
         last_candidate->next_candidate != NULL;
         last_candidate = last_candidate->next_candidate) {
    }
    candidate->next_candidate = NULL;
    last_candidate->next_candidate = candidate;
  }
nullcandidate:

  if (on_ice_candidate_callback != NULL)
    on_ice_candidate_callback(peer, candidate);
}
// can have seprate ports to support diffrent bundle policies
// eatch stream should have its own ice candidate
void gather_ice_candidate(struct RTCPeerConnection *peer) {

  peer->ice_connection_state = ICE_GATHRING;
  struct ifaddrs *all_network_interface;

  getifaddrs(&all_network_interface);

  if (all_network_interface < 0) {
    printf("something went wrong when gathring candidates");
    exit(0);
  }

  char *local_ip;
  int priority = 0xFFFF;
  int foundation = 42322;
  int component_id = 1;
  int port = 5020;
  char *candidate_type = "host";
  char *candidate;
  struct RTCIecCandidates *local_ice_candidate;
  // host candidates
  while ((local_ip = get_running_NIC_IP(&all_network_interface)) != NULL) {
    local_ice_candidate = calloc(1, sizeof(struct RTCIecCandidates));

    local_ice_candidate->priority = priority;
    local_ice_candidate->foundation = foundation;
    local_ice_candidate->port = port;
    local_ice_candidate->address = local_ip;
    local_ice_candidate->type = candidate_type;
    local_ice_candidate->component_id = 1;
    local_ice_candidate->sdpMid = 0;
    local_ice_candidate->candidate = "";
    local_ice_candidate->transport = "udp";
    parse_ice_candidate(local_ice_candidate);
    add_local_icecandidate(peer, local_ice_candidate);

    // listen_for_handshake(local_ip, port);
    priority--;
  }
 
  local_ice_candidate = calloc(1, sizeof(struct RTCIecCandidates));
  // server reflexive candidate
  struct stun_binding *srflx = stun_bind_request(NULL, NULL, NULL, -1);
  if (srflx != NULL) {
    local_ice_candidate->priority = priority;
    local_ice_candidate->foundation = foundation;
    local_ice_candidate->port = port;
    local_ice_candidate->address = srflx->bound_ip;
    local_ice_candidate->raddr = srflx->bound_ip;
    local_ice_candidate->rport = srflx->bound_port;
    local_ice_candidate->type = "srflx";
    local_ice_candidate->component_id = 1;
    local_ice_candidate->sdpMid = 0;
    local_ice_candidate->transport = "udp";

    parse_ice_candidate(local_ice_candidate);
    add_local_icecandidate(peer, local_ice_candidate);
  }
  // Empty candidate to signal ICE gathring completion

  add_local_icecandidate(peer, NULL);
  peer->ice_connection_state = ICE_COMPLEATE;

  return;
}
// incomplete
void add_candidate_for_each_transiver(
    struct RTCPeerConnection *peer, struct RTCIecCandidates *local_candidate) {
  for (struct RTCRtpTransceivers *transceiver = peer->transceiver;
       transceiver != NULL; transceiver = transceiver->next_trans) {

    add_local_icecandidate(peer, local_candidate);
  }
}
char *pair_local_and_remote_candidates() { return NULL; }

// void listen_for_ice_handshake(struct RTCRtpTransceivers *transceiver ,struct
// RTCIecCandidates *local_candidate,struct RTCIecCandidates *remote_candidate)
// {
//   listen_for_ice_handshake() {
//     if (stun_request)
//       sendresponse() if (response) {}
//   }
// }
bool check_pair_compatiblity(struct RTCRtpTransceivers *transceiver,
                             struct RTCIecCandidates *local_candidate,
                             struct RTCIecCandidates *remote_candidate) {

  printf("------------------------------123132 %s %s  \n",
         remote_candidate->transport, local_candidate->transport);

  if (transceiver == NULL || local_candidate == NULL ||
      remote_candidate == NULL)
    return true;

  printf("%s %s . ", local_candidate->transport, remote_candidate->transport);
  // check if already exist

  if (g_strcmp0(local_candidate->transport, remote_candidate->transport) == 0) {
    return true;
  }
  return false;
}
// return true if new pair made
bool make_pair(struct RTCRtpTransceivers *transceiver,
               struct RTCIecCandidates *rcandidate) {
  bool newpairmade = false;
  for (struct RTCIecCandidates *lcandidate = transceiver->local_ice_candidate;
       lcandidate != NULL; lcandidate = lcandidate->next_candidate) {
    // if pair exists
    if (check_pair_compatiblity(transceiver, lcandidate, rcandidate)) {
      struct CandidataPair *candidate_pair =
          calloc(1, sizeof(struct CandidataPair));
      candidate_pair->p0 = lcandidate;
      candidate_pair->p1 = rcandidate;
      candidate_pair->isvalid = false;
      candidate_pair->state = ICE_PAIR_WAITING;
      if (transceiver->pair_checklist == NULL) {
        transceiver->pair_checklist = candidate_pair;
      } else {
        struct CandidataPair *endlist = transceiver->pair_checklist;
        for (; endlist->next_pair != NULL; endlist = endlist->next_pair)
          ;
        endlist->next_pair = candidate_pair;
      }
      newpairmade = true;
    }
  }
  return newpairmade;
}
guint do_ice_handshake(struct args *arg) {

  struct RTCIecCandidates *candidate = arg->candidate;
  struct RTCRtpTransceivers *transceiver = arg->transceiver;
  if (candidate == NULL || transceiver == NULL) {
    return false;
  }
  make_pair(transceiver, candidate);
  for (struct CandidataPair *pair = transceiver->pair_checklist; pair != NULL;
       pair = pair->next_pair) {
    printf("\n ice handshake request sent form %s://%s:%d to %s://%s:%d\n",
           pair->p0->transport, pair->p0->address, pair->p0->port,
           pair->p1->transport, pair->p1->address, pair->p1->port);

    // stun_bind_request(remote_candidate, NULL, remote_candidate->address,
    //                   remote_candidate->port);
  }
  return true;
}

void ice_handshake_ended(struct RTCIecCandidates *local_candidate,
                         struct RTCIecCandidates *remote_candidate) {

  printf("\nice handchake ended  for candididate pair %s:%d \n", "fasf", 213);
}
