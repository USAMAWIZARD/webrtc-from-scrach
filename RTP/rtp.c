#include<stdlib.h>
#include<stdio.h>
struct Rtp {
   unsigned int v:2;
   unsigned int padding:1;
   unsigned int ext:1;
   unsigned int  csrc_count:4;
   unsigned int marker:1;
   unsigned int pt:6;
   unsigned int seq_no:15; 
   long int timestamp:32;
   long int ssrc:32;
   long int csrc:32;
   long int hader_ex:32;
   char *payload; 
};

struct Rtp*  create_rtp_packet(){
    static int  seqno=0;
    struct Rtp * rtp_packet;
    rtp_packet=(struct  Rtp*) malloc(sizeof(struct Rtp));
    rtp_packet->v=0;
    rtp_packet->padding=0;
    rtp_packet->ext=0;
    rtp_packet->csrc_count=0;
    rtp_packet->pt=0;
    rtp_packet->seq_no=seqno;
    rtp_packet->timestamp=0;
    rtp_packet->ssrc=0;
    rtp_packet->csrc=0;
    rtp_packet->hader_ex=0;
    rtp_packet->payload="1";
    // sprintf("RTP Version: %d, SSRC: %d, Payload Type: %s, Seq Number: %d, CSRC Count: %d, Payload Length: %d Marker: %v",
	// 	rtp_packet->v, rtp_packet->ssrc, rtp_packet->PayloadType, rtp_packet->SequenceNumber, len(rtp_packet->CSRC), len(p.Payload), rtp_packet->Marker)
    seqno++;
    return rtp_packet;
}
