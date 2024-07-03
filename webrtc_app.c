#include "./ICE/ice.h"
#include "./RTP/rtp.h"
#include "./STUN/stun.h"
#include "./SignallingClient/signalling_client.h"
#include "./WebRTC/webrtc.h"
#include "./parser/h264_parser/h264_parser.h"
#include <glib.h>
#include <libavcodec/avcodec.h>
#include <libavcodec/codec.h>
#include <libavcodec/codec_par.h>
#include <libavcodec/packet.h>
#include <libavformat/avformat.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
void user_defined_read_data(char *file_name,
                            void(send_rtp_packet)(struct RtpStream *,
                                                  unsigned char *, int),
                            struct RtpStream *rtpStream) {

  AVFormatContext *ctx = avformat_alloc_context();
  if (avformat_open_input(&ctx, file_name, NULL, NULL)) {
    exit(0);
  }
  avformat_find_stream_info(ctx, NULL);

  AVCodecParameters *codec_par = ctx->streams[0]->codecpar;

  AVCodec *dec = avcodec_find_decoder(codec_par->codec_id);

  AVCodecContext *codec_ctx = avcodec_alloc_context3(dec);
  avcodec_parameters_to_context(codec_ctx, codec_par);
  avcodec_open2(codec_ctx, dec, NULL);

  AVPacket *pkt = av_packet_alloc();

  while (av_read_frame(ctx, pkt) >= 0) {
    static int i = 1;
    rtpStream->timestamp += 3000;
    h264_parser_get_nal_unit(pkt->data, pkt->size, send_rtp_packet, rtpStream);
    ;
    // if(i==4)
    // exit(0);
    //
    // i++;
  }
}

gint main(gint argc, gchar **argv) {

  static GMainLoop *main_loop;
  // struct RtpSession *rtpSession = create_rtp_session();
  // char *loopback_ip = "127.0.0.1";
  // void *filePtr = fopen("./sample.h264", "rb");
  // if (filePtr == NULL) {
  //   printf("file not found ");
  // }
  //
  // struct RtpStream *rtpStream = create_rtp_stream(
  //   "127.0.0.1", 5001, rtpSession, &user_defined_read_data, "./sample.h264");
  // stun_bind_request(loopback_ip);
  // gather_ice_candidate(NULL);
  //  start_rtp_session(rtpSession);

  websocket_connect("127.0.0.1", 3001);

  struct RTCPeerConnection *peer = NEW_RTCPeerConnection();
  struct MediaStreamTrack *video_track = NEW_MediaTrack(
      "video", "video NEW_MediaTrack", &user_defined_read_data, NULL);

  add_track(peer, video_track);
  create_offer(peer);

  main_loop = g_main_loop_new(NULL, FALSE);
  g_main_loop_run(main_loop);
  g_main_loop_unref(main_loop);

}
