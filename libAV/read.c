// #include <libavcodec/avcodec.h>
// #include <libavcodec/codec.h>
// #include <libavcodec/codec_par.h>
// #include <libavcodec/packet.h>
// #include <libavformat/avformat.h>
// #include <stdio.h>
// #include <unistd.h>
//
// void main() {
//   AVFormatContext *ctx = avformat_alloc_context();
//   avformat_open_input(&ctx, "../sample.h264", NULL, NULL);
//   avformat_find_stream_info(ctx, NULL);
//   AVCodecParameters *codec_par = ctx->streams[0]->codecpar;
//   AVCodec *dec = avcodec_find_decoder(codec_par->codec_id);
//
//   AVCodecContext *codec_ctx = avcodec_alloc_context3(dec);
//   avcodec_parameters_to_context(codec_ctx, codec_par);
//   avcodec_open2(codec_ctx, dec, NULL);
//
//   AVPacket *pkt = av_packet_alloc();
//
//   while (av_read_frame(ctx, pkt) >= 0) {
//     printf(" %ld %ld %d \n ", pkt->pts, pkt->duration, pkt->size);
//   }
//
//   printf("%d", ctx->nb_streams);
// }
