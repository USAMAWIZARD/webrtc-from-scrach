all: rtp
rtp:./RTP/rtp_stream.c ./RTP/rtp_session.c
	gcc ./Network/network.c ./RTP/rtp_session.c ./RTP/rtp_stream.c  ./parser/h264_parser/h264_parser.c ./STUN/stun.c  ./webrtc.c -o webrtc
