all: rtp
rtp:./RTP/rtp_stream.c ./RTP/rtp_session.c
	gcc ./Network/sendpackets.c ./RTP/rtp_session.c ./RTP/rtp_stream.c  ./read_files/h264_parser.c  ./webrtc.c -o webrtc
