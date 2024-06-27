CC=gcc
CFLAGS= -Wall -Werror
SRC=src
BIN=bin


all: rtp

rtp:./RTP/rtp_stream.c ./RTP/rtp_session.c
	gcc ./Network/network.c ./RTP/rtp_session.c ./RTP/rtp_stream.c  ./parser/h264_parser/h264_parser.c ./STUN/stun.c  ./ICE/ice.c ./webrtc.c -o webrtc  -lavutil -lavcodec -lavformat 
