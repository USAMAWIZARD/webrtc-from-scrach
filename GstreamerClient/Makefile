CC=gcc
CFLAGS= 
LIBS=
PKG_CONFIG=`pkg-config --cflags --libs libsoup-2.4 gstreamer-1.0 json-glib-1.0 gstreamer-webrtc-1.0 gstreamer-sdp-1.0 `


all:webrtc


webrtc:
	$(CC) ./webrtc_recv.c  ../SignallingClient/signalling_client.c  -o ./webrtc_recv  $(LIBS) $(PKG_CONFIG)

clean:
	rm -rf ./webrtc_recv

run:
	make
	./webrtc_recv

