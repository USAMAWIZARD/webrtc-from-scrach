CC=ccache gcc
CFLAGS=-ggdb -flto
LIBS=-lavutil -lavcodec -lavformat -lgsasl -lz -lgmp -lm  -lsrtp3
PKG_CONFIG=`pkg-config --cflags --libs libsoup-2.4 json-glib-1.0 openssl `


ifeq ($(MAKECMDGOALS),test)
	EXCLUDE=-not -name "webrtc_app.c" -not -path "./SignallingClient/*" 
else
	EXCLUDE=-not -name "test.c"  -not -path "./test/*" 
endif


SRC=$(shell find . $(EXCLUDE) -name "*.c" -not -path "./SignallingServer/*" -not -path "./GstreamerClient/*")

OBJECTS=$(SRC:.c=.o)

$(info src files $(SRC))
$(info obj files $(OBJECTS))

all:webrtc


webrtc:$(OBJECTS)
	$(CC)  $(CFLAGS) -o  $@ $(addprefix ./build/,$(^F)) $(LIBS) $(PKG_CONFIG)
 
%.o:%.c
	$(CC) $(CFLAGS) -c -o $(addprefix ./build/,$(@F)) $^ $(PKG_CONFIG)

clean:
	rm -rf ./build/*

run:
	make
	./webrtc

test:webrtc
	./webrtc

startservers:
	nohup npm start --prefix ./WebRTC_Browser_APP/ &
	npm start --prefix ./SignallingServer/



