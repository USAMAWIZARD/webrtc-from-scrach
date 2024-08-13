CC=gcc
CFLAGS= 
LIBS=-lavutil -lavcodec -lavformat -lgsasl -lz
PKG_CONFIG=`pkg-config --cflags --libs libsoup-2.4 json-glib-1.0  `

SRC=$(shell find . -name "*.c" -not -path "./SignallingServer/*" -not -path "./GstreamerClient/*")

OBJECTS=$(SRC:.c=.o)

$(info src files $(SRC))
$(info obj files $(OBJECTS))

all:webrtc


webrtc:$(OBJECTS)
	$(CC) -o  $@ $(addprefix ./build/,$(^F)) $(LIBS) $(PKG_CONFIG)
 
%.o:%.c
	$(CC) $(CFLAGS) -c -o $(addprefix ./build/,$(@F)) $^ $(PKG_CONFIG)

clean:
	rm -rf ./build/*

run:
	make
	./webrtc

startservers:
	nohup npm start --prefix ./WebRTC_Browser_APP/ &
	npm start --prefix ./SignallingServer/

