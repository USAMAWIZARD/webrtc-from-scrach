
This project tries to implement a very minamal webrtc implementation without considering any security details in RFC just to learn and understand in depth how WebRTC works  <br>

this will just try to make a WebRTC connection from another peer and send a stream in the simplest way possible <br>

# WebRTC Streaming from Scrach implementtion to Gstreamer Client 
sending a basic video from webrtc scrach implementation to a Gstreamer WebRTC Client.

## Build the Program

1. git clone https://github.com/USAMAWIZARD/webrtc-from-scrach.git
2. Run the following command to build the program:

Build Scrach WebRTC implementation <br>
``` 
make
 ```

Build Gstreamer Client WebRTC <br>

```
cd GstreamerClient
make 
```


## Start Signalling Server
```
cd SignallingServer/
npm i 
npm start 
```


## Start Scrach implementation (sender)


```sh
./webrtc
```

## Start Gstreamer Client (receiver)

Once the receiver is started, run your program with the following command:

```sh
cd ./GstreamerClient
./webrtc_recv
```

now WebRTC Scrach implementation Will send a video to Gstreamer Client.

## TODO 
add basic security checks
refactor implementation
update ICE DTLS WebRTC connection states
