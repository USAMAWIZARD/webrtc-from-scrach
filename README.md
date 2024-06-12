
# RTP Streaming with GStreamer

## Build the Program

1. git clone https://github.com/USAMAWIZARD/webrtc-from-scrach.git
2. Run the following command to build the program:

   ```sh
   make
   ```

## Start the Receiver

Before running the RTP stream, start the receiver with the following command:

```sh
GST_DEBUG=3 gst-launch-1.0 -v udpsrc port=5001 caps="application/x-rtp, media=(string)video, clock-rate=(int)90000, encoding-name=(string)H264, payload=(int)96" ! rtph264depay ! avdec_h264 ! videoconvert ! autovideosink
```

## Run the Program

Once the receiver is started, run your program with the following command:

```sh
./webrtc
```
