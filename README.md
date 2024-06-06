build the program 
make

play rtp using gstreamer

start the reciver first 

GST_DEBUG=3 gst-launch-1.0 -v udpsrc port=5001 caps = "application/x-rtp, media=(string)video, clock-rate=(int)90000, encoding-name=(string)H264, payload=(int)96" ! rtph264depay !  avdec_h264  ! videoconvert ! autovideosink


run the program

./webrtc
