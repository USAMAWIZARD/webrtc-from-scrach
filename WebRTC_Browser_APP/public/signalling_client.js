var websocket = new WebSocket("ws://192.168.0.115:3001");
var remote_peer = null;
var peer;
websocket.onopen = () => {
  console.log("websocket connection open ");
}
websocket.onclose = () => {
  console.log("websocket connection close ");
}
function is_sender_mode(mode) {
  return mode.includes("send")
}
websocket.onmessage = async (message) => {
  message = JSON.parse(message.data);
  switch (message.command) {
    case "start":
      console.log("start")
      remote_peer = message.peer;
      if (is_sender_mode(mode)) {
        await add_media();
        await add_media();
        send_offer();
      }
      //else
      //  await add_media();
      //await add_media("audio");
      break;
    case "offer":
      console.log("recived offer +", message.offer);
      peer.setRemoteDescription(message.offer).then(() => {
        send_answer();
      });
      break;
    case "answer":
      console.log("recived answer :" + message.answer.sdp);
      await peer.setRemoteDescription(message.answer);
      break;
    case "candidate":
      if (message.candidate != null)
        console.log("recived ice candidate \n");
      console.log(message.candidate);
      await peer.addIceCandidate(message.candidate);
  }
}

(async () => {

  peer = new RTCPeerConnection({
    iceServers: [
      {
        urls: "stun:stun.l.google.com:19302"
      }
    ]
  }
  );
  peer.onsignalingstatechange = (e) => {
    //console.log(e);
  }
  peer.onicecandidate = (({ candidate }) => {
    if (candidate != null)
      console.log(candidate);
    websocket.send(JSON.stringify({ "command": "candidate", "candidate": candidate, "peer": remote_peer }));
  });
  peer.ontrack = (media_track) => {
    let track = media_track.track;
    console.log("new track added of kind", track.kind, track.id);
    let media_stream = new MediaStream([track]);
    setVideo(media_stream);
  }
})();

async function add_media(type) {
  if (type == "video" || type == undefined || type == null) {
    media = await navigator.mediaDevices.getUserMedia({ video: true });
    setVideo(media);
    peer.addTrack(media.getVideoTracks()[0]);
    return;
  }
  else if (type == "audio") {
    media = await navigator.mediaDevices.getUserMedia({ audio: true });
    peer.addTrack(media.getAudioTracks()[0]);
    console.warn("audio aded");
    return;
  }

  //stream1 = media.getVideoTracks()[0].clone();
  //peer.addTrack(stream1);

}
function send_offer() {
  peer.createOffer().then(async (localdesc) => {
    console.log("create and send offer " + localdesc.sdp);
    peer.setLocalDescription(localdesc).then(() => {
      websocket.send(JSON.stringify({ "command": "offer", "offer": localdesc, "peer": remote_peer }));
    });
  });
}
function send_answer() {
  peer.createAnswer().then(async (answer) => {
    console.log(" create and send answer : " + answer.sdp);
    await peer.setLocalDescription(answer).then(() => {
      websocket.send(JSON.stringify({ "command": "answer", "answer": answer, "peer": remote_peer }));
    })
  });
}
function setVideo(video_stream) {
  let video_player = document.getElementById("video_player");
  video_player.srcObject = video_stream;
  video_player.play();
}
