var websocket = new WebSocket("ws://192.168.0.115:3001", "echo-protocol");
var remote_peer = null;
var peer;
websocket.onopen = () => {
  console.log("websocket connection open ");
}
websocket.onclose = () => {
  console.log("websocket connection close ");
}
websocket.onmessage = async (message) => {
  message = JSON.parse(message.data);
  switch (message.command) {
    case "start":
      console.log("start")
      remote_peer = message.peer;
      if (mode == "sender") {
        await add_media();
        send_offer();
      }
      break;

    case "offer":
      console.log("recived offer +", message.offer.sdp);
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
        console.log("recived ice candidate \n" + message.candidate.candidate);
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

async function add_media() {
  var media = await navigator.mediaDevices.getUserMedia({ video: true });

  if (mode == "sender") {
    setVideo(media);
    peer.addTrack(media.getVideoTracks()[0]);
  }

}
function send_offer() {
  peer.createOffer().then(async (localdesc) => { console.log("create and send offer " + localdesc.sdp);
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
  })
}
function setVideo(video_stream) {
  let video_player = document.getElementById("video_player");
  video_player.srcObject = video_stream;
  video_player.play();
}
