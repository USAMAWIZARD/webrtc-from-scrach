var WebSocketServer = require('websocket').server;
var http = require('http');

var socket_id_map = new Map();

var last_joined_id = null;
var server = http.createServer(function(request, response) {
  response.writeHead(404);
  response.end();
});

server.listen(3001, function() {
  console.log('Signalling Server is listening on port 3001');
});

wsServer = new WebSocketServer({
  httpServer: server,
});

wsServer.getUniqueID = function() {
  function s4() {
    return Math.floor((1 + Math.random()) * 0x10000).toString(16).substring(1);
  }
  return s4() + s4() + '-' + s4();
};

wsServer.on('request', function(wsrequest) {
 // console.log(wsrequest);
  var connection = wsrequest.accept("",wsrequest.origin);

  var socket_id = wsServer.getUniqueID();
  connection.id = socket_id;
  socket_id_map.set(socket_id, connection);

   console.log(connection.id);
  if (last_joined_id != null) {
    last_ws_connection = socket_id_map.get(last_joined_id);
    if (last_ws_connection != null && last_ws_connection) {
      connection.send(JSON.stringify({ "command": "start", "peer": last_joined_id }));
      last_ws_connection.send(JSON.stringify({ "command": "start", "peer": socket_id }));
    }
    last_joined_id = null;
  }
  else {
    last_joined_id = socket_id;
  }

  connection.on('message', function(message) {
    if (message.type != 'utf8')
      return;

    var message = JSON.parse(message.utf8Data);
    peer_pair = socket_id_map.get(message.peer);
    if (peer_pair != undefined) {
      console.log("send to ", message.peer,message);
      peer_pair.send(JSON.stringify(message));
    }
    else {
      console.log("peer no longer active");
    }
  });

  connection.on('close', function(reasonCode, description) {
    console.log( ' Peer ' + connection.remoteAddress + ' disconnected.');
    if (connection.id == last_joined_id) {
      last_joined_id = null;
    }

    socket_id_map.delete(connection.id)
  });

});
