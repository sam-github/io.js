'use strict';

const common = require('../common');
if (!common.hasCrypto)
  common.skip('missing crypto');

const fixtures = require('../common/fixtures');
const tls = require('tls');
const net = require('net');

// This test ensures that when tls sockets are created with `allowHalfOpen`,
// they won't hang.
const key = fixtures.readKey('agent1-key.pem');
const cert = fixtures.readKey('agent1-cert.pem');
const ca = fixtures.readKey('ca1-cert.pem');
const options = {
  maxVersion: 'TLSv1.3',
  key,
  cert,
  ca: [ca],
};

const server = tls.createServer(options, common.mustCall((conn) => {
  process._rawDebug('server on handshake')
  server.close();
  process._rawDebug('server write()');
  conn.write('hello', common.mustCall(() => {
    // XXX this cb never occurs
    process._rawDebug('server write cb');
  }));
/*
server on handshake
NET 31303: SERVER _emitCloseIfDrained
NET 31303: SERVER handle? false   connections? 1
server write()
NET 31303: Socket.prototype._writeGeneric false false
server TLSWrap::DoWrite() established? 1 count 1 empty? 0
    SSL_write([0].len 5) => 5
server TLSWrap::EncOut() established? 1 pending=0 write_size=0 waiting? 0
  // SSL_write() => 5, but BIO_pending(enc_out_) == 0... I guess the data
  // is buffered, and isn't going to be ready until after our current
  // TLSWrap::SSLInfoCallback() returns?
server TLSWrap::InvokeQueued(0, (null)) scheduled? 1 current? 0x55e3bbeced80
STREAM 31303: onWriteComplete 0 undefined
...TLSWrap::InvokeQueued()
...TLSWrap::DoWrite()
NET 31303:   after write: req.async? true size= 5
STREAM 31303: resume
*/
  conn.on('end', () => process._rawDebug('server on end'));
  conn.on('data', () => process._rawDebug('server on data'));
  conn.on('data', common.mustCall()); // XXX fails on 1.3!
  conn.on('close', () => process._rawDebug('server on close'));
  process._rawDebug('server end()');
  // XXX this never causes TLSWrap::DoShutdown()
  conn.end();
})).listen(0, common.mustCall(() => {
  const netSocket = new net.Socket({
    allowHalfOpen: true,
  });

  const socket = tls.connect({
    socket: netSocket,
    rejectUnauthorized: false,
  });

  const { port, address } = server.address();

  // Doing `net.Socket.connect()` after `tls.connect()` will make tls module
  // wrap the socket in StreamWrap.
  netSocket.connect({
    port,
    address,
  });

  socket.on('secureConnect', () => process._rawDebug('client on handshake'));
  socket.on('end', () => process._rawDebug('client on end'));
  socket.on('data', () => process._rawDebug('client on data'));
  socket.on('close', () => process._rawDebug('client on close'));


  // XXX early exit so I can see just server side debugging
  // return socket.on('data', () => process.reallyExit(9));

  process._rawDebug('client write()');
  socket.write('hello');
  process._rawDebug('client end()');
  socket.end();
}));
