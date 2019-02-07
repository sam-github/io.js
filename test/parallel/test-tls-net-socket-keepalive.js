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
    process.rawDebug('server write cb');
  }));
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

  process._rawDebug('client write()');
  socket.write('hello');
  process._rawDebug('client end()');
  socket.end();
}));
