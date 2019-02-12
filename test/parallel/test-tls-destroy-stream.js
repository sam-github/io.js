'use strict';

const common = require('../common');
if (!common.hasCrypto) common.skip('missing crypto');

const fixtures = require('../common/fixtures');
const makeDuplexPair = require('../common/duplexpair');
const net = require('net');
const assert = require('assert');
const tls = require('tls');

tls.DEFAULT_MAX_VERSION = 'TLSv1.3';

// This test ensures that an instance of StreamWrap should emit "end" and
// "close" when the socket on the other side call `destroy()` instead of
// `end()`.
// Refs: https://github.com/nodejs/node/issues/14605
const CONTENT = 'Hello World';
const tlsServer = tls.createServer(
  {
    maxVersion: 'TLSv1.3', // passes with 1.2
    key: fixtures.readSync('test_key.pem'),
    cert: fixtures.readSync('test_cert.pem'),
    ca: [fixtures.readSync('test_ca.pem')],
  },
  (socket) => {
    process._rawDebug('server on secureConnection', socket.getProtocol());
    socket.on('error', (err) => {
      process._rawDebug('server on error:', err);
      process.reallyExit(7);
      //XXX assert.ifError(err);
    });
    socket.on('close', common.mustCall((hadError) => {
      process._rawDebug('server on close: hadError?', hadError);
      // XXX? assert.ok(hadError);
    }));
    // XXX destroy() tears down socket before CONTENT gets flushed. probably
    // because of key update messages... confirm this with tracing. Is it
    // a bug in the test?
    process._rawDebug('server socket.write()');
    socket.write(CONTENT, (err) => {
      process._rawDebug('server write cb, err:', err);
      process.reallyExit(9);
    });
    process._rawDebug('server socket.destroy()');
    socket.destroy();
    //process.reallyExit(3);
  },
);

const server = net.createServer((conn) => {
  process._rawDebug('net server connection');
  conn.on('error', common.mustNotCall());
  // Assume that we want to use data to determine what to do with connections.
  conn.once('data', common.mustCall((chunk) => {
    process._rawDebug('net conn data');
    const { clientSide, serverSide } = makeDuplexPair();
    serverSide.on('close', common.mustCall(() => {
      conn.destroy();
    }));
    clientSide.pipe(conn);
    conn.pipe(clientSide);

    conn.on('close', common.mustCall(() => {
      clientSide.destroy();
    }));
    clientSide.on('close', common.mustCall(() => {
      conn.destroy();
    }));

    process.nextTick(() => {
      process._rawDebug('net conn unshift data');
      conn.unshift(chunk);
    });

    tlsServer.emit('connection', serverSide);
  }));
});

server.listen(0, () => {
  const port = server.address().port;
  const conn = tls.connect({ port, rejectUnauthorized: false }, () => {
    conn.on('data', common.mustCall((data) => {
      assert.strictEqual(data.toString('utf8'), CONTENT);
    }));
    conn.on('error', common.mustNotCall());
    conn.on('close', common.mustCall(() => server.close()));
  });
});
