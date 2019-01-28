'use strict';
const common = require('../common');
if (!common.hasCrypto)
  common.skip('missing crypto');

const fixtures = require('../common/fixtures');
const makeDuplexPair = require('../common/duplexpair');
const assert = require('assert');
const { TLSSocket, connect } = require('tls');

const key = fixtures.readKey('agent1-key.pem');
const cert = fixtures.readKey('agent1-cert.pem');
const ca = fixtures.readKey('ca1-cert.pem');

const { clientSide, serverSide } = makeDuplexPair();

const clientTLS = connect({
  socket: clientSide,
  ca,
  host: 'agent1'  // Hostname from certificate
});
const serverTLS = new TLSSocket(serverSide, {
  isServer: true,
  key,
  cert,
  ca
});

assert.strictEqual(clientTLS.connecting, false);
assert.strictEqual(serverTLS.connecting, false);
/*
clientTLS.on('secureConnect', common.mustCall(() => {
  console.log('X secureConnect');
  clientTLS.write('foobar', common.mustCall((err) => {
    console.log('X write cb', err);
    serverTLS.on('data', common.mustCall((data) => {
      console.log('X on data');
      assert.strictEqual(data.toString(), 'foobar');
      assert.strictEqual(clientTLS._handle.writeQueueSize, 0);
    }));
  }));
  assert.ok(clientTLS._handle.writeQueueSize > 0);
}));
return*/

// XXX test write before secureConnect on client & server side
// XXX fails because it writes multiple times, once for each secureConnect event
clientTLS.on('secureConnect', common.mustCall(() => {
  clientTLS.write('foobar', common.mustCall(() => {
    assert.strictEqual(serverTLS.read().toString(), 'foobar');
    assert.strictEqual(clientTLS._handle.writeQueueSize, 0);
  }));
  assert.ok(clientTLS._handle.writeQueueSize > 0);
}));
