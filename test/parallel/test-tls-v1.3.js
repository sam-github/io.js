'use strict';

const common = require('../common');
const fixtures = require('../common/fixtures');

const {
  assert, connect, keys
} = require(fixtures.path('tls-connect'));

// Use ec10 and agent10, they are the only identities with intermediate CAs.
const client = keys.ec10;
const server = keys.agent10;

// The certificates aren't for "localhost", so override the identity check.
function checkServerIdentity(hostname, cert) {
  assert.strictEqual(hostname, 'localhost');
  assert.strictEqual(cert.subject.CN, 'agent10.example.com');
}

connect({
  client: {
    ca: server.ca,
    checkServerIdentity,
  },
  server: {
    //enableTrace: true,
    key: server.key,
    cert: server.cert,
    ca: client.ca,
  },
}, function(err, pair, cleanup) {
  console.log('client', pair.client.err);
  console.log('server', pair.server.err);
  process.exit(9);
  assert.ifError(err);
  const c = pair.client.conn;
  const s = pair.server.conn;

  c.write('farewell');
  s.on('data', common.mustCall((d) => {
    console.log('S: %s', d)
    return cleanup();
  }));
});

