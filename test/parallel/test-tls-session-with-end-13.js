'use strict';

// Minimal repro of end bug surfacing in test/parallel/test-tls-ticket-cluster.js

const assert = require('assert');
const tls = require('tls');
const cluster = require('cluster');
const fixtures = require('../common/fixtures');

if (cluster.isMaster) {
  let session = null;
  let port = null;
  let count = 0;

  function shoot() {
    console.error('[master] connecting', port, 'session?', !!session);
    const c = tls.connect(port, {
      session,
      rejectUnauthorized: false
    }).on('data', () => {
      console.log('client on data');
    }).on('error', (err) => {
      console.log('client on error');
      assert.ifError(err);
    }).on('close', () => {
      count++;
      console.log('client on close', count);
      if (count < 2)
        shoot();
      else
        cluster.disconnect();
    }).once('session', (_) => {
      console.log('client on session');
      session = _;
    });
  }

  const worker = cluster.fork();

  worker.on('message', (msg) => {
    console.error('[master] got %j', msg);
    port = msg.port;
    shoot();
  });

  return;
}

const key = fixtures.readSync('agent.key');
const cert = fixtures.readSync('agent.crt');

const options = { key, cert };

const server = tls.createServer(options, (c) => {
  console.log('worker', 'reused?', c.isSessionReused(), 'proto', c.getProtocol());
  c.on('error', (err) => {
    console.log('server on error');
    assert.ifError(err);
  });
  c.end('bye');
  if (c.isSessionReused())
    server.close()
});

server.listen(0, () => {
  const { port } = server.address();
  process.send({
    msg: 'listening',
    port,
  });
});
