'use strict';

// TODO support ipv6
const common = require('../common');
if (!common.hasQuic)
  common.skip('missing quic');

const { createSocket } = require('quic');
const fixtures = require('../common/fixtures');
const key = fixtures.readKey('agent1-key.pem', 'binary');
const cert = fixtures.readKey('agent1-cert.pem', 'binary');
const ca = fixtures.readKey('ca1-cert.pem', 'binary');

const kServerName = 'agent2';
const kALPN = 'zzz';

// Setting `type` to `udp4` while setting `ipv6Only` to `true` is possible
// and it will throw an error.
{
  const server = createSocket({
    type: 'udp4',
    port: 0,
    ipv6Only: true,
  });

  server.on('error', common.mustCall((err) => {
    common.expectsError({
      code: 'EINVAL',
      type: Error,
      message: 'bind EINVAL 0.0.0.0',
      syscall: 'bind'
    })(err);
  }));

  server.listen({
    key,
    cert,
    ca,
    alpn: kALPN,
  });
}

// Connecting ipv6 server by "127.0.0.1" should work when `ipv6Only`
// is set to `false`.
{
  const server = createSocket({
    type: 'udp6',
    port: 0,
    ipv6Only: false,
  });

  server.listen({
    key,
    cert,
    ca,
    alpn: kALPN,
  });

  server.on('session', common.mustCall((serverSession) => {
    serverSession.on('stream', common.mustCall());
  }));

  server.on('ready', common.mustCall(() => {
    const client = createSocket({
      port: 0,
    });

    const clientSession = client.connect({
      key,
      cert,
      ca,
      address: common.localhostIPv4,
      port: server.address.port,
      servername: kServerName,
      alpn: kALPN,
    });

    clientSession.on('secure', common.mustCall(() => {
      const clientStream = clientSession.openStream({
        halfOpen: true,
      });
      clientStream.end('hello');
      clientStream.on('close', common.mustCall(() => {
        client.close();
        server.close();
      }));
    }));
  }));
}

// When the `ipv6Only` set to `true`, a client cann't connect to it
// through "127.0.0.1".
{
  const server = createSocket({
    type: 'udp6',
    port: 0,
    ipv6Only: true,
  });

  server.listen({
    key,
    cert,
    ca,
    alpn: kALPN,
  });

  server.on('ready', common.mustCall(() => {
    const client = createSocket({
      port: 0,
    });

    client.on('ready', common.mustCall());

    const clientSession = client.connect({
      key,
      cert,
      ca,
      address: common.localhostIPv4,
      port: server.address.port,
      servername: kServerName,
      alpn: kALPN,
      idleTimeout: common.platformTimeout(500),
    });

    clientSession.on('secure', common.mustNotCall());
    clientSession.on('close', common.mustCall(() => {
      client.close();
      server.close();
    }));
  }));
}
