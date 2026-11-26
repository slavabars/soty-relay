import 'dart:async';

import 'package:dtm_app/core/crypto/envelope_crypto.dart';
import 'package:dtm_app/core/crypto/keypair.dart';
import 'package:dtm_app/core/host/host_link.dart' show HostEndpoint;
import 'package:dtm_app/core/security_limits.dart' show maxFederatedHosts;
import 'package:dtm_app/core/sync/gossip_message.dart';
import 'package:dtm_app/models/envelope.dart';
import 'package:dtm_host/host_config.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support.dart';

void main() {
  Future<String> announceOf(StartedServer server) =>
      Future.value('ws://127.0.0.1:${server.server.boundPort}/ws');

  Future<void> expectMember(
    StartedServer server,
    String addr, {
    Duration timeout = const Duration(seconds: 8),
  }) async {
    final deadline = DateTime.now().add(timeout);
    while (true) {
      if (server.db.federatedHosts().any((h) => h.addr == addr)) return;
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('member $addr was never adopted');
      }
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
  }

  test('a joining host is adopted by the seed and learns it back', () async {
    final a = await startServer();
    final b = await startServer(
      config: HostConfig(
        listenAddress: '127.0.0.1',
        port: 0,
        allowInboundFederation: true,
        allowPrivateFederation: true,
        federatedPeers: [
          HostEndpoint(addr: 'ws://127.0.0.1:${a.server.boundPort}/ws'),
        ],
      ),
    );

    final aAddr = await announceOf(a);
    final bAddr = await announceOf(b);
    await expectMember(a, bAddr);
    await expectMember(b, aAddr);
    expect(b.db.federatedHosts().any((h) => h.addr == bAddr), isFalse);

    await a.dispose();
    await b.dispose();
  });

  test('a third host joining through one seed reaches the whole mesh',
      () async {
    final a = await startServer();
    final b = await startServer(
      config: HostConfig(
        listenAddress: '127.0.0.1',
        port: 0,
        allowInboundFederation: true,
        allowPrivateFederation: true,
        federatedPeers: [
          HostEndpoint(addr: 'ws://127.0.0.1:${a.server.boundPort}/ws'),
        ],
      ),
    );
    final c = await startServer(
      config: HostConfig(
        listenAddress: '127.0.0.1',
        port: 0,
        allowInboundFederation: true,
        allowPrivateFederation: true,
        federationSyncInterval: const Duration(milliseconds: 200),
        federatedPeers: [
          HostEndpoint(addr: 'ws://127.0.0.1:${a.server.boundPort}/ws'),
        ],
      ),
    );

    final aAddr = await announceOf(a);
    final bAddr = await announceOf(b);
    final cAddr = await announceOf(c);
    await expectMember(c, aAddr);
    await expectMember(c, bAddr);
    await expectMember(b, cAddr);

    await a.dispose();
    await b.dispose();
    await c.dispose();
  });

  test('live relay spans the joined network seed → third host', () async {
    final a = await startServer();
    final b = await startServer(
      config: HostConfig(
        listenAddress: '127.0.0.1',
        port: 0,
        allowInboundFederation: true,
        allowPrivateFederation: true,
        federatedPeers: [
          HostEndpoint(addr: 'ws://127.0.0.1:${a.server.boundPort}/ws'),
        ],
      ),
    );
    final c = await startServer(
      config: HostConfig(
        listenAddress: '127.0.0.1',
        port: 0,
        allowInboundFederation: true,
        allowPrivateFederation: true,
        federationSyncInterval: const Duration(milliseconds: 200),
        federatedPeers: [
          HostEndpoint(addr: 'ws://127.0.0.1:${a.server.boundPort}/ws'),
        ],
      ),
    );

    final rx = await recipientKey();
    final subscriber = await connectHost(a);
    await subscriber.send(const HelloMessage(myPeerId: 'sub'));
    await subscriber.send(SubscribeMessage(since: 0, keys: [rx]));

    final sender = await DtmKeyPair.generate();
    EnvelopeRelayed? relayed;
    for (var i = 0; i < 80 && relayed == null; i++) {
      final envelope = await createEnvelopeForPubKey(
        sender: sender,
        recipientX25519PubKeyHex: rx,
        plaintext: 'across $i',
      );
      final publisher = await connectHost(c);
      await publisher.send(const HelloMessage(myPeerId: 'pub'));
      await publisher.send(PublishMessage(envelope: envelope));
      await publisher.close();
      await Future<void>.delayed(const Duration(milliseconds: 100));
      for (final frame in subscriber.envelopeFrames()) {
        for (final got in frame.envelopes) {
          if (got.id == envelope.id) {
            relayed = EnvelopeRelayed(envelope: got, hops: frame.hops);
          }
        }
      }
    }
    if (relayed == null) {
      throw StateError('subscriber on the seed never got the envelope '
          'published through the third host');
    }
    expect(a.db.has(relayed.envelope.id), isTrue);
    expect(b.db.has(relayed.envelope.id), isTrue);
    expect(c.db.has(relayed.envelope.id), isTrue);

    await subscriber.close();
    await a.dispose();
    await b.dispose();
    await c.dispose();
  });

  test('a non-federated client cannot inject network members', () async {
    final a = await startServer();
    final client = await connectHost(a);
    await client.send(const HelloMessage(myPeerId: 'dev'));
    await client.send(
      const NetworkMessage(
        hosts: [HostEndpoint(addr: 'ws://127.0.0.1:9/ws')],
      ),
    );
    await Future<void>.delayed(const Duration(milliseconds: 200));
    expect(a.db.federatedHosts(), isEmpty);

    await client.close();
    await a.dispose();
  });

  test('an announced host without dtm-net capability is not adopted',
      () async {
    final a = await startServer();
    final client = await connectHost(a);
    await client.send(
      const HelloMessage(
        myPeerId: 'legacy-host',
        capabilities: ['dtm-host'],
        announce: 'ws://127.0.0.1:9/ws',
      ),
    );
    await client.send(
      const NetworkMessage(
        hosts: [HostEndpoint(addr: 'ws://127.0.0.1:11/ws')],
      ),
    );
    await Future<void>.delayed(const Duration(milliseconds: 200));
    expect(a.db.federatedHosts(), isEmpty);

    await client.close();
    await a.dispose();
  });

  test('an oversized network frame drops the connection', () async {
    final a = await startServer();
    final client = await connectHost(a);
    await client.send(const HelloMessage(myPeerId: 'dev'));
    final hosts = <HostEndpoint>[
      for (var i = 0; i < maxFederatedHosts + 1; i++)
        HostEndpoint(addr: 'ws://127.0.0.1:$i/ws'),
    ];
    await client.send(NetworkMessage(hosts: hosts));
    await client.waitClosed();
    expect(a.db.federatedHosts(), isEmpty);

    await a.dispose();
  });
}

class EnvelopeRelayed {
  final Envelope envelope;
  final int hops;

  const EnvelopeRelayed({required this.envelope, required this.hops});
}