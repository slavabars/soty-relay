import 'package:dtm_app/core/crypto/envelope_crypto.dart';
import 'package:dtm_app/core/crypto/keypair.dart';
import 'package:dtm_app/core/host/host_link.dart' show HostEndpoint;
import 'package:dtm_app/core/sync/gossip_message.dart';
import 'package:dtm_app/models/envelope.dart';
import 'package:dtm_host/host_config.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support.dart';

void main() {
  test('host A relays live to a client subscribed on hosting B', () async {
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

    final rx = await recipientKey();
    final subscriber = await connectHost(b);
    await subscriber.send(const HelloMessage(myPeerId: 'sub'));
    await subscriber.send(SubscribeMessage(since: 0, keys: [rx]));

final publisher = await connectHost(a);
    await publisher.send(const HelloMessage(myPeerId: 'pub'));

    final sender = await DtmKeyPair.generate();
    EnvelopeRelayed? relayed;
    for (var i = 0; i < 60 && relayed == null; i++) {
      final envelope = await createEnvelopeForPubKey(
        sender: sender,
        recipientX25519PubKeyHex: rx,
        plaintext: 'relay $i',
      );
      await publisher.send(PublishMessage(envelope: envelope));
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
      throw StateError('host B never relayed the envelope live');
    }
    expect(relayed.hops, 1);
    expect(a.db.has(relayed.envelope.id), isTrue);
    expect(b.db.has(relayed.envelope.id), isTrue);

    await publisher.close();
    await subscriber.close();
    await a.dispose();
    await b.dispose();
  });

  test('anti-entropy pulls envelopes published before a peer connected',
      () async {
    final a = await startServer();

    final rx = await recipientKey();
    final envelope = await envelopeFor(rx);
    final publisher = await connectHost(a);
    await publisher.send(const HelloMessage(myPeerId: 'pub'));
    await publisher.send(PublishMessage(envelope: envelope));
    await publisher.close();
    await Future<void>.delayed(const Duration(milliseconds: 200));
    expect(a.db.has(envelope.id), isTrue);

    final b = await startServer(
      config: HostConfig(
        listenAddress: '127.0.0.1',
        port: 0,
        allowInboundFederation: true,
        allowPrivateFederation: true,
        federatedPeers: [
          HostEndpoint(addr: 'ws://127.0.0.1:${a.server.boundPort}/ws'),
        ],
        federationSyncInterval: const Duration(milliseconds: 150),
      ),
    );
    final subscriber = await connectHost(b);
    await subscriber.send(const HelloMessage(myPeerId: 'sub'));
    await subscriber.send(SubscribeMessage(since: 0, keys: [rx]));

    final deadline = DateTime.now().add(const Duration(seconds: 8));
    var seen = false;
    while (!seen && DateTime.now().isBefore(deadline)) {
      for (final frame in subscriber.envelopeFrames()) {
        if (frame.envelopes.any((e) => e.id == envelope.id)) {
          seen = true;
        }
      }
      if (seen) break;
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }

    expect(seen, isTrue, reason: 'B never synced the envelope from A');
    expect(b.db.has(envelope.id), isTrue);
    final synced = subscriber
        .envelopeFrames()
        .firstWhere((f) => f.envelopes.any((e) => e.id == envelope.id));
    expect(synced.hops, 0);

    await subscriber.close();
    await a.dispose();
    await b.dispose();
  });

  test('a three-host chain relays to the far client within the hop ceiling',
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
        federatedPeers: [
          HostEndpoint(addr: 'ws://127.0.0.1:${b.server.boundPort}/ws'),
        ],
      ),
    );

    final rx = await recipientKey();
    final subscriber = await connectHost(c);
    await subscriber.send(const HelloMessage(myPeerId: 'sub'));
    await subscriber.send(SubscribeMessage(since: 0, keys: [rx]));

    final publisher = await connectHost(a);
    await publisher.send(const HelloMessage(myPeerId: 'pub'));

    final sender = await DtmKeyPair.generate();
    EnvelopeRelayed? relayed;
    for (var i = 0; i < 80 && relayed == null; i++) {
      final envelope = await createEnvelopeForPubKey(
        sender: sender,
        recipientX25519PubKeyHex: rx,
        plaintext: 'chain $i',
      );
      await publisher.send(PublishMessage(envelope: envelope));
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
      throw StateError('host C never relayed the envelope through the chain');
    }
    expect(relayed.hops, 2);
    expect(c.db.has(relayed.envelope.id), isTrue);

    await publisher.close();
    await subscriber.close();
    await a.dispose();
    await b.dispose();
    await c.dispose();
  });
}

class EnvelopeRelayed {
  final Envelope envelope;
  final int hops;

  const EnvelopeRelayed({required this.envelope, required this.hops});
}