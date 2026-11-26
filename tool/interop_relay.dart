// Interop check against a running dtm_relay (host/relay-owrt/).
//
//   cd host && dart run tool/interop_relay.dart ws://127.0.0.1:13100/ws
//
// Uses the app's real GossipMessage, Envelope and crypto code, so a pass
// means the Go relay accepts app frames and the app parser accepts its
// answers. Not part of `flutter test`; run it after any wire change.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:dtm_app/core/crypto/envelope_crypto.dart';
import 'package:dtm_app/core/crypto/keypair.dart';
import 'package:dtm_app/core/sync/gossip_message.dart';

Future<void> main(List<String> args) async {
  final url = args.isEmpty ? 'ws://127.0.0.1:13100/ws' : args.first;
  final publisher = await _C.connect(url);
  final subscriber = await _C.connect(url);

  final sender = await DtmKeyPair.generate();
  final recipient = await DtmKeyPair.generate();
  final xA = await sender.x25519PublicKeyHex;
  final xB = await recipient.x25519PublicKeyHex;

  await publisher.send(const HelloMessage(
    myPeerId: 'interop-A',
    myAddrs: ['/ip4/192.168.1.50/tcp/4010'],
  ));
  final welcomeA = await publisher.waitFor<WelcomeMessage>((_) => true);
  _check(welcomeA.capabilities.contains('dtm-tracker'), 'A tracker cap');
  _check(welcomeA.capabilities.contains('dtm-live'), 'A live cap');
  _check(welcomeA.maxEnvelopeSize > 0, 'A maxEnvelopeSize');
  await publisher.send(SubscribeMessage(since: 0, keys: [xA]));
  await publisher.waitFor<EnvelopesMessage>((m) => m.done);

  await subscriber.send(const HelloMessage(
    myPeerId: 'interop-B',
    capabilities: [dtmPresence],
    myAddrs: ['/ip4/192.168.1.51/tcp/4010'],
  ));
  final welcomeB = await subscriber.waitFor<WelcomeMessage>((_) => true);
  _check(welcomeB.identity != null, 'B identity present');
  await subscriber.send(SubscribeMessage(since: 0, keys: [xB]));
  await subscriber.waitFor<EnvelopesMessage>((m) => m.done);

  final presence = await subscriber.waitFor<PresenceMessage>(
    (m) => m.online.contains(xB),
  );
  _check(presence.at > 0, 'presence timestamp');

  final env = await createEnvelopeForPubKey(
    sender: sender,
    recipientX25519PubKeyHex: xB,
    plaintext: 'interop hello',
  );
  await publisher.send(PublishMessage(envelope: env));
  final ack = await publisher.waitFor<PublishedMessage>((m) => m.id == env.id);
  _check(ack.accepted, 'PUBLISH accepted');
  final relayed = await subscriber.waitFor<EnvelopesMessage>(
    (m) => m.envelopes.any((e) => e.id == env.id),
  );
  _check(relayed.envelopes.single.id == env.id, 'live relay delivery');

  await publisher.send(PublishMessage(envelope: env));
  final dup = await publisher.waitFor<PublishedMessage>(
    (m) => m.id == env.id && !m.accepted,
  );
  _check(!dup.accepted, 'duplicate rejected');

  final slice = await createEnvelopeForPubKey(
    sender: sender,
    recipientX25519PubKeyHex: xB,
    plaintext: 'interop live slice',
  );
  await publisher.send(PublishLiveMessage(envelope: slice));
  final liveAck =
      await publisher.waitFor<PublishedMessage>((m) => m.id == slice.id);
  _check(liveAck.accepted, 'PUBLISH_LIVE accepted with a subscriber');
  await subscriber.waitFor<EnvelopesMessage>(
    (m) => m.envelopes.any((e) => e.id == slice.id),
  );

  await subscriber.send(const PeerListRequestMessage());
  final list = await subscriber.waitFor<PeerListMessage>((_) => true);
  final peer = list.peers.where((p) => p.peerId == 'interop-A');
  _check(peer.isNotEmpty, 'PEER_LIST returned the other device');
  _check(peer.first.xPubKey == xA, 'PEER_LIST x25519 key');
  _check(peer.first.addrs.contains('/ip4/192.168.1.50/tcp/4010'),
      'PEER_LIST address');

  // The app must be able to parse every frame; reaching here means every
  // GossipMessage.fromJson call succeeded.
  await publisher.close();
  await subscriber.close();
  stdout.writeln('INTEROP PASS: $url');
}

void _check(bool ok, String what) {
  if (!ok) {
    throw StateError('interop check failed: $what');
  }
  stdout.writeln('ok  $what');
}

class _C {
  final WebSocket ws;
  final List<GossipMessage> buf = [];
  late final StreamSubscription<dynamic> _sub;

  _C(this.ws) {
    _sub = ws.listen((frame) {
      final text = frame is String ? frame : utf8.decode(frame as List<int>);
      final decoded = jsonDecode(text);
      if (decoded is Map<String, dynamic>) {
        buf.add(GossipMessage.fromJson(decoded));
      }
    }, onError: (_) {});
  }

  static Future<_C> connect(String url) async {
    // ignore: close_sinks — the _C instance owns and closes the socket.
    final ws = await WebSocket.connect(url);
    ws.pingInterval = const Duration(seconds: 25);
    return _C(ws);
  }

  Future<void> send(GossipMessage message) async {
    ws.add(jsonEncode(message.toJson()));
  }

  Future<T> waitFor<T extends GossipMessage>(
    bool Function(T) predicate, {
    Duration timeout = const Duration(seconds: 6),
  }) async {
    final deadline = DateTime.now().add(timeout);
    while (DateTime.now().isBefore(deadline)) {
      for (final message in buf) {
        if (message is T && predicate(message)) return message;
      }
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
    throw TimeoutException('no matching $T');
  }

  Future<void> close() async {
    await _sub.cancel();
    await ws.close();
  }
}
