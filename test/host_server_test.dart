import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:dtm_app/core/crypto/envelope_crypto.dart';
import 'package:dtm_app/core/crypto/keypair.dart';
import 'package:dtm_app/core/host/host_link.dart' show HostEndpoint;
import 'package:dtm_app/core/security_limits.dart' as limits;
import 'package:dtm_app/core/sync/gossip_message.dart';
import 'package:dtm_app/models/envelope.dart';
import 'package:dtm_host/host_config.dart';
import 'package:dtm_host/host_db.dart';
import 'package:dtm_host/host_key.dart';
import 'package:dtm_host/host_server.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('GET /status reports aggregate health and no secrets', () async {
    final server = await _startServer();
    final client = HttpClient();
    addTearDown(client.close);

    Future<(int, String)> get(String path) async {
      final request = await client.getUrl(
        Uri.parse('http://127.0.0.1:${server.server.boundPort}$path'),
      );
      final response = await request.close();
      return (response.statusCode, await utf8.decoder.bind(response).join());
    }

    final (code, body) = await get('/status');
    expect(code, 200);
    final json = jsonDecode(body) as Map<String, dynamic>;
    expect(json['ok'], isTrue);
    for (final key in [
      'startedAt',
      'uptimeSeconds',
      'connections',
      'connectionsTotal',
      'federatedLinks',
      'queue',
      'envelopes',
      'peers',
      'subscriptions',
      'dbBytes',
      'receivedTotal',
      'relayedTotal',
      'rejectedTotal',
      'duplicateTotal',
      'backfillTotal',
    ]) {
      expect(json[key], isA<int>(), reason: key);
    }
    expect(json['rssBytes'], anyOf(isNull, isA<int>()));
    expect(json['load1'], anyOf(isNull, isA<num>()));
    expect(json['version'], isA<String>());
    expect((json['version'] as String), isNotEmpty);
    expect(body, isNot(contains(await server.key.hexPub)));
    expect(body, isNot(contains('127.0.0.1')));

    final (healthCode, healthBody) = await get('/healthz');
    expect(healthCode, 200);
    expect(jsonDecode(healthBody), {'ok': true});

    final (missingCode, _) = await get('/nope');
    expect(missingCode, 404);

    await server.dispose();
  });

  test('GET /status counts accepted and duplicate envelopes', () async {
    final server = await _startServer();
    final client = await _connect(server);
    await client.send(const HelloMessage(myPeerId: 'dev'));
    await client.waitFor<WelcomeMessage>();
    final envelope = await _envelopeFor(await _recipientKey());

    await client.send(PublishMessage(envelope: envelope));
    await client.waitFor<PublishedMessage>();
    await client.send(PublishMessage(envelope: envelope));
    await client.waitFor<PublishedMessage>();

    final http = HttpClient();
    addTearDown(http.close);
    final request = await http.getUrl(
      Uri.parse('http://127.0.0.1:${server.server.boundPort}/status'),
    );
    final response = await request.close();
    final body = await utf8.decoder.bind(response).join();
    final json = jsonDecode(body) as Map<String, dynamic>;
    expect(json['receivedTotal'], 1);
    expect(json['duplicateTotal'], 1);
    expect(json['rejectedTotal'], 0);
    expect(json['connectionsTotal'], greaterThanOrEqualTo(1));

    await server.dispose();
  });

  test('GET /directory lists self and federated members with keys', () async {
    final server = await _startServer();
    final memberKey = _hex32('a');
    final now = DateTime.now().millisecondsSinceEpoch;
    server.db.rememberFederatedHost(
      HostEndpoint(
        addr: 'ws://203.0.113.7:3100/ws',
        edPubKey: memberKey,
      ),
      now,
    );
    server.db.rememberFederatedHost(
      const HostEndpoint(addr: 'ws://127.0.0.1:3100/ws', edPubKey: null),
      now,
    );
    server.db.rememberFederatedHost(
      HostEndpoint(
        addr: 'ws://127.0.0.2:3100/ws',
        edPubKey: await server.key.hexPub,
      ),
      now,
    );
    final client = HttpClient();
    addTearDown(client.close);

    final request = await client.getUrl(
      Uri.parse('http://127.0.0.1:${server.server.boundPort}/directory'),
    );
    final response = await request.close();
    final body = await utf8.decoder.bind(response).join();
    expect(response.statusCode, 200);
    final json = jsonDecode(body) as Map<String, dynamic>;
    expect(json['ok'], isTrue);

    final self = json['self'] as Map<String, dynamic>;
    expect(self['ed25519'], await server.key.hexPub);
    expect(self['addr'], startsWith('ws://127.0.0.1:'));

    final members = (json['members'] as List).cast<Map<String, dynamic>>();
    expect(members, hasLength(1));
    expect(members.single['addr'], 'ws://203.0.113.7:3100/ws');
    expect(members.single['ed25519'], memberKey);

    await server.dispose();
  });

  test('HELLO is answered with a pinned WELCOME', () async {
    final server = await _startServer();
    final client = await _connect(server);

    await client.send(const HelloMessage(myPeerId: 'dev1'));
    final welcome = await client.waitFor<WelcomeMessage>();

    expect(welcome.identity, await server.key.hexPub);
    expect(welcome.retentionSeconds, server.config.retentionMs ~/ 1000);
    expect(welcome.maxEnvelopeSize, limits.maxFrameBytes);

    await server.dispose();
  });

  test('SUBSCRIBE answers with an empty done backfill on a fresh host',
      () async {
    final server = await _startServer();
    final client = await _connect(server);

    await client.send(const HelloMessage(myPeerId: 'dev'));
    await client.waitFor<WelcomeMessage>();
    await client.send(
      SubscribeMessage(since: 0, keys: [List.filled(64, 'a').join()]),
    );

    final backfill = await client.waitFor<EnvelopesMessage>();
    expect(backfill.envelopes, isEmpty);
    expect(backfill.done, isTrue);

    await server.dispose();
  });

  test('a valid PUBLISH is accepted and returned by a later SUBSCRIBE',
      () async {
    final server = await _startServer();
    final publisher = await _connect(server);
    await publisher.send(const HelloMessage(myPeerId: 'pub'));

    final envelope = await _envelopeFor(await _recipientKey());

    await publisher.send(PublishMessage(envelope: envelope));
    final acked = await publisher.waitFor<PublishedMessage>();
    expect(acked.accepted, isTrue);
    expect(server.db.has(envelope.id), isTrue);

    final subscriber = await _connect(server);
    await subscriber.send(const HelloMessage(myPeerId: 'sub'));
    await subscriber.send(
      SubscribeMessage(since: 0, keys: [envelope.recipientPubKey]),
    );
    final batch = await subscriber.waitFor<EnvelopesMessage>(
      (m) => m.envelopes.any((e) => e.id == envelope.id),
    );
    expect(batch.envelopes.map((e) => e.id), contains(envelope.id));

    await server.dispose();
  });

  test('a duplicate id is rejected as not accepted', () async {
    final server = await _startServer();
    final client = await _connect(server);
    await client.send(const HelloMessage(myPeerId: 'pub'));

    final envelope = await _envelopeFor(await _recipientKey());
    await client.send(PublishMessage(envelope: envelope));
    await client.waitFor<PublishedMessage>();
    await client.send(PublishMessage(envelope: envelope));
    final second = await client.waitFor<PublishedMessage>(
      (m) => m.accepted == false,
    );
    expect(second.accepted, isFalse);

    await server.dispose();
  });

  test('a signed-valid envelope is relayed live to a subscribed client',
      () async {
    final server = await _startServer();
    final recipient = await _recipientKey();
    final subscriber = await _connect(server);
    await subscriber.send(const HelloMessage(myPeerId: 'sub'));
    await subscriber.send(
      SubscribeMessage(since: 0, keys: [recipient]),
    );
    await subscriber.waitFor<EnvelopesMessage>();

    final envelope = await _envelopeFor(recipient);
    final publisher = await _connect(server);
    await publisher.send(const HelloMessage(myPeerId: 'pub'));
    await publisher.send(PublishMessage(envelope: envelope));

    final relayed = await subscriber.waitFor<EnvelopesMessage>(
      (m) => m.envelopes.any((e) => e.id == envelope.id),
    );
    expect(relayed.hops, 0);
    expect(relayed.envelopes.single.id, envelope.id);

    await server.dispose();
  });

  test('PUBLISH_LIVE reaches an online subscriber without storing', () async {
    final server = await _startServer();
    final recipient = await _recipientKey();
    final subscriber = await _connect(server);
    await subscriber.send(const HelloMessage(myPeerId: 'sub'));
    await subscriber.waitFor<WelcomeMessage>();
    await subscriber.send(
      SubscribeMessage(since: 0, keys: [recipient]),
    );
    await subscriber.waitFor<EnvelopesMessage>((m) => m.done);

    final envelope = await _envelopeFor(recipient);
    final publisher = await _connect(server);
    await publisher.send(const HelloMessage(myPeerId: 'pub'));
    await publisher.waitFor<WelcomeMessage>();
    await publisher.send(PublishLiveMessage(envelope: envelope));
    final ack = await publisher.waitFor<PublishedMessage>();
    expect(ack.accepted, isTrue);

    final relayed = await subscriber.waitFor<EnvelopesMessage>(
      (m) => m.envelopes.any((e) => e.id == envelope.id),
    );
    expect(relayed.envelopes.single.id, envelope.id);
    expect(server.db.envelopeCount(), 0);

    await server.dispose();
  });

  test('PUBLISH_LIVE with no subscriber is not acknowledged as delivered',
      () async {
    final server = await _startServer();
    final publisher = await _connect(server);
    await publisher.send(const HelloMessage(myPeerId: 'pub-live'));
    await publisher.waitFor<WelcomeMessage>();

    final envelope = await _envelopeFor(await _recipientKey());
    await publisher.send(PublishLiveMessage(envelope: envelope));
    final ack = await publisher.waitFor<PublishedMessage>();

    expect(
      ack.accepted,
      isFalse,
      reason: 'nobody received it, so the sender must keep retrying',
    );
    expect(server.db.envelopeCount(), 0);

    await server.dispose();
  });

  test('WANT then GET serves the stored envelope backlog', () async {
    final server = await _startServer();
    final client = await _connect(server);
    await client.send(const HelloMessage(myPeerId: 'want'));

    final recipient = await _recipientKey();
    final envelope = await _envelopeFor(recipient);
    await client.send(PublishMessage(envelope: envelope));
    await client.waitFor<PublishedMessage>();

    // A device is only ever served what it subscribed to.
    await client.send(SubscribeMessage(since: 0, keys: [recipient]));
    await client.waitFor<EnvelopesMessage>((m) => m.done);

    await client.send(const WantMessage(since: 0));
    final have = await client.waitFor<HaveMessage>();
    expect(have.ids, [envelope.id]);

    await client.send(GetMessage(ids: have.ids));
    final got = await client.waitFor<EnvelopesMessage>(
      (m) => m.envelopes.any((e) => e.id == envelope.id),
    );
    expect(got.envelopes.single.id, envelope.id);

    await server.dispose();
  });

  test('GET never hands a device an envelope it did not subscribe to',
      () async {
    final server = await _startServer();
    final publisher = await _connect(server);
    await publisher.send(const HelloMessage(myPeerId: 'pub'));
    final recipient = await _recipientKey();
    final envelope = await _envelopeFor(recipient);
    await publisher.send(PublishMessage(envelope: envelope));
    await publisher.waitFor<PublishedMessage>();
    expect(server.db.has(envelope.id), isTrue);

    final stranger = await _connect(server);
    await stranger.send(const HelloMessage(myPeerId: 'stranger'));
    await stranger.send(GetMessage(ids: [envelope.id]));

    final answer = await stranger.waitFor<EnvelopesMessage>();
    expect(answer.envelopes, isEmpty);

    await server.dispose();
  });

  test('a client claiming dtm-host without a reachable endpoint is a client',
      () async {
    final server = await _startServer();
    final emitter = await _connect(server);
    await emitter.send(const HelloMessage(myPeerId: 'emitter'));

    final recipient = await _recipientKey();
    final envelope = await _envelopeFor(recipient);
    await emitter.send(PublishMessage(envelope: envelope));
    await emitter.waitFor<PublishedMessage>();

    // No `announce`, so the claim cannot be verified: the fan-out must not
    // reach this connection.
    final impostor = await _connect(server);
    await impostor.send(
      const HelloMessage(
        myPeerId: 'impostor',
        capabilities: ['dtm-host', 'dtm-net'],
      ),
    );
    await impostor.waitFor<WelcomeMessage>();
    await Future<void>.delayed(const Duration(milliseconds: 250));

    final leaked = impostor.received
        .whereType<EnvelopesMessage>()
        .expand((m) => m.envelopes);
    expect(leaked, isEmpty);

    await impostor.send(GetMessage(ids: [envelope.id]));
    final answer = await impostor.waitFor<EnvelopesMessage>();
    expect(answer.envelopes, isEmpty);

    await server.dispose();
  });

  test('a subscribed device still receives a live envelope', () async {
    final server = await _startServer();
    final recipient = await _recipientKey();
    final subscriber = await _connect(server);
    await subscriber.send(const HelloMessage(myPeerId: 'sub'));
    await subscriber.send(SubscribeMessage(since: 0, keys: [recipient]));
    await subscriber.waitFor<EnvelopesMessage>((m) => m.done);

    final publisher = await _connect(server);
    await publisher.send(const HelloMessage(myPeerId: 'pub'));
    final envelope = await _envelopeFor(recipient);
    await publisher.send(PublishMessage(envelope: envelope));

    final live = await subscriber.waitFor<EnvelopesMessage>(
      (m) => m.envelopes.any((e) => e.id == envelope.id),
    );
    expect(live.envelopes.single.id, envelope.id);

    await server.dispose();
  });

  test('a non-hex subscription key drops the connection', () async {
    final server = await _startServer();
    final client = await _connect(server);
    await client.send(const HelloMessage(myPeerId: 'badkey'));
    await client.send(SubscribeMessage(since: 0, keys: ['z' * 64]));
    await client.waitClosed();

    await server.dispose();
  });

  test('connections past the cap are refused', () async {
    final server = await _startServer(
      config: const HostConfig(
        listenAddress: '127.0.0.1',
        port: 0,
        maxConnections: 2,
      ),
    );
    final first = await _connect(server);
    final second = await _connect(server);
    expect(first.ws.readyState, WebSocket.open);
    expect(second.ws.readyState, WebSocket.open);

    await expectLater(
      _connect(server),
      throwsA(isA<WebSocketException>()),
    );

    await server.dispose();
  });

  test('the since window pulls an old cursor to the window edge', () {
    const now = 1700000000000;
    const window = limits.gossipMaxScanWindow;
    // `since: 0` means "everything within the scan window", exactly as the
    // device side computes it (gossip.dart); the window and the retention
    // window are the same 30 days.
    expect(HostServer.scanWindowStart(0, now), now - window);
    expect(HostServer.scanWindowStart(-5, now), 0);
    expect(HostServer.scanWindowStart(now - 1000, now), now - 1000);
    // A real millisecond timestamp older than the window must not be clamped
    // to itself (that replayed the whole store on every SUBSCRIBE).
    expect(
      HostServer.scanWindowStart(now - limits.gossipMaxScanWindow - 1, now),
      now - limits.gossipMaxScanWindow,
    );
  });

  test('hostile envelopes are rejected with accepted=false', () async {
    final server = await _startServer();
    final client = await _connect(server);
    await client.send(const HelloMessage(myPeerId: 'evil'));
    final recipient = await _recipientKey();

    final base = await _envelopeFor(recipient);
    final tampered = Envelope(
      id: base.id,
      senderPubKey: base.senderPubKey,
      recipientPubKey: base.recipientPubKey,
      timestamp: base.timestamp,
      ciphertext: base.ciphertext,
      ephemeralPubKey: base.ephemeralPubKey,
      signature: '00${base.signature.substring(2)}',
    );
    await client.send(PublishMessage(envelope: tampered));
    expect((await client.waitFor<PublishedMessage>()).accepted, isFalse);

    final futureStamped = await _envelopeFor(
      recipient,
      timestamp: DateTime.now().toUtc().millisecondsSinceEpoch +
          (60 * 10 * 1000),
    );
    await client.send(PublishMessage(envelope: futureStamped));
    expect((await client.waitFor<PublishedMessage>()).accepted, isFalse);

    final forgedId = Envelope(
      id: List.filled(64, 'c').join(),
      senderPubKey: base.senderPubKey,
      recipientPubKey: base.recipientPubKey,
      timestamp: base.timestamp,
      ciphertext: base.ciphertext,
      ephemeralPubKey: base.ephemeralPubKey,
      signature: base.signature,
    );
    await client.send(PublishMessage(envelope: forgedId));
    expect((await client.waitFor<PublishedMessage>()).accepted, isFalse);
    expect(server.db.has(forgedId.id), isFalse);

    await server.dispose();
  });

  test('a sender over its per-window budget is rate limited', () async {
    final server = await _startServer(
      config: const HostConfig(
        listenAddress: '127.0.0.1',
        port: 0,
        rateLimitPerWindow: 2,
        rateWindowSeconds: 60,
      ),
    );
    final client = await _connect(server);
    await client.send(const HelloMessage(myPeerId: 'flood'));

    final sender = await DtmKeyPair.generate();
    final recipient = await _recipientKey();
    for (var i = 0; i < 3; i++) {
      final envelope = await createEnvelopeForPubKey(
        sender: sender,
        recipientX25519PubKeyHex: recipient,
        plaintext: 'flood $i',
      );
      await client.send(PublishMessage(envelope: envelope));
      await client.waitFor<PublishedMessage>(
        (_) => client.received.whereType<PublishedMessage>().length >= i + 1,
      );
    }
    final acks = client.received.whereType<PublishedMessage>().toList();
    expect(acks.where((a) => a.accepted), hasLength(2));
    expect(acks.last.accepted, isFalse);

    await server.dispose();
  });

  test('live slices have their own, larger per-window budget', () async {
    final server = await _startServer(
      config: const HostConfig(
        listenAddress: '127.0.0.1',
        port: 0,
        rateLimitPerWindow: 1,
        liveRateLimitPerWindow: 2,
        rateWindowSeconds: 60,
      ),
    );
    final client = await _connect(server);
    await client.send(const HelloMessage(myPeerId: 'slice-flood'));

    final sender = await DtmKeyPair.generate();
    final recipient = await _recipientKey();
    final subscriber = await _connect(server);
    await subscriber.send(const HelloMessage(myPeerId: 'slice-target'));
    await subscriber.waitFor<WelcomeMessage>();
    await subscriber.send(SubscribeMessage(since: 0, keys: [recipient]));
    await subscriber.waitFor<EnvelopesMessage>((m) => m.done);
    Future<Envelope> next(String text) => createEnvelopeForPubKey(
      sender: sender,
      recipientX25519PubKeyHex: recipient,
      plaintext: text,
    );

    Future<bool> publish(Future<Envelope> envelope, {bool live = false}) async {
      final built = await envelope;
      await client.send(
        live
            ? PublishLiveMessage(envelope: built)
            : PublishMessage(envelope: built),
      );
      final ack = await client.waitFor<PublishedMessage>(
        (m) => m.id == built.id,
      );
      return ack.accepted;
    }

    // One stored envelope spends the stored budget only, not the live one.
    expect(await publish(next('stored')), isTrue);
    expect(await publish(next('stored-2')), isFalse);
    expect(await publish(next('slice-1'), live: true), isTrue);
    expect(await publish(next('slice-2'), live: true), isTrue);
    expect(await publish(next('slice-3'), live: true), isFalse);

    await server.dispose();
  });

  test('oversized, non-JSON and malformed frames drop the connection',
      () async {
    final server = await _startServer();

    final garbage = await _connect(server);
    garbage.ws.add('this is not json');
    await garbage.waitClosed();

    final big = await _connect(server);
    big.ws.add('x' * (limits.maxFrameBytes + 1));
    await big.waitClosed();

    final badKey = await _connect(server);
    await badKey.send(const HelloMessage(myPeerId: 'y'));
    await badKey.waitFor<WelcomeMessage>();
    await badKey.send(
      const SubscribeMessage(since: 0, keys: ['zzz']),
    );
    await badKey.waitClosed();

    final oversizedKeyList = await _connect(server);
    await oversizedKeyList.send(const HelloMessage(myPeerId: 'z'));
    await oversizedKeyList.waitFor<WelcomeMessage>();
    await oversizedKeyList.send(
      SubscribeMessage(
        since: 0,
        keys: [
          for (var i = 0; i <= limits.maxHostSubscriptionKeys; i++)
            'a${i.toString().padLeft(63, 'b')}',
        ],
      ),
    );
    await oversizedKeyList.waitFor<EnvelopesMessage>();
    expect(oversizedKeyList.ws.readyState, WebSocket.open);
    await oversizedKeyList.close();

    await server.dispose();
  });

  test('HELLO with dtm-presence gets a feed of subscribed devices',
      () async {
    final server = await _startServer();
    final first = await _connect(server);
    await first.send(
      const HelloMessage(myPeerId: 'devA', capabilities: [dtmPresence]),
    );
    await first.waitFor<WelcomeMessage>();
    final keyA = _hex32('a');
    final keyB = _hex32('b');
    await first.send(SubscribeMessage(since: 0, keys: [keyA]));

    final second = await _connect(server);
    await second.send(
      const HelloMessage(myPeerId: 'devB', capabilities: [dtmPresence]),
    );
    await second.waitFor<WelcomeMessage>();

    final feed = await second.waitFor<PresenceMessage>();
    expect(feed.online, contains(keyA));

    await second.send(SubscribeMessage(since: 0, keys: [keyB]));
    final updated = await first.waitFor<PresenceMessage>(
      (m) => m.online.contains(keyB),
    );
    expect(updated.online, unorderedEquals([keyA, keyB]));

    await first.close();
    final afterLeave = await second.waitFor<PresenceMessage>(
      (m) => m.online.contains(keyB) && !m.online.contains(keyA),
    );
    expect(afterLeave.online, [keyB]);

    await server.dispose();
  });

  test('a client without dtm-presence never receives a presence feed',
      () async {
    final server = await _startServer();
    final silent = await _connect(server);
    await silent.send(const HelloMessage(myPeerId: 'silent'));
    await silent.waitFor<WelcomeMessage>();

    final watcher = await _connect(server);
    await watcher.send(
      const HelloMessage(myPeerId: 'watch', capabilities: [dtmPresence]),
    );
    await watcher.waitFor<WelcomeMessage>();
    await watcher.send(
      SubscribeMessage(since: 0, keys: [_hex32('a'), _hex32('b')]),
    );

    await watcher.waitFor<PresenceMessage>(
      (m) => m.online.length == 2,
    );

    final other = await _connect(server);
    await other.send(const HelloMessage(myPeerId: 'other'));
    await other.send(SubscribeMessage(since: 0, keys: [_hex32('c')]));
    await other.waitFor<EnvelopesMessage>();
    await Future<void>.delayed(const Duration(milliseconds: 600));
    expect(
      silent.received.whereType<PresenceMessage>(),
      isEmpty,
      reason: 'a client that never asked for presence must not be spammed',
    );

    await server.dispose();
  });

  test('a presence feed is capped at maxPresenceKeys, dropping stalest',
      () async {
    final server = await _startServer();
    final watcher = await _connect(server);
    await watcher.send(
      const HelloMessage(myPeerId: 'watch', capabilities: [dtmPresence]),
    );
    await watcher.waitFor<WelcomeMessage>();

    final clients = <_Client>[];
    for (var i = 0; i <= limits.maxPresenceKeys; i++) {
      final client = await _connect(server);
      clients.add(client);
      await client.send(HelloMessage(myPeerId: 'dev$i'));
      await client.send(
        SubscribeMessage(since: 0, keys: [_presenceKey(i)]),
      );
      await Future<void>.delayed(const Duration(milliseconds: 4));
    }

    final feed = await watcher.waitFor<PresenceMessage>(
      (m) => m.online.length == limits.maxPresenceKeys,
      const Duration(seconds: 8),
    );
    expect(feed.online.length, limits.maxPresenceKeys);
    expect(feed.online.first, _presenceKey(limits.maxPresenceKeys));
    expect(
      feed.online.contains(_presenceKey(0)),
      isFalse,
      reason: 'the stalest subscription is the one dropped',
    );

    for (final client in clients) {
      await client.close();
    }
    await server.dispose();
  });
  test('a known seed key alone cannot federate inbound', () async {
    final seedKey = _hex32('a');
    final server = await _startServer(
      config: HostConfig(
        listenAddress: '127.0.0.1',
        port: 0,
        federatedPeers: [
          HostEndpoint(addr: 'ws://127.0.0.1:1/ws', edPubKey: seedKey),
        ],
      ),
    );
    final recipient = await _recipientKey();
    final envelope = await _envelopeFor(recipient);
    server.db.insertIfAbsent(envelope);

    final client = await _connect(server);
    await client.send(
      HelloMessage(
        myPeerId: seedKey,
        capabilities: const ['dtm-host', 'dtm-net'],
        announce: 'ws://203.0.113.9:3100/ws',
      ),
    );
    await client.waitFor<WelcomeMessage>();
    await client.send(GetMessage(ids: [envelope.id]));
    final answer = await client.waitFor<EnvelopesMessage>();
    expect(answer.envelopes, isEmpty);

    await client.close();
    await server.dispose();
  });

  test('WANT answer stays within the gossip list cap', () async {
    final server = await _startServer();
    final now = DateTime.now().millisecondsSinceEpoch;
    final total = limits.maxGossipItems + 20;
    for (var i = 0; i < total; i++) {
      server.db.insertIfAbsent(
        Envelope(
          id: i.toRadixString(16).padLeft(64, '0'),
          senderPubKey: _hex32('a'),
          recipientPubKey: _hex32('b'),
          timestamp: now - 1000 + i,
          ciphertext: 'AA==',
          ephemeralPubKey: _hex32('c'),
          signature: _hex32('d'),
        ),
      );
    }

    final client = await _connect(server);
    await client.send(const HelloMessage(myPeerId: 'want'));
    await client.send(const WantMessage(since: 0));
    final answer = await client.waitFor<HaveMessage>();
    expect(
      answer.ids.length,
      lessThanOrEqualTo(limits.maxGossipItems),
      reason: 'a larger HAVE is rejected by the client parser',
    );

    await client.close();
    await server.dispose();
  });
}
String _hex32(String fill) => List.filled(64, fill).join();

/// A distinct valid 32-byte key per index, so N clients mean N online keys.
String _presenceKey(int index) =>
    '${List.filled(62, 'c').join()}${index.toRadixString(16).padLeft(2, '0')}';

/// HostServer backed by a fresh in-memory db on an ephemeral loopback port.
Future<_StartedServer> _startServer({HostConfig? config}) async {
  final resolved = config ??
      const HostConfig(listenAddress: '127.0.0.1', port: 0);
  final db = HostDatabase.openInMemory();
  final key = await HostKey.generate();
  final server = HostServer(db: db, key: key, config: resolved);
  await server.start();
  return _StartedServer(db: db, key: key, server: server, config: resolved);
}

Future<String> _recipientKey() async =>
    (await DtmKeyPair.generate()).x25519PublicKeyHex;

Future<Envelope> _envelopeFor(
  String recipientX, {
  int? timestamp,
}) async {
  final sender = await DtmKeyPair.generate();
  return createEnvelopeForPubKey(
    sender: sender,
    recipientX25519PubKeyHex: recipientX,
    plaintext: 'hello',
    timestamp: timestamp,
  );
}

Future<_Client> _connect(_StartedServer server) async => _Client(
  await WebSocket.connect(
    'ws://127.0.0.1:${server.server.boundPort}/ws',
  ),
);

class _StartedServer {
  final HostDatabase db;
  final HostKey key;
  final HostServer server;
  final HostConfig config;

  _StartedServer({
    required this.db,
    required this.key,
    required this.server,
    required this.config,
  });

  Future<void> dispose() async {
    await server.stop();
    db.dispose();
  }
}

class _Client {
  final WebSocket ws;
  final List<GossipMessage> received = [];

  _Client(this.ws) {
    unawaited(_drain());
  }

  Future<void> _drain() async {
    await for (final frame in ws) {
      final text = frame is String
          ? frame
          : utf8.decode(frame as List<int>);
      final decoded = jsonDecode(text);
      if (decoded is! Map<String, dynamic>) continue;
      received.add(GossipMessage.fromJson(decoded));
    }
  }

  Future<void> send(GossipMessage message) async {
    ws.add(jsonEncode(message.toJson()));
  }

  Future<T> waitFor<T>([
    bool Function(T)? matcher,
    Duration timeout = const Duration(seconds: 4),
  ]) async {
    final deadline = DateTime.now().add(timeout);
    while (true) {
      for (final message in received) {
        if (message is T) {
          final typed = message as T;
          if (matcher == null ||
              matcher(typed)) {
            return typed;
          }
        }
      }
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('no $T frame within $timeout');
      }
      await Future<void>.delayed(const Duration(milliseconds: 15));
    }
  }

  Future<void> waitClosed([
    Duration timeout = const Duration(seconds: 4),
  ]) async {
    await ws.done.timeout(timeout);
  }

  Future<void> close() async {
    if (ws.readyState == WebSocket.open ||
        ws.readyState == WebSocket.connecting) {
      await ws.close();
    }
  }
}