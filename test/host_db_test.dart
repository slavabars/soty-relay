import 'dart:io';

import 'package:cryptography/cryptography.dart';
import 'package:dtm_app/core/crypto/envelope_crypto.dart';
import 'package:dtm_app/core/crypto/keypair.dart';
import 'package:dtm_app/core/security_limits.dart' show maxKnownPeers;
import 'package:dtm_app/core/storage/pruned_roots_dao.dart'
    show rootSignatureData;
import 'package:dtm_app/models/envelope.dart';
import 'package:dtm_host/host_db.dart';
import 'package:dtm_host/host_key.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sqlite3/sqlite3.dart' as sqlite3_pkg;

void main() {
  late HostDatabase db;
  late HostKey key;

  setUp(() {
    db = HostDatabase.openInMemory();
  });

  tearDown(() {
    db.dispose();
  });

  Future<Envelope> stamp(
    DtmKeyPair sender,
    String recipientX,
    String text,
    int ts, {
    String chainLink = '',
  }) {
    return createEnvelopeForPubKey(
      sender: sender,
      recipientX25519PubKeyHex: recipientX,
      plaintext: text,
      timestamp: ts,
      chainLink: chainLink,
    );
  }

  test('insertIfAbsent writes each id exactly once', () async {
    final sender = await DtmKeyPair.generate();
    final recipient = await DtmKeyPair.generate();
    final rx = await recipient.x25519PublicKeyHex;
    final envelope = await stamp(sender, rx, 'once', 1000);

    expect(db.insertIfAbsent(envelope, source: 'publish'), isTrue);
    expect(db.insertIfAbsent(envelope, source: 'dupe'), isFalse);
    expect(db.has(envelope.id), isTrue);
  });

  test('envelopeById round-trips every field', () async {
    final sender = await DtmKeyPair.generate();
    final recipient = await DtmKeyPair.generate();
    final rx = await recipient.x25519PublicKeyHex;
    final head =
        await stamp(sender, rx, 'head', 1000, chainLink: '');
    final envelope =
        await stamp(sender, rx, 'linked', 1234, chainLink: head.id);

    db.insertIfAbsent(envelope, source: 'federated', hops: 2);

    final restored = db.envelopeById(envelope.id);
    expect(restored, isNotNull);
    expect(restored!.id, envelope.id);
    expect(restored.senderPubKey, envelope.senderPubKey);
    expect(restored.recipientPubKey, envelope.recipientPubKey);
    expect(restored.timestamp, envelope.timestamp);
    expect(restored.ciphertext, envelope.ciphertext);
    expect(restored.ephemeralPubKey, envelope.ephemeralPubKey);
    expect(restored.signature, envelope.signature);
    expect(restored.chainLink, head.id);
  });

  test('a pre-chain_link database is migrated in place', () async {
    final dir = Directory.systemTemp.createTempSync('host_db_migration');
    addTearDown(() => dir.deleteSync(recursive: true));
    final path = '${dir.path}/host.db';

    final legacy = sqlite3_pkg.sqlite3.open(path);
    legacy.execute(
      'CREATE TABLE messages ('
      'id TEXT PRIMARY KEY,'
      'sender_pub_key TEXT NOT NULL,'
      'recipient_pub_key TEXT NOT NULL,'
      'timestamp INTEGER NOT NULL,'
      'ciphertext TEXT NOT NULL,'
      'ephemeral_pub_key TEXT NOT NULL,'
      'signature TEXT NOT NULL,'
      'source TEXT NOT NULL,'
      'hops INTEGER NOT NULL DEFAULT 0)',
    );
    legacy.execute(
      'CREATE INDEX IF NOT EXISTS idx_messages_ts ON messages(timestamp)',
    );
    legacy.execute(
      'CREATE INDEX IF NOT EXISTS idx_messages_recipient_ts '
      'ON messages(recipient_pub_key, timestamp)',
    );
    legacy.dispose();

    final migrated = await HostDatabase.open(path);
    addTearDown(migrated.dispose);

    final sender = await DtmKeyPair.generate();
    final recipient = await DtmKeyPair.generate();
    final rx = await recipient.x25519PublicKeyHex;
    final envelope = await stamp(sender, rx, 'chained', 5, chainLink: 'c' * 64);
    expect(migrated.insertIfAbsent(envelope), isTrue);
    expect(migrated.envelopeById(envelope.id)!.chainLink, 'c' * 64);
  });

  test('idsSince is ordered oldest-first and bounded', () async {
    final sender = await DtmKeyPair.generate();
    final recipient = await DtmKeyPair.generate();
    final rx = await recipient.x25519PublicKeyHex;

    final env1 = await stamp(sender, rx, 'one', 100);
    final env2 = await stamp(sender, rx, 'two', 300);
    final env3 = await stamp(sender, rx, 'three', 200);
    for (final e in [env1, env2, env3]) {
      db.insertIfAbsent(e, source: 'publish');
    }

    expect(db.idsSince(0), [env1.id, env3.id, env2.id]);
    expect(db.idsSince(250), [env2.id]);
    expect(db.idsSince(150, limit: 1), [env3.id]);
  });

  test('envelopesForRecipients filters by keys and since', () async {
    final sender = await DtmKeyPair.generate();
    final ra = await DtmKeyPair.generate();
    final rb = await DtmKeyPair.generate();
    final raX = await ra.x25519PublicKeyHex;
    final rbX = await rb.x25519PublicKeyHex;

    final forA = await stamp(sender, raX, 'a', 100);
    final forB = await stamp(sender, rbX, 'b', 200);
    final forA2 = await stamp(sender, raX, 'a2', 300);
    db.insertIfAbsent(forA, source: 'publish');
    db.insertIfAbsent(forB, source: 'publish');
    db.insertIfAbsent(forA2, source: 'publish');

    final hits = db.envelopesForRecipients([raX, rbX], 0);
    expect(hits.map((e) => e.id), [forA.id, forB.id, forA2.id]);

    final since = db.envelopesForRecipients([raX], 150);
    expect(since.map((e) => e.id), [forA2.id]);

    expect(db.envelopesForRecipients([], 0), isEmpty);
  });

  test('latestTimestamp is null when empty and max afterwards', () async {
    expect(db.latestTimestamp(), isNull);

    final sender = await DtmKeyPair.generate();
    final recipient = await DtmKeyPair.generate();
    final rx = await recipient.x25519PublicKeyHex;
    final low = await stamp(sender, rx, 'low', 500);
    final high = await stamp(sender, rx, 'high', 900);
    db.insertIfAbsent(low, source: 'publish');
    db.insertIfAbsent(high, source: 'publish');

    expect(db.latestTimestamp(), 900);
  });

  test('subscriptions are remembered until they age out', () async {
    final keyA = List.filled(64, 'a').join();
    final keyB = List.filled(64, 'b').join();

    db.rememberSubscription(keyA, 1000);

    final at1800 = db.rememberedSubscriptions(1800, 1000);
    expect(at1800, {keyA});

    db.forgetExpiredSubscriptions(1800, 1000);
    expect(db.rememberedSubscriptions(1800, 1000), {keyA});

    expect(db.rememberedSubscriptions(5000, 1000), isEmpty);

    db.rememberSubscription(keyB, 4500);
    expect(db.rememberedSubscriptions(5000, 1000), {keyB});

    db.forgetExpiredSubscriptions(5000, 1000);
    expect(db.rememberedSubscriptions(5000, 1000), {keyB});

    db.forgetExpiredSubscriptions(6000, 1000);
    expect(db.rememberedSubscriptions(6000, 1000), isEmpty);
  });

  test('pruneOlderThan deletes the batch and signs a verifiable root',
      () async {
    key = await HostKey.generate();
    final sender = await DtmKeyPair.generate();
    final recipient = await DtmKeyPair.generate();
    final rx = await recipient.x25519PublicKeyHex;
    final old1 = await stamp(sender, rx, 'g1', 100);
    final old2 = await stamp(sender, rx, 'g2', 200);
    final fresh = await stamp(sender, rx, 'keep', 3000);
    for (final e in [old1, old2, fresh]) {
      db.insertIfAbsent(e, source: 'publish');
    }

    final batch = await db.pruneOlderThan(2500, key);

    expect(batch.deletedAny, isTrue);
    expect(batch.count, 2);
    expect(batch.merkleRoot, isNotNull);
    expect(db.has(old1.id), isFalse);
    expect(db.has(old2.id), isFalse);
    expect(db.has(fresh.id), isTrue);

    final root = db.prunedRoots().single;
    expect(root.cutoffTs, 2500);
    expect(root.merkleRoot, batch.merkleRoot);
    expect(root.devicePubKey, await key.hexPub);

    final data = rootSignatureData(root.merkleRoot, root.cutoffTs, root.count);
    final verified = await Ed25519().verify(
      data,
      signature: Signature(
        hexToBytes(root.signature),
        publicKey: SimplePublicKey(
          hexToBytes(root.devicePubKey),
          type: KeyPairType.ed25519,
        ),
      ),
    );
    expect(verified, isTrue);
  });

  test('pruneRelayWindow keeps remembered recipients and prunes the rest',
      () async {
    key = await HostKey.generate();
    final sender = await DtmKeyPair.generate();
    final ra = await DtmKeyPair.generate();
    final rb = await DtmKeyPair.generate();
    final raX = await ra.x25519PublicKeyHex;
    final rbX = await rb.x25519PublicKeyHex;

    final unremembered1 = await stamp(sender, raX, 'u1', 1000);
    final remembered = await stamp(sender, rbX, 'remembered', 2000);
    final unremembered2 = await stamp(sender, raX, 'u2', 3000);
    for (final e in [unremembered1, remembered, unremembered2]) {
      db.insertIfAbsent(e, source: 'publish');
    }
    db.rememberSubscription(rbX, 9000);

    final now = 10000;
    final batch = await db.pruneRelayWindow(
      now,
      5000,
      db.rememberedSubscriptions(now, 5000),
      key,
    );

    expect(batch.count, 2);
    expect(db.has(unremembered1.id), isFalse);
    expect(db.has(unremembered2.id), isFalse);
    expect(db.has(remembered.id), isTrue);
    expect(db.prunedRoots(), hasLength(1));
  });

  test('pruning nothing writes no root', () async {
    key = await HostKey.generate();
    final now = DateTime.now().toUtc().millisecondsSinceEpoch;
    final batch = await db.pruneOlderThan(now, key);
    expect(batch.deletedAny, isFalse);
    expect(batch.merkleRoot, isNull);
    expect(db.prunedRoots(), isEmpty);
  });

  group('tracker registry', () {
    test('rememberPeer merges facts without wiping them', () {
      db.rememberPeer(
        'id-a',
        xPubKey: 'a' * 64,
        addrs: const ['/ip4/1.2.3.4/tcp/9'],
        nowMs: 1000,
      );
      db.rememberPeer('id-a', nowMs: 2000);
      db.rememberPeer(
        'id-a',
        addrs: const ['/ip4/5.6.7.8/tcp/9'],
        nowMs: 3000,
      );

      final sampled = db.samplePeers(10, nowMs: 3000, ttlMs: 100000);
      expect(sampled, hasLength(1));
      expect(sampled.single.xPubKey, 'a' * 64);
      expect(sampled.single.peerId, 'id-a');
      expect(sampled.single.addrs, ['/ip4/5.6.7.8/tcp/9']);
      expect(sampled.single.lastSeen, 3000);
    });

    test('samplePeers excludes the asker and honours the limit', () {
      for (var i = 0; i < 12; i++) {
        db.rememberPeer(
          'id-$i',
          xPubKey: 'a' * 64,
          addrs: const ['/ip4/1.2.3.4/tcp/9'],
          nowMs: 1000 + i,
        );
      }
      final limited = db.samplePeers(4, nowMs: 2000, ttlMs: 100000);
      expect(limited, hasLength(4));

      final withoutSelf = db.samplePeers(
        20,
        excludePeerId: 'id-3',
        nowMs: 2000,
        ttlMs: 100000,
      );
      expect(withoutSelf.map((p) => p.peerId), isNot(contains('id-3')));
    });

    test('stale peers are forgotten by TTL', () {
      db.rememberPeer('id-a', addrs: const ['/ip4/1.2.3.4/tcp/9'], nowMs: 1000);
      db.rememberPeer('id-b', addrs: const ['/ip4/1.2.3.4/tcp/9'], nowMs: 5000);

      final at6000 = db.samplePeers(
        20,
        excludePeerId: '',
        nowMs: 6000,
        ttlMs: 3000,
      );
      expect(at6000.map((p) => p.peerId), ['id-b']);
    });

    test('the registry is bounded by maxKnownPeers', () {
      final cap = maxKnownPeers;
      for (var i = 0; i < cap + 5; i++) {
        db.rememberPeer(
          'pe-$i',
          addrs: const ['/ip4/1.2.3.4/tcp/9'],
          nowMs: 1000 + i,
        );
      }
      final sampled = db.samplePeers(
        1 << 20,
        excludePeerId: '',
        nowMs: 1 << 30,
        ttlMs: 1 << 30,
      );
      expect(sampled.length, lessThanOrEqualTo(cap));
    });

    test('subscription keys are evicted beyond the row cap', () {
      for (var i = 0; i < 5; i++) {
        db.rememberSubscription('k$i', 1000 + i, maxRows: 3);
      }
      expect(db.subscriptionCount(), 3);
      // The newest arrivals survive the eviction.
      expect(db.rememberedSubscriptions(1010, 1000), {'k2', 'k3', 'k4'});
    });
  });
}