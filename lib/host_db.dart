import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

import 'package:dtm_app/core/host/host_link.dart' show HostEndpoint;
import 'package:dtm_app/core/security_limits.dart'
    show maxFederatedHosts, maxHostSubscriptionRows, maxKnownPeers;
import 'package:dtm_app/core/storage/merkle.dart' show merkleRoot;
import 'package:dtm_app/core/sync/gossip_message.dart' show PeerRef;
import 'package:dtm_app/models/envelope.dart';
import 'package:sqlite3/open.dart' as open_lib;
import 'package:sqlite3/sqlite3.dart' as sqlite3_pkg;

import 'host_key.dart';

/// Raw-sqlite store for a relay host.
///
/// The schema mirrors the device `messages` table (plus the recipient index
/// and a subscription table) so envelope rows round-trip unchanged, but the
/// host never imports the app's drift layer (which pulls in Flutter).
///
/// Policy: an envelope is accepted unconditionally (bounded by caps and the
/// rate limiter) but retained for relay-window pruning unless its recipient
/// is a remembered subscription. Every prune signs a Merkle root with the
/// host key, exactly like the device-side procedure.
class HostDatabase {
  final sqlite3_pkg.Database _db;
  final String? _path;

  HostDatabase._(this._db, [this._path]);

  static Future<HostDatabase> open(String path) async {
    _resolveSqlite3();
    File(path).parent.createSync(recursive: true);
    final db = sqlite3_pkg.sqlite3.open(path);
    final hostDb = HostDatabase._(db, path);
    hostDb._ensureSchema();
    return hostDb;
  }

  /// Size of the database file on disk, 0 for an in-memory database.
  int get fileBytes {
    final path = _path;
    if (path == null) return 0;
    final file = File(path);
    return file.existsSync() ? file.lengthSync() : 0;
  }

  static HostDatabase openInMemory() {
    _resolveSqlite3();
    final db = sqlite3_pkg.sqlite3.openInMemory();
    final hostDb = HostDatabase._(db);
    hostDb._ensureSchema();
    return hostDb;
  }

  void _ensureSchema() {
    _db.execute(
      'CREATE TABLE IF NOT EXISTS messages ('
      'id TEXT PRIMARY KEY,'
      'sender_pub_key TEXT NOT NULL,'
      'recipient_pub_key TEXT NOT NULL,'
      'timestamp INTEGER NOT NULL,'
      'ciphertext TEXT NOT NULL,'
      'ephemeral_pub_key TEXT NOT NULL,'
      'signature TEXT NOT NULL,'
      'source TEXT NOT NULL,'
      'hops INTEGER NOT NULL DEFAULT 0,'
      'chain_link TEXT NOT NULL DEFAULT \'\')',
    );
    _addColumnIfMissing(
      'messages',
      'chain_link TEXT NOT NULL DEFAULT \'\'',
    );
    _db.execute(
      'CREATE INDEX IF NOT EXISTS idx_messages_ts '
      'ON messages(timestamp)',
    );
    _db.execute(
      'CREATE INDEX IF NOT EXISTS idx_messages_recipient_ts '
      'ON messages(recipient_pub_key, timestamp)',
    );
    _db.execute(
      'CREATE TABLE IF NOT EXISTS pruned_roots ('
      'id INTEGER PRIMARY KEY AUTOINCREMENT,'
      'cutoff_ts INTEGER NOT NULL,'
      'merkle_root TEXT NOT NULL,'
      'count INTEGER NOT NULL,'
      'device_pub_key TEXT NOT NULL,'
      'signature TEXT NOT NULL)',
    );
    _db.execute(
      'CREATE TABLE IF NOT EXISTS host_subscriptions ('
      'recipient_key TEXT PRIMARY KEY,'
      'last_seen INTEGER NOT NULL)',
    );
    _db.execute(
      'CREATE TABLE IF NOT EXISTS host_state ('
      'key TEXT PRIMARY KEY,'
      'value TEXT NOT NULL)',
    );
    _db.execute(
      'CREATE TABLE IF NOT EXISTS known_peers ('
      'peer_id TEXT PRIMARY KEY,'
      'x_pub_key TEXT NOT NULL DEFAULT \'\','
      'addrs TEXT NOT NULL DEFAULT \'[]\','
      'first_seen INTEGER NOT NULL,'
      'last_seen INTEGER NOT NULL)',
    );
    _db.execute(
      'CREATE TABLE IF NOT EXISTS federated_hosts ('
      'addr TEXT PRIMARY KEY,'
      'ed_pub_key TEXT NOT NULL DEFAULT \'\','
      'first_seen INTEGER NOT NULL,'
      'last_seen INTEGER NOT NULL)',
    );
  }

  static void _resolveSqlite3() {
    try {
      // Triggers the package's default loader.
      sqlite3_pkg.sqlite3;
    } catch (_) {
      open_lib.open.overrideForAll(
        () => DynamicLibrary.open('libsqlite3.so.0'),
      );
    }
  }

  /// Migrates a pre-chain_link host DB in place; new databases already carry
  /// the column, so this is a no-op for them.
  void _addColumnIfMissing(String table, String definition) {
    final columnName = definition.split(' ').first;
    final columns = _db.select(
      'PRAGMA table_info($table)',
    );
    final has = columns.any((r) => r['name'] == columnName);
    if (!has) {
      _db.execute('ALTER TABLE $table ADD COLUMN $definition');
    }
  }

  String? readState(String key) {
    final rows = _db.select(
      'SELECT value FROM host_state WHERE key = ?',
      [key],
    );
    if (rows.isEmpty) return null;
    return rows.first['value'] as String;
  }

  void writeState(String key, String value) {
    _db.execute(
      'INSERT OR REPLACE INTO host_state (key, value) VALUES (?, ?)',
      [key, value],
    );
  }

  /// Insert-or-ignore by id; returns `true` only when a new row was written.
  bool insertIfAbsent(
    Envelope envelope, {
    String source = 'publish',
    int hops = 0,
  }) {
    _db.execute(
      'INSERT OR IGNORE INTO messages ('
      'id, sender_pub_key, recipient_pub_key, timestamp, ciphertext, '
      'ephemeral_pub_key, signature, source, hops, chain_link) '
      'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [
        envelope.id,
        envelope.senderPubKey,
        envelope.recipientPubKey,
        envelope.timestamp,
        envelope.ciphertext,
        envelope.ephemeralPubKey,
        envelope.signature,
        source,
        hops,
        envelope.chainLink,
      ],
    );
    return _db.updatedRows == 1;
  }

  bool has(String id) {
    final rows = _db.select('SELECT 1 FROM messages WHERE id = ?', [id]);
    return rows.isNotEmpty;
  }

  Envelope? envelopeById(String id) {
    final rows = _db.select(
      'SELECT * FROM messages WHERE id = ?',
      [id],
    );
    if (rows.isEmpty) return null;
    return _toEnvelope(rows.first);
  }

  List<String> idsSince(int sinceTs, {int? limit}) {
    var sql = 'SELECT id FROM messages WHERE timestamp >= ? '
        'ORDER BY timestamp ASC, id ASC';
    final params = <Object?>[sinceTs];
    if (limit != null) {
      sql += ' LIMIT ?';
      params.add(limit);
    }
    return _db.select(sql, params).map((r) => r['id'] as String).toList();
  }

  /// Envelopes addressed to any of [keys] with `timestamp >= [sinceTs]`,
  /// oldest-first. Bounded by [limit].
  List<Envelope> envelopesForRecipients(
    List<String> keys,
    int sinceTs, {
    int? limit,
  }) {
    if (keys.isEmpty) return const [];
    final placeholders = List<String>.filled(keys.length, '?').join(', ');
    final params = <Object?>[...keys, sinceTs];
    var sql = 'SELECT * FROM messages WHERE recipient_pub_key IN '
        '($placeholders) AND timestamp >= ? '
        'ORDER BY timestamp ASC, id ASC';
    if (limit != null) {
      sql += ' LIMIT ?';
      params.add(limit);
    }
    return _db.select(sql, params).map(_toEnvelope).toList();
  }

  int? latestTimestamp() {
    final rows = _db.select('SELECT MAX(timestamp) AS m FROM messages');
    if (rows.isEmpty || rows.first['m'] == null) return null;
    return rows.first['m'] as int;
  }

  void rememberSubscription(
    String recipientKey,
    int nowMs, {
    int maxRows = maxHostSubscriptionRows,
  }) {
    _db.execute(
      'INSERT OR REPLACE INTO host_subscriptions (recipient_key, last_seen) '
      'VALUES (?, ?)',
      [recipientKey, nowMs],
    );
    final rows = _db.select('SELECT COUNT(*) AS c FROM host_subscriptions')
        .first['c'] as int;
    if (rows > maxRows) {
      _db.execute(
        'DELETE FROM host_subscriptions WHERE recipient_key NOT IN ('
        'SELECT recipient_key FROM host_subscriptions '
        'ORDER BY last_seen DESC LIMIT ?)',
        [maxRows],
      );
    }
  }

  /// Upserts a peer into the tracker registry, merging new facts over the
  /// stored row (an empty xPubKey or addr list keeps the previous value) and
  /// refreshing the health timestamps. Bounded by [maxKnownPeers]: the oldest
  /// rows are evicted once the cap is hit.
  void rememberPeer(
    String peerId, {
    String? xPubKey,
    List<String> addrs = const [],
    required int nowMs,
  }) {
    final previous = _peerRow(peerId);
    final storedX = previous?['x_pub_key'] as String? ?? '';
    final mergedX = xPubKey == null || xPubKey.isEmpty ? storedX : xPubKey;
    final jsonAddrs = previous?['addrs'] as String? ?? '[]';
    final mergedAddrs = addrs.isEmpty ? jsonAddrs : jsonEncode(addrs);
    final init = previous?['first_seen'] as int? ?? nowMs;
    _db.execute(
      'INSERT INTO known_peers '
      '(peer_id, x_pub_key, addrs, first_seen, last_seen) '
      'VALUES (?, ?, ?, ?, ?) '
      'ON CONFLICT(peer_id) DO UPDATE SET '
      'x_pub_key = excluded.x_pub_key, '
      'addrs = excluded.addrs, last_seen = excluded.last_seen',
      [peerId, mergedX, mergedAddrs, init, nowMs],
    );
    final oversized = _db.select('SELECT COUNT(*) AS c FROM known_peers')
        .first['c'] as int;
    if (oversized > maxKnownPeers) {
      _db.execute(
        'DELETE FROM known_peers WHERE first_seen NOT IN ('
        'SELECT first_seen FROM known_peers ORDER BY first_seen DESC '
        'LIMIT ?)',
        [maxKnownPeers],
      );
    }
  }

  /// Forgets peers that have not refreshed themselves within the TTL.
  void forgetStalePeers(int cutoffMs) {
    _db.execute(
      'DELETE FROM known_peers WHERE last_seen < ?',
      [cutoffMs],
    );
  }

  /// Records a host the network introduced us to (addr-keyed). Keeping the
  /// first-seen marker lets the oldest member be forgotten first when the
  /// membership grows past [maxFederatedHosts].
  void rememberFederatedHost(HostEndpoint endpoint, int nowMs) {
    final previous = _db.select(
      'SELECT first_seen FROM federated_hosts WHERE addr = ?',
      [endpoint.addr],
    );
    final firstSeen = previous.isEmpty
        ? nowMs
        : previous.first['first_seen'] as int;
    _db.execute(
      'INSERT OR REPLACE INTO federated_hosts '
      '(addr, ed_pub_key, first_seen, last_seen) '
      'VALUES (?, ?, ?, ?)',
      [endpoint.addr, endpoint.edPubKey ?? '', firstSeen, nowMs],
    );
  }

  /// Rows the relay currently stores, for the operational log line.
  int envelopeCount() =>
      _db.select('SELECT COUNT(*) AS c FROM messages').first['c'] as int;

  /// Tracker-known peers currently stored.
  int peerCount() =>
      _db.select('SELECT COUNT(*) AS c FROM known_peers').first['c'] as int;

  /// Subscription keys currently remembered.
  int subscriptionCount() =>
      _db.select('SELECT COUNT(*) AS c FROM host_subscriptions').first['c']
          as int;

  /// Every network member this host knows about, including ones introduced  /// by other members (survives restarts). Bounded by [maxFederatedHosts];
  /// the oldest entries are evicted beyond the ceiling.
  List<HostEndpoint> federatedHosts() {
    _db.execute(
      'DELETE FROM federated_hosts WHERE addr NOT IN ('
      'SELECT addr FROM federated_hosts ORDER BY first_seen DESC LIMIT ?)',
      [maxFederatedHosts],
    );
    final rows = _db.select(
      'SELECT * FROM federated_hosts ORDER BY first_seen ASC',
    );
    return rows.map((r) {
      final pk = r['ed_pub_key'] as String;
      return HostEndpoint(
        addr: r['addr'] as String,
        edPubKey: pk.isEmpty ? null : pk,
      );
    }).toList(growable: false);
  }

  /// A random, bounded sample of live peers to hand to a device that asked
  /// for more contacts; the asker itself is excluded so it never gets a
  /// self-dial suggestion.
  List<PeerRef> samplePeers(
    int limit, {
    String? excludePeerId,
    required int nowMs,
    required int ttlMs,
  }) {
    forgetStalePeers(nowMs - ttlMs);
    final rows = _db.select(
      'SELECT * FROM known_peers WHERE peer_id != ? '
      'ORDER BY RANDOM() LIMIT ?',
      [excludePeerId ?? '', limit],
    );
    return rows.map(_toPeerRef).toList(growable: false);
  }

  sqlite3_pkg.Row? _peerRow(String peerId) {
    final rows = _db.select(
      'SELECT * FROM known_peers WHERE peer_id = ?',
      [peerId],
    );
    if (rows.isEmpty) return null;
    return rows.first;
  }

  PeerRef _toPeerRef(sqlite3_pkg.Row row) {
    final addrsRaw = row['addrs'] as String;
    final List<String> addrs;
    try {
      final decoded = jsonDecode(addrsRaw);
      if (decoded is! List) {
        return PeerRef(
          xPubKey: row['x_pub_key'] as String,
          peerId: row['peer_id'] as String,
          lastSeen: row['last_seen'] as int?,
        );
      }
      addrs = decoded
          .whereType<String>()
          .where((addr) => addr.startsWith('/'))
          .toList(growable: false);
    } on FormatException {
      return PeerRef(
        xPubKey: row['x_pub_key'] as String,
        peerId: row['peer_id'] as String,
        lastSeen: row['last_seen'] as int?,
      );
    }
    return PeerRef(
      xPubKey: row['x_pub_key'] as String,
      peerId: row['peer_id'] as String,
      addrs: addrs,
      lastSeen: row['last_seen'] as int?,
    );
  }

  /// The keys a client asked this host to hold for at least one [retentionMs]
  /// window, even while that client is offline.
  Set<String> rememberedSubscriptions(int nowMs, int retentionMs) {
    final rows = _db.select(
      'SELECT recipient_key FROM host_subscriptions '
      'WHERE last_seen >= ?',
      [nowMs - retentionMs],
    );
    return rows.map((r) => r['recipient_key'] as String).toSet();
  }

  void forgetExpiredSubscriptions(int nowMs, int retentionMs) {
    _db.execute(
      'DELETE FROM host_subscriptions WHERE last_seen < ?',
      [nowMs - retentionMs],
    );
  }

  /// Age-based prune (default 30 days). Always signs a Merkle root first.
  Future<PrunedHostBatch> pruneOlderThan(
    int cutoffMs,
    HostKey key,
  ) async {
    final ids = _idsOlderThan(cutoffMs);
    return _pruneIds(ids, cutoffMs, key);
  }

  /// Drops envelopes older than [nowMs] - [windowMs] whose recipient is not
  /// a remembered subscription (relay-window gossip cache). Signed too.
  Future<PrunedHostBatch> pruneRelayWindow(
    int nowMs,
    int windowMs,
    Set<String> remembered,
    HostKey key,
  ) async {
    final params = <Object?>[nowMs - windowMs];
    var sql = 'SELECT id FROM messages WHERE timestamp < ? ';
    if (remembered.isNotEmpty) {
      final placeholders = List<String>.filled(remembered.length, '?').join(
        ', ',
      );
      sql += 'AND recipient_pub_key NOT IN ($placeholders)';
      params.addAll(remembered);
    }
    sql += ' ORDER BY timestamp ASC, id ASC';
    final ids = _db.select(sql, params).map((r) => r['id'] as String).toList();
    final cutoff = nowMs - windowMs;
    return _pruneIds(ids, cutoff, key);
  }

  Future<PrunedHostBatch> _pruneIds(
    List<String> ids,
    int cutoff,
    HostKey key,
  ) async {
    if (ids.isEmpty) {
      return PrunedHostBatch(cutoffTs: cutoff, count: 0, merkleRoot: null);
    }
    final root = await merkleRoot(ids) ?? '';
    final signature = await key.sign(
      _rootData(root, cutoff, ids.length),
    );
    final pub = await key.hexPub;
    _db.execute(
      'INSERT INTO pruned_roots '
      '(cutoff_ts, merkle_root, count, device_pub_key, signature) '
      'VALUES (?, ?, ?, ?, ?)',
      [cutoff, root, ids.length, pub, signature],
    );
    final placeholders = List<String>.filled(ids.length, '?').join(', ');
    _db.execute(
      'DELETE FROM messages WHERE id IN ($placeholders) AND '
      'timestamp < ?',
      [...ids, cutoff],
    );
    return PrunedHostBatch(
      cutoffTs: cutoff,
      count: ids.length,
      merkleRoot: root,
      signature: signature,
    );
  }

  List<String> _idsOlderThan(int cutoff) {
    final rows = _db.select(
      'SELECT id FROM messages WHERE timestamp < ? '
      'ORDER BY timestamp ASC, id ASC',
      [cutoff],
    );
    return rows.map((r) => r['id'] as String).toList();
  }

  List<PrunedRootRow> prunedRoots() {
    final rows = _db.select(
      'SELECT * FROM pruned_roots ORDER BY cutoff_ts ASC',
    );
    return rows
        .map(
          (r) => PrunedRootRow(
            cutoffTs: r['cutoff_ts'] as int,
            merkleRoot: r['merkle_root'] as String,
            count: r['count'] as int,
            devicePubKey: r['device_pub_key'] as String,
            signature: r['signature'] as String,
          ),
        )
        .toList();
  }

  void dispose() {
    _db.dispose();
  }

  Envelope _toEnvelope(sqlite3_pkg.Row row) => Envelope(
    id: row['id'] as String,
    senderPubKey: row['sender_pub_key'] as String,
    recipientPubKey: row['recipient_pub_key'] as String,
    timestamp: row['timestamp'] as int,
    ciphertext: row['ciphertext'] as String,
    ephemeralPubKey: row['ephemeral_pub_key'] as String,
    signature: row['signature'] as String,
    chainLink: row['chain_link'] as String? ?? '',
  );

  /// Byte layout matching the device's `rootSignatureData` so roots signed
  /// by a host can be verified with the app's PrunedRootsDao.
  static List<int> _rootData(String root, int cutoff, int count) {
    final out = <int>[];
    out.addAll(root.codeUnits);
    out.addAll('$cutoff'.codeUnits);
    out.addAll('$count'.codeUnits);
    return out;
  }
}

class PrunedHostBatch {
  final int cutoffTs;
  final int count;
  final String? merkleRoot;
  final String? signature;

  const PrunedHostBatch({
    required this.cutoffTs,
    required this.count,
    required this.merkleRoot,
    this.signature,
  });

  bool get deletedAny => count > 0;
}

class PrunedRootRow {
  final int cutoffTs;
  final String merkleRoot;
  final int count;
  final String devicePubKey;
  final String signature;

  const PrunedRootRow({
    required this.cutoffTs,
    required this.merkleRoot,
    required this.count,
    required this.devicePubKey,
    required this.signature,
  });
}