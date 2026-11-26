import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:dtm_app/core/crypto/hex.dart' show isHexOfLength;
import 'package:dtm_app/core/host/host_link.dart' show HostEndpoint;
import 'package:dtm_app/core/host/rate_limiter.dart';
import 'package:dtm_app/core/security_limits.dart' as limits;
import 'package:dtm_app/core/sync/gossip_message.dart';
import 'package:dtm_app/models/envelope.dart';

import 'host_config.dart';
import 'host_db.dart';
import 'host_key.dart';
import 'host_version.dart';

/// A federation relay: an operator-run process that stores only opaque,
/// encrypted envelopes, relays them live to subscribed clients and to peer
/// hosts, answers backfill (WANT/HAVE/GET), and prunes to a signed Merkle
/// trail. It can never decrypt or read a single message.
class HostServer {
  final HostDatabase db;
  final HostKey key;
  final HostConfig config;
  final RateLimiter _rateLimiter;
  final RateLimiter _liveLimiter;
  final RateLimiter _globalLimiter;
  int _insertsSinceCapCheck = 0;
  final Set<_ClientContext> _connections = {};
  final Map<String, _PeerLink> _links = {};
  HttpServer? _httpServer;
  Timer? _pruneTimer;
  Timer? _federationTimer;
  Timer? _presenceTimer;
  String? _lastPresence;
  bool _started = false;
  DateTime? _startedAt;

  /// Process counters since start, exposed as aggregate metrics only.
  int _connectionsTotal = 0;
  int _receivedTotal = 0;
  int _relayedTotal = 0;
  int _rejectedTotal = 0;
  int _duplicateTotal = 0;
  int _backfillTotal = 0;
  int _liveTotal = 0;

  /// DNS answers for announced endpoints, so a host that reconnects often does
  /// not turn into a resolver flood.
  final Map<String, _AddrCheck> _addrCheckCache = {};

  /// This host's own reachable endpoint (identity + announce URL), computed
  /// once the socket is bound.
  HostEndpoint? _selfEndpoint;

  HostServer._({
    required this.db,
    required this.key,
    required this.config,
    required RateLimiter rateLimiter,
    required RateLimiter liveLimiter,
    required RateLimiter globalLimiter,
  }) : _rateLimiter = rateLimiter,
       _liveLimiter = liveLimiter,
       _globalLimiter = globalLimiter;

  factory HostServer({
    required HostDatabase db,
    required HostKey key,
    required HostConfig config,
  }) {
    return HostServer._(
      db: db,
      key: key,
      config: config,
      rateLimiter: RateLimiter(
        limitPerWindow: config.rateLimitPerWindow,
        windowSeconds: config.rateWindowSeconds,
        maxKeys: config.rateLimiterMaxKeys,
      ),
      liveLimiter: RateLimiter(
        limitPerWindow: config.liveRateLimitPerWindow,
        windowSeconds: config.rateWindowSeconds,
        maxKeys: config.rateLimiterMaxKeys,
      ),
      globalLimiter: RateLimiter(
        limitPerWindow: config.globalRateLimitPerWindow,
        windowSeconds: config.rateWindowSeconds,
        maxKeys: 1,
      ),
    );
  }

  /// The TCP port this server bound to after [start]. 0 while not started.
  int get boundPort => _httpServer?.port ?? 0;

  Future<void> start() async {
    if (_started) return;
    _started = true;
    _startedAt = DateTime.now().toUtc();
    final addr = InternetAddress.tryParse(config.listenAddress) ??
        InternetAddress.anyIPv4;
    final server = await HttpServer.bind(addr, config.port);
    _httpServer = server;
    _selfEndpoint = HostEndpoint(
      addr: _effectiveAnnounce(),
      edPubKey: await key.hexPub,
    );
    server.listen(_handleHttpRequest);
    _pruneTimer = Timer.periodic(
      config.pruneInterval,
      (_) => unawaited(_guarded(
        _prune,
        'prune',
      )),
    );
    _federationTimer = Timer.periodic(
      config.federationSyncInterval,
      (_) => unawaited(_guarded(() async {
        _federationSync();
      })),
    );
    for (final peer in config.federatedPeers) {
      unawaited(_startPeerLink(peer));
    }
    for (final member in db.federatedHosts()) {
      unawaited(_startPeerLink(member, requirePublic: true));
    }
    await _prune();
  }

  Future<void> stop() async {
    _pruneTimer?.cancel();
    _federationTimer?.cancel();
    _presenceTimer?.cancel();
    for (final link in _links.values) {
      link.closed = true;
      link.backoff?.cancel();
    }
    final sockets = _connections.map((c) => c.ws).toList(growable: false);
    for (final ws in sockets) {
      await ws.close();
    }
    _connections.clear();
    _links.clear();
    await _httpServer?.close(force: true);
    _httpServer = null;
  }

  Future<void> _handleHttpRequest(HttpRequest request) async {
    try {
      if (request.method == 'GET' &&
          (request.uri.path == '/status' ||
              request.uri.path == '/status/')) {
        await _sendStatus(request.response);
        return;
      }
      if (request.method == 'GET' &&
          (request.uri.path == '/directory' ||
              request.uri.path == '/directory/')) {
        await _sendDirectory(request.response);
        return;
      }
      if (request.method == 'GET' &&
          (request.uri.path == '/healthz' ||
              request.uri.path == '/healthz/')) {
        request.response.headers
          ..contentType = ContentType.json
          ..set(HttpHeaders.cacheControlHeader, 'no-store')
          ..set('Access-Control-Allow-Origin', '*');
        request.response.write(jsonEncode({'ok': true}));
        await request.response.close();
        return;
      }
      if (request.method == 'GET' && request.uri.path == '/ws') {
        if (_connections.length >= config.maxConnections) {
          request.response.statusCode = HttpStatus.serviceUnavailable;
          await request.response.close();
          return;
        }
        final remote = request.connectionInfo?.remoteAddress;
        final ws = await WebSocketTransformer.upgrade(request);
        // A peer that stops answering pings is dropped instead of pinning a
        // socket forever.
        ws.pingInterval = limits.hostIdleTimeout;
        unawaited(_handleSocket(ws, remote: remote));
        return;
      }
      request.response.statusCode = HttpStatus.notFound;
      await request.response.close();
    } catch (_) {
      // A malformed upgrade must not surface as an unhandled async error.
    }
  }

  /// Public network directory for the site's relay table.
  ///
  /// Lists the relay's own reachable endpoint and its federated members with
  /// their Ed25519 identities. Addresses and public keys are already published
  /// in invites; no envelope, client address or seed ever appears here.
  Future<void> _sendDirectory(HttpResponse response) async {
    final self = _selfEndpoint;
    response.headers
      ..contentType = ContentType.json
      ..set(HttpHeaders.cacheControlHeader, 'no-store')
      ..set('Access-Control-Allow-Origin', '*');
    if (self == null) {
      response.statusCode = HttpStatus.serviceUnavailable;
      response.write(jsonEncode({'ok': false}));
      await response.close();
      return;
    }
    final members = <Map<String, String>>[];
    final seen = <String>{self.addr};
    for (final endpoint in _networkMembers()) {
      final key = endpoint.edPubKey;
      if (key == null || key.isEmpty || key == self.edPubKey) continue;
      if (!seen.add(endpoint.addr)) continue;
      if (!_publiclyRoutable(endpoint.addr)) continue;
      members.add({'addr': endpoint.addr, 'ed25519': key});
      if (members.length >= limits.maxFederatedHosts) break;
    }
    response.write(jsonEncode({
      'ok': true,
      'ts': DateTime.now().toUtc().millisecondsSinceEpoch,
      'self': {'addr': self.addr, 'ed25519': self.edPubKey},
      'members': members,
    }));
    await response.close();
  }

  /// Resident set size of this process, or null when the platform does not
  /// expose it.
  static int? _rssBytes() {
    try {
      for (final line in File('/proc/self/status').readAsLinesSync()) {
        if (!line.startsWith('VmRSS:')) continue;
        final kb = int.tryParse(line.replaceAll(RegExp(r'[^0-9]'), ''));
        if (kb != null) return kb * 1024;
      }
    } catch (_) {
      // Not Linux or /proc unavailable.
    }
    return null;
  }

  /// One-minute load average, or null when it is not available.
  static double? _load1() {
    try {
      final raw = File('/proc/loadavg').readAsStringSync().trim();
      final first = raw.split(RegExp(r'\s+')).first;
      return double.tryParse(first);
    } catch (_) {
      return null;
    }
  }

  /// Operational status for the public status page and the alert script.
  ///
  /// Deliberately contains only aggregate counters and process health: no
  /// identity keys, no client addresses, no envelope metadata.
  Future<void> _sendStatus(HttpResponse response) async {
    final startedAt = _startedAt;
    final now = DateTime.now().toUtc();
    final uptime = startedAt == null
        ? 0
        : now.difference(startedAt).inSeconds;
    final payload = {
      'ok': true,
      'ts': now.millisecondsSinceEpoch,
      'startedAt': startedAt?.millisecondsSinceEpoch,
      'uptimeSeconds': uptime,
      'connections': _connections.where((c) => !c.closed).length,
      'connectionsTotal': _connectionsTotal,
      'federatedLinks': _links.length,
      'queue': db.envelopeCount(),
      'envelopes': db.envelopeCount(),
      'peers': db.peerCount(),
      'subscriptions': db.subscriptionCount(),
      'dbBytes': db.fileBytes,
      'receivedTotal': _receivedTotal,
      'relayedTotal': _relayedTotal,
      'rejectedTotal': _rejectedTotal,
      'duplicateTotal': _duplicateTotal,
      'backfillTotal': _backfillTotal,
      'liveTotal': _liveTotal,
      'rssBytes': _rssBytes(),
      'load1': _load1(),
      'version': hostVersion,
    };
    response.headers
      ..contentType = ContentType.json
      ..set(HttpHeaders.cacheControlHeader, 'no-store')
      ..set('Access-Control-Allow-Origin', '*');
    response.write(jsonEncode(payload));
    await response.close();
  }

  Future<void> _handleSocket(
    WebSocket ws, {
    _ClientContext? ctx,
    InternetAddress? remote,
  }) async {
    ctx ??= _ClientContext(ws: ws, remoteAddress: remote);
    _connectionsTotal++;
    _connections.add(ctx);
    try {
      await for (final frame in ws) {
        if (ctx.closed) break;
        // Check the raw frame before allocating a decoded string: a hostile
        // peer must not be able to make us UTF-8-decode megabytes first.
        final String text;
        if (frame is String) {
          if (frame.length > limits.maxFrameBytes) break;
          text = frame;
        } else if (frame is List<int>) {
          if (frame.length > limits.maxFrameBytes) break;
          text = utf8.decode(frame);
        } else {
          break;
        }
        if (text.length > limits.maxFrameBytes) break;
        final decoded = jsonDecode(text);
        if (decoded is! Map<String, dynamic>) break;
        await _dispatch(ctx, GossipMessage.fromJson(decoded));
      }
    } on FormatException {
      // Hostile or corrupt frame: connection dropped at the boundary.
    } on WebSocketException {
      // Remote closed abruptly.
    } catch (_) {
      // Any residual failure: drop this connection, keep the host going.
    } finally {
      ctx.closed = true;
      _connections.remove(ctx);
      final link = ctx.peerLink;
      if (link != null) link.wsGone();
      await ws.close();
      _schedulePresence();
    }
  }

  Future<void> _dispatch(_ClientContext ctx, GossipMessage message) async {
    switch (message) {
      case HelloMessage(
          :final myPeerId,
          :final capabilities,
          :final myAddrs,
          :final announce,
        ):
        if (myPeerId.isEmpty || myPeerId.length > limits.maxPeerIdLength) {
          throw const FormatException('HELLO peer id is out of bounds');
        }
        ctx.peerId = myPeerId;
        ctx.identity = myPeerId;
        ctx.capabilities.addAll(capabilities);
        // A relay role is granted, never claimed: an unknown client that
        // asserts `dtm-host` in its HELLO stays an ordinary client, so it can
        // never receive the federation fan-out or other devices' envelopes.
        ctx.isFederated = capabilities.contains('dtm-host') &&
            await _mayFederate(ctx, myPeerId, announce);
        if (!ctx.isFederated && myAddrs.isNotEmpty) {
          db.rememberPeer(
            myPeerId,
            addrs: myAddrs,
            nowMs: DateTime.now().toUtc().millisecondsSinceEpoch,
          );
        }
        _send(
          ctx,
          WelcomeMessage(
            serverTime: DateTime.now().toUtc().millisecondsSinceEpoch,
            retentionSeconds: config.retentionMs ~/ 1000,
            maxEnvelopeSize: limits.maxFrameBytes,
            identity: await key.hexPub,
            capabilities: const ['dtm-tracker', 'dtm-net', 'dtm-live'],
          ),
        );
        if (ctx.isFederated && ctx.networkCapable && announce != null) {
          _adoptNetworkMember(
            HostEndpoint(addr: announce, edPubKey: myPeerId),
          );
          _send(ctx, _networkMessage());
        }
        if (capabilities.contains(dtmPresence)) {
          _sendPresenceTo(ctx);
        }
      case SubscribeMessage(:final since, :final keys):
        final now = DateTime.now().toUtc().millisecondsSinceEpoch;
        final clampedSince = scanWindowStart(since, now);
        final clampedKeys = keys.take(
          limits.maxHostSubscriptionKeys,
        ).toList(growable: false);
        for (final k in clampedKeys) {
          if (!isHexOfLength(k, 32)) {
            throw const FormatException('Subscription key is not 32-byte hex');
          }
          db.rememberSubscription(k, now);
        }
        final peerIds = ctx.peerId;
        if (peerIds != null && clampedKeys.isNotEmpty) {
          db.rememberPeer(
            peerIds,
            xPubKey: clampedKeys.first,
            nowMs: now,
          );
        }
        ctx.subscribed
          ..clear()
          ..addAll(clampedKeys);
        final subscribedAt = now;
        ctx.subscribedAt
          ..clear()
          ..addEntries(
            clampedKeys.map((k) => MapEntry(k, subscribedAt)),
          );
        _schedulePresence();
        await _sendBackfill(ctx, clampedSince);
      case PublishMessage(:final envelope):
        final accepted = await _acceptEnvelope(
          envelope,
          source: 'publish',
          hops: 0,
        );
        if (accepted) {
          _fanOut(envelope, 0, except: ctx);
        }
        _send(
          ctx,
          PublishedMessage(id: envelope.id, accepted: accepted),
        );
      case PublishLiveMessage(:final envelope):
        final verified = await _verifyEnvelope(
          envelope,
          limiter: _liveLimiter,
        );
        var forwarded = 0;
        if (verified) {
          _liveTotal++;
          forwarded = _fanOutLive(envelope, except: ctx);
        }
        // A live frame is never stored, so "accepted" must mean it actually
        // reached a subscriber. Acknowledging a frame that was forwarded to
        // nobody would mark the slice sent and stop the sender's retries while
        // the recipient is simply connected to another relay.
        _send(
          ctx,
          PublishedMessage(
            id: envelope.id,
            accepted: verified && forwarded > 0,
          ),
        );
      case WantMessage(:final since):
        final now = DateTime.now().toUtc().millisecondsSinceEpoch;
        // The peer parser caps HAVE at maxGossipItems; a larger answer would
        // be dropped as a malformed frame and break federation on a busy host.
        final ids = db.idsSince(
          scanWindowStart(since, now),
          limit: limits.maxGossipItems,
        );
        _send(ctx, HaveMessage(ids: ids));
      case HaveMessage(:final ids):
        if (ctx.isFederated) {
          final missing = <String>[];
          for (final id in ids.take(limits.maxGossipItems)) {
            if (missing.length >= limits.maxGossipItems) break;
            if (db.envelopeById(id) == null) missing.add(id);
          }
          if (missing.isNotEmpty) {
            _send(ctx, GetMessage(ids: missing));
          }
        }
      case GetMessage(:final ids):
        final envelopes = <Envelope>[];
        for (final id in ids.take(limits.maxGossipItems)) {
          final envelope = db.envelopeById(id);
          if (envelope == null) continue;
          // Serving by id is not a bypass: a device only ever gets envelopes
          // addressed to a key it subscribed with.
          if (!_entitledTo(ctx, envelope)) continue;
          envelopes.add(envelope);
        }
        _send(ctx, EnvelopesMessage(envelopes: envelopes, done: true));
      case EnvelopesMessage(:final envelopes, :final hops):
        if (ctx.isFederated) {
          for (final envelope in envelopes) {
            final inserted = await _acceptEnvelope(
              envelope,
              source: 'federated',
              hops: hops,
            );
            if (inserted) _fanOut(envelope, hops, except: ctx);
          }
        }
      case WelcomeMessage(:final identity, :final capabilities):
        ctx.capabilities.addAll(capabilities);
        final link = ctx.peerLink;
        if (link != null && identity != null) {
          link.identity = identity;
          final pinned = link.endpoint.edPubKey;
          if (pinned != null && pinned != identity) {
            throw FormatException(
              'Host identity mismatch: expected $pinned got $identity',
            );
          }
        }
        if (ctx.isFederated && ctx.networkCapable) {
          _send(ctx, _networkMessage());
        }
      case PeerListRequestMessage():
        final now = DateTime.now().toUtc().millisecondsSinceEpoch;
        final peers = db.samplePeers(
          config.trackerSampleSize,
          excludePeerId: ctx.peerId,
          nowMs: now,
          ttlMs: config.trackerPeerTtlMs,
        );
        final hosts = _networkMembers()
            .where((h) => h.addr != _selfEndpoint?.addr)
            .take(limits.maxTrackerHosts)
            .toList(growable: false);
        _send(ctx, PeerListMessage(peers: peers, hosts: hosts));
      case NetworkMessage(:final hosts):
        if (!ctx.isFederated) break;
        if (!ctx.networkCapable) break;
        for (final endpoint in hosts) {
          _adoptNetworkMember(endpoint);
        }
      case PeerListMessage():
      case PublishedMessage():
      case PresenceMessage():
        break;
    }
  }

  /// Validation shared by stored and live envelopes: rate limit, clock skew,
  /// Ed25519 signature and content id. Nothing reaches the database here.
  Future<bool> _verifyEnvelope(
    Envelope envelope, {
    RateLimiter? limiter,
  }) async {
    final budget = limiter ?? _rateLimiter;
    if (!budget.allow(envelope.senderPubKey)) {
      _rejectedTotal++;
      return false;
    }
    if (!envelope.withinSkew()) {
      _rejectedTotal++;
      return false;
    }
    if (!await envelope.verify()) {
      _rejectedTotal++;
      return false;
    }
    if (!await envelope.hasValidId()) {
      _rejectedTotal++;
      return false;
    }
    return true;
  }

  Future<bool> _acceptEnvelope(
    Envelope envelope, {
    required String source,
    required int hops,
  }) async {
    // Global backstop: per-sender buckets are defeated by generating a fresh
    // Ed25519 key per envelope, so aggregate stored ingress needs its own cap.
    if (!_globalLimiter.allow('stored')) {
      _rejectedTotal++;
      return false;
    }
    if (!await _verifyEnvelope(envelope)) return false;
    final inserted = db.insertIfAbsent(envelope, source: source, hops: hops);
    if (inserted) {
      _receivedTotal++;
      _enforceStorageCapsMaybe();
    } else {
      _duplicateTotal++;
    }
    return inserted;
  }

  /// Check the count cap on every insert (cheap in memory) and the byte cap
  /// periodically; eviction is oldest-first and never signs a prune root,
  /// because a cap drop is a cache eviction, not a retention promise.
  void _enforceStorageCapsMaybe() {
    _insertsSinceCapCheck++;
    if (_insertsSinceCapCheck % 32 != 0) return;
    _enforceStorageCaps();
  }

  void _enforceStorageCaps() {
    final evicted = db.evictOldestBeyond(
      maxEnvelopes: config.maxStoredEnvelopes,
      maxBytes: config.maxStoredBytes,
    );
    if (evicted > 0) {
      _log('storage cap: evicted=$evicted '
          'envelopes=${db.envelopeCount()}');
    }
  }

  /// Forwards a live-only envelope to currently connected subscribers of its
  /// recipient. Federated relays are deliberately excluded: they store what
  /// they receive, and a media slice must never land on a relay's disk.
  int _fanOutLive(Envelope envelope, {_ClientContext? except}) {
    var forwarded = 0;
    for (final ctx in _connections.toList(growable: false)) {
      if (ctx.closed || ctx == except || ctx.isFederated) continue;
      if (!ctx.subscribed.contains(envelope.recipientPubKey)) continue;
      _send(
        ctx,
        EnvelopesMessage(envelopes: [envelope], done: false, hops: 0),
      );
      _relayedTotal++;
      forwarded++;
    }
    return forwarded;
  }

  /// Whether a directory entry is worth publishing: loopback, link-local,
  /// multicast and the private IPv4 ranges cannot be reached from the site's
  /// status probe, so they are left out of `/directory`.
  static bool _publiclyRoutable(String addr) {
    final uri = Uri.tryParse(addr);
    if (uri == null) return false;
    if (uri.scheme != 'ws' && uri.scheme != 'wss') return false;
    final host = uri.host.toLowerCase();
    if (host.isEmpty || host == 'localhost' || host == '::1') return false;
    final parsed = InternetAddress.tryParse(host);
    if (parsed == null) return true;
    if (parsed.isLoopback || parsed.isLinkLocal || parsed.isMulticast) {
      return false;
    }
    final raw = parsed.rawAddress;
    if (raw.length == 4) {
      if (raw[0] == 10) return false;
      if (raw[0] == 172 && raw[1] >= 16 && raw[1] <= 31) return false;
      if (raw[0] == 192 && raw[1] == 168) return false;
      if (raw[0] == 100 && raw[1] >= 64 && raw[1] <= 127) return false;
      if (raw[0] == 0) return false;
    }
    return true;
  }

  /// Whether [ctx] may act as a federated relay.
  ///
  /// A relay role is granted, never claimed. Three ways in:
  /// * we dialed the endpoint ourselves (its key is pinned by an operator seed
  ///   or by an earlier NETWORK exchange);
  /// * the key the client claims is a host this relay already knows;
  /// * the client is reachable at the endpoint it announces, i.e. the announced
  ///   host resolves to the address the socket actually came from. That is the
  ///   one-sided `--peer` bootstrap: B seeds A, A has never seen B, but B is
  ///   provably where it says it is.
  ///
  /// Anything else — notably an app client, or a listener behind NAT with no
  /// reachable endpoint — stays an ordinary client no matter what its HELLO
  /// advertises.
  Future<bool> _mayFederate(
    _ClientContext ctx,
    String? claimedKey,
    String? announce,
  ) async {
    if (claimedKey == null || claimedKey.isEmpty) return false;
    final link = ctx.peerLink;
    if (link != null) {
      final pinned = link.endpoint.edPubKey ?? '';
      return pinned.isEmpty || pinned == claimedKey;
    }
    // Inbound federation needs an operator decision. A claimed key is only a
    // string: knowing a public host key (including this relay's own key from
    // WELCOME, /directory or an invite) must never be enough.
    if (announce == null || announce.isEmpty) return false;
    final known = <HostEndpoint>[
      ...config.federatedPeers,
      ...db.federatedHosts(),
    ].where((e) => e.addr == announce && e.edPubKey == claimedKey);
    if (known.isNotEmpty) {
      // The operator pinned this exact endpoint/key pair (or a trusted member
      // introduced it). It may be a LAN address, so no public-address check.
      return _announceMatchesRemote(announce, ctx.remoteAddress);
    }
    if (!config.allowInboundFederation) return false;
    // Open meshes are opt-in. Require the announced endpoint to resolve to
    // the socket source and, by default, reject loopback/private targets so
    // a reverse proxy (where every client appears as 127.0.0.1) cannot be
    // spoofed into granting federation.
    return _announceMatchesRemote(
      announce,
      ctx.remoteAddress,
      requirePublic: !config.allowPrivateFederation,
    );
  }

  /// Whether the host part of [announce] resolves to the address the socket
  /// came from. Only `ws`/`wss` endpoints are considered; DNS results are
  /// cached briefly so a reconnecting host cannot hammer a resolver.
  Future<bool> _announceMatchesRemote(
    String announce,
    InternetAddress? remote, {
    bool requirePublic = false,
  }) async {
    if (remote == null) return false;
    if (requirePublic && !_isPublicAddress(remote)) return false;
    final uri = Uri.tryParse(announce);
    if (uri == null) return false;
    if (uri.scheme != 'ws' && uri.scheme != 'wss') return false;
    if (uri.host.isEmpty || announce.length > limits.maxAddrLength) {
      return false;
    }
    final cached = _addrCheckCache[uri.host];
    final now = DateTime.now();
    if (cached != null && now.isBefore(cached.expires)) {
      if (requirePublic &&
          !cached.addresses.every(_isPublicAddress)) {
        return false;
      }
      return _sameAddress(cached.addresses, remote);
    }
    List<InternetAddress> addresses;
    try {
      addresses = await InternetAddress.lookup(uri.host).timeout(
        const Duration(seconds: 5),
      );
    } catch (_) {
      addresses = const [];
    }
    _addrCheckCache[uri.host] = _AddrCheck(
      addresses: addresses,
      expires: now.add(const Duration(minutes: 10)),
    );
    if (_addrCheckCache.length > limits.maxFederatedHosts * 4) {
      _addrCheckCache.remove(_addrCheckCache.keys.first);
    }
    if (requirePublic && !addresses.every(_isPublicAddress)) return false;
    return _sameAddress(addresses, remote);
  }

  /// Whether [address] is globally routable. Used to keep opt-in inbound
  /// federation from being spoofed through loopback or a private network.
  static bool _isPublicAddress(InternetAddress address) {
    final raw = address.rawAddress;
    if (raw.length == 4) {
      final a = raw[0];
      final b = raw[1];
      if (a == 0 || a == 10 || a == 127) return false;
      if (a == 169 && b == 254) return false;
      if (a == 172 && b >= 16 && b <= 31) return false;
      if (a == 192 && b == 168) return false;
      if (a == 100 && b >= 64 && b <= 127) return false;
      if (a >= 224) return false;
      return true;
    }
    if (raw.length == 16) {
      if (raw.every((b) => b == 0)) return false;
      if (raw.sublist(0, 15).every((b) => b == 0) && raw[15] == 1) {
        return false; // ::1 loopback
      }
      if (raw[0] == 0xfe && (raw[1] & 0xc0) == 0x80) return false;
      if ((raw[0] & 0xfe) == 0xfc) return false;
      if (raw[0] == 0xff) return false;
      final v4Mapped = raw.sublist(0, 10).every((b) => b == 0) &&
          raw[10] == 0xff && raw[11] == 0xff;
      if (v4Mapped) {
        final a = raw[12];
        final b = raw[13];
        if (a == 0 || a == 10 || a == 127) return false;
        if (a == 169 && b == 254) return false;
        if (a == 172 && b >= 16 && b <= 31) return false;
        if (a == 192 && b == 168) return false;
        if (a == 100 && b >= 64 && b <= 127) return false;
        if (a >= 224) return false;
      }
      return true;
    }
    return false;
  }

  static bool _sameAddress(
    List<InternetAddress> candidates,
    InternetAddress remote,
  ) {
    final target = remote.rawAddress;
    for (final candidate in candidates) {
      final raw = candidate.rawAddress;
      if (raw.length != target.length) continue;
      var same = true;
      for (var i = 0; i < raw.length; i++) {
        if (raw[i] != target[i]) {
          same = false;
          break;
        }
      }
      if (same) return true;
    }
    return false;
  }

  /// Whether [ctx] is entitled to see [envelope]: relays see the whole store,
  /// a device only what it subscribed to.
  bool _entitledTo(_ClientContext ctx, Envelope envelope) =>
      ctx.isFederated || ctx.subscribed.contains(envelope.recipientPubKey);

  /// Start of the `since` scan window. A real millisecond timestamp older than
  /// [limits.gossipMaxScanWindow] is pulled forward to the window edge instead
  /// of being mistaken for a value to clamp; a negative cursor starts at 0.
  static int scanWindowStart(int since, int now) {
    if (since < 0) return 0;
    if (now - since > limits.gossipMaxScanWindow) {
      return now - limits.gossipMaxScanWindow;
    }
    return since;
  }

  void _fanOut(
    Envelope envelope,
    int hops, {
    _ClientContext? except,
  }) {    for (final ctx in _connections.toList(growable: false)) {
      if (ctx.closed || ctx == except) continue;
      if (ctx.isFederated) {
        if (hops >= limits.hostGossipMaxHops) continue;
        _send(
          ctx,
          EnvelopesMessage(
            envelopes: [envelope],
            done: false,
            hops: hops + 1,
          ),
        );
        _relayedTotal++;
      } else if (ctx.subscribed.contains(envelope.recipientPubKey)) {
        _send(
          ctx,
          EnvelopesMessage(envelopes: [envelope], done: false, hops: hops),
        );
        _relayedTotal++;
      }
    }
  }

  Future<void> _sendBackfill(_ClientContext ctx, int since) async {
    var cursor = since;
    for (var round = 0; round < limits.hostBackfillMaxRounds; round++) {
      final batch = db.envelopesForRecipients(
        ctx.subscribed.toList(growable: false),
        cursor,
        limit: limits.maxGossipItems,
      );
      if (batch.isEmpty) break;
      _backfillTotal += batch.length;
      _send(ctx, EnvelopesMessage(envelopes: batch, done: false));
      cursor = batch.last.timestamp + 1;
      if (batch.length < limits.maxGossipItems) break;
    }
    _send(
      ctx,
      const EnvelopesMessage(envelopes: [], done: true),
    );
  }

  Future<void> _prune() async {
    final now = DateTime.now().toUtc().millisecondsSinceEpoch;
    db.forgetStalePeers(now - config.trackerPeerTtlMs);
    db.forgetExpiredSubscriptions(now, config.retentionMs);
    final remembered = db.rememberedSubscriptions(now, config.retentionMs);
    await db.pruneOlderThan(now - config.retentionMs, key);
    await db.pruneRelayWindow(now, config.relayWindowMs, remembered, key);
    _enforceStorageCaps();
    _log(
      'prune: connections=${_connections.length} '
      'links=${_links.length} peers=${db.peerCount()} '
      'hosts=${db.federatedHosts().length} envelopes=${db.envelopeCount()}',
    );
  }

  void _federationSync() {
    final cursor = db.latestTimestamp() ?? 0;
    final network = _networkMessage();
    for (final ctx in _connections.toList(growable: false)) {
      if (ctx.closed || !ctx.isFederated) continue;
      try {
        ctx.ws.add(jsonEncode(WantMessage(since: cursor).toJson()));
        if (ctx.networkCapable) {
          ctx.ws.add(jsonEncode(network.toJson()));
        }
      } catch (_) {
        // Socket already gone; the read-loop cleanup handles it.
      }
    }
  }

  Future<void> _startPeerLink(
    HostEndpoint endpoint, {
    bool requirePublic = false,
  }) async {
    if (_links.containsKey(endpoint.addr)) return;
    if (requirePublic && !await _endpointIsPublic(endpoint.addr)) {
      return;
    }
    final link = _PeerLink(endpoint: endpoint, requirePublic: requirePublic);
    _links[endpoint.addr] = link;
    await _connectPeer(link);
  }

  /// Whether [addr] is a public ws/wss endpoint. Wire-supplied members must
  /// pass this before the relay dials them, so a compromised federated peer
  /// cannot turn the relay into an SSRF probe of its own LAN or loopback.
  Future<bool> _endpointIsPublic(String addr) async {
    if (config.allowPrivateFederation) return true;
    final uri = Uri.tryParse(addr);
    if (uri == null || (uri.scheme != 'ws' && uri.scheme != 'wss')) {
      return false;
    }
    if (uri.host.isEmpty || addr.length > limits.maxAddrLength) return false;
    final literal = InternetAddress.tryParse(uri.host);
    if (literal != null) return _isPublicAddress(literal);
    try {
      final addresses = await InternetAddress.lookup(uri.host).timeout(
        const Duration(seconds: 5),
      );
      return addresses.isNotEmpty && addresses.every(_isPublicAddress);
    } catch (_) {
      return false;
    }
  }

  Future<void> _connectPeer(_PeerLink link) async {
    if (link.closed) return;
    if (link.requirePublic && !await _endpointIsPublic(link.endpoint.addr)) {
      return;
    }
    try {
      final ws = await WebSocket.connect(
        link.endpoint.addr,
      ).timeout(config.peerConnectTimeout);
      link.ws = ws;
      link.attempt = 0;
      final ctx = _ClientContext(ws: ws)
        ..peerLink = link
        ..isFederated = true;
      ws.add(
        jsonEncode(
          HelloMessage(
            myPeerId: await key.hexPub,
            capabilities: const ['dtm-host', 'dtm-net'],
            announce: _selfEndpoint?.addr,
          ).toJson(),
        ),
      );
      await _handleSocket(ws, ctx: ctx);
    } catch (_) {
      // Unreachable or mid-connect drop: back off and retry.
    }
    if (!link.closed) {
      _scheduleReconnect(link);
    }
  }

  /// The host's reachable WebSocket endpoint this process answers on.
  String _effectiveAnnounce() {
    final configured = config.announceUrl;
    if (configured != null && configured.isNotEmpty) return configured;
    final listen = config.listenAddress;
    final host = listen.isEmpty || listen == '0.0.0.0' || listen == '::'
        ? '127.0.0.1'
        : listen;
    return 'ws://$host:$boundPort/ws';
  }

  /// Full network view of this host: itself + operator seeds + members the
  /// network introduced. Addr-keyed, bounded by `maxFederatedHosts`.
  List<HostEndpoint> _networkMembers() {
    final map = <String, HostEndpoint>{};
    final self = _selfEndpoint;
    if (self != null) map[self.addr] = self;
    for (final endpoint in config.federatedPeers) {
      map.putIfAbsent(endpoint.addr, () => endpoint);
    }
    for (final endpoint in db.federatedHosts()) {
      map.putIfAbsent(endpoint.addr, () => endpoint);
    }
    return map.values.take(limits.maxFederatedHosts).toList(growable: false);
  }

  NetworkMessage _networkMessage() =>
      NetworkMessage(hosts: _networkMembers());

  /// Adds a peer-introduced host to the network: persist it and open an
  /// outbound link (full mesh — direction does not matter to the relay).
  void _adoptNetworkMember(HostEndpoint endpoint) {
    final self = _selfEndpoint;
    if (self != null && endpoint.addr == self.addr) return;
    // Persist/dial only after a public-address check performed by
    // `_startPeerLink`; private targets would be an SSRF primitive. Keep the
    // adoption optimistic for the operator's own private LAN only when that
    // was explicitly enabled.
    db.rememberFederatedHost(
      endpoint,
      DateTime.now().toUtc().millisecondsSinceEpoch,
    );
    if (_links.containsKey(endpoint.addr)) return;
    unawaited(_startPeerLink(endpoint, requirePublic: true));
  }

  void _scheduleReconnect(_PeerLink link) {
    if (link.closed) return;
    link.attempt++;
    final delay = _backoff(link.attempt);
    link.backoff?.cancel();
    link.backoff = Timer(
      delay,
      () => unawaited(_connectPeer(link)),
    );
  }

  Duration _backoff(int attempt) {
    final base = config.peerReconnectBase.inMilliseconds;
    final exp = base * (1 << (attempt > 6 ? 6 : attempt));
    return Duration(milliseconds: exp < 1 ? 1 : exp);
  }

  void _send(_ClientContext ctx, GossipMessage message) {
    if (ctx.closed) return;
    try {
      ctx.ws.add(jsonEncode(message.toJson()));
    } catch (_) {
      // Socket already closed; cleanup owns it.
    }
  }

  /// Devices subscribed to this host right now, newest subscription first and
  /// capped at [limits.maxPresenceKeys]. Federated host links carry no
  /// subscriptions and are skipped, so a host never shows up as a peer.
  List<String> _presenceKeys() {
    final entries = <MapEntry<String, int>>[];
    final seen = <String>{};
    for (final ctx in _connections) {
      if (ctx.closed || ctx.isFederated) continue;
      for (final key in ctx.subscribed) {
        if (!seen.add(key)) continue;
        entries.add(MapEntry(key, ctx.subscribedAt[key] ?? 0));
      }
    }
    entries.sort((a, b) => b.value.compareTo(a.value));
    return entries
        .take(limits.maxPresenceKeys)
        .map((e) => e.key)
        .toList(growable: false);
  }

  PresenceMessage _presenceMessage() => PresenceMessage(
    online: _presenceKeys(),
    at: DateTime.now().toUtc().millisecondsSinceEpoch,
  );

  void _sendPresenceTo(_ClientContext ctx) {
    if (ctx.closed || ctx.isFederated) return;
    _send(ctx, _presenceMessage());
  }

  /// Coalesces churn (a device reconnecting, several subscribing at once)
  /// into one feed, and skips a feed identical to the one already sent.
  void _schedulePresence() {
    _presenceTimer?.cancel();
    _presenceTimer = Timer(
      const Duration(milliseconds: 400),
      _broadcastPresence,
    );
  }

  void _broadcastPresence() {
    final message = _presenceMessage();
    final fingerprint = message.online.join(',');
    if (fingerprint == _lastPresence) return;
    _lastPresence = fingerprint;
    for (final ctx in _connections.toList(growable: false)) {
      if (ctx.closed || ctx.isFederated) continue;
      if (!ctx.capabilities.contains(dtmPresence)) continue;
      _send(ctx, message);
    }
  }

  /// Runs a background future; a failure there must never take the host down
  /// (a stray prune error would otherwise kill the whole relay silently).
  static Future<void> _guarded(
    Future<void> Function() task, [
    String? label,
  ]) async {
    try {
      await task();
    } catch (e) {
      _log('${label ?? 'task'} failed: $e');
    }
  }

  /// Operators read the relay through its log, not a debugger.
  static void _log(String message) {
    stderr.writeln('[host] $message');
  }
}

/// A connected peer-host or device, plus the protocol state the host keeps
/// only for live delivery (never for retention).
class _ClientContext {
  final WebSocket ws;
  final InternetAddress? remoteAddress;
  String? peerId;
  String? identity;
  bool isFederated = false;
  bool closed = false;
  _PeerLink? peerLink;
  final Set<String> subscribed = {};

  /// When each subscribed key was last announced (ms UTC), used to order the
  /// presence feed so truncation drops the stalest devices.
  final Map<String, int> subscribedAt = {};

  /// Capabilities the peer asserted in its HELLO (or our WELCOME back).
  final Set<String> capabilities = {};

  bool get networkCapable => capabilities.contains('dtm-net');

  _ClientContext({required this.ws, this.remoteAddress});
}

/// Cached DNS answer for one announced endpoint host.
class _AddrCheck {
  final List<InternetAddress> addresses;
  final DateTime expires;

  const _AddrCheck({required this.addresses, required this.expires});
}

class _PeerLink {
  final HostEndpoint endpoint;
  final bool requirePublic;
  String? identity;
  WebSocket? ws;
  int attempt = 0;
  bool closed = false;
  Timer? backoff;

  _PeerLink({required this.endpoint, this.requirePublic = false});

  void wsGone() {
    ws = null;
  }
}