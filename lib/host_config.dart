import 'package:dtm_app/core/host/host_link.dart' show HostEndpoint;
import 'package:dtm_app/core/security_limits.dart'
    show hostBackfillMaxRounds, hostGossipMaxHops, hostRateLimitLivePerWindow,
        hostRateLimitPerWindow, hostRateWindowSeconds, hostRetentionMs,
        hostRelayWindowMs, hostTrackerPeerTtlMs, maxHostConnections,
        maxRateLimiterKeys, maxTrackerPeers;

/// Operator knobs for a relay host. [relayWindowMs]/[retentionMs] mirror
/// [hostRelayWindowMs]/[hostRetentionMs]; every other knob has a sane default
/// so a stock binary runs with `dtm_host --db /path/to/host.db`.
class HostConfig {
  final String listenAddress;
  final int port;

  /// The host's own reachable WebSocket endpoint (`ws://host:port/ws`).
  /// Null computes it from [listenAddress]/the bound port; set it via
  /// `--announce` when the host sits behind NAT/a reverse proxy.
  final String? announceUrl;

  /// Peer hosts to join (explicit seed list; the network keeps itself
  /// discovered from here on, see `NetworkMessage`).
  final List<HostEndpoint> federatedPeers;

  /// Relay window for envelopes whose recipient is not subscribed here.
  final int relayWindowMs;

  /// Age-based retention for subscribed recipients (and the prune cutoff).
  final int retentionMs;

  /// Federation gossip hop ceiling, from [hostGossipMaxHops].
  final int maxGossipHops;

  /// Ceiling on backfill rounds per SUBSCRIBE, from [hostBackfillMaxRounds].
  final int maxBackfillRounds;

  /// Anti-spam budget per sender per window; the bucket table is capped at
  /// [rateLimiterMaxKeys]. Defaults mirror the device's security limits.
  final int rateLimitPerWindow;

  /// Separate, larger budget for live-only slices: they are forwarded and
  /// never stored, and a normal photo is dozens of frames.
  final int liveRateLimitPerWindow;
  final int rateWindowSeconds;
  final int rateLimiterMaxKeys;

  /// Tracker knobs: how many random peers one PEER_LIST hands out, and how
  /// long a peer stays remembered without refreshing itself.
  final int trackerSampleSize;
  final int trackerPeerTtlMs;

  /// Ceiling on simultaneous WebSocket connections, from
  /// [hostConfigMaxConnections] by default; per-connection cost is a socket
  /// plus its subscription keys.
  final int maxConnections;

  final Duration pruneInterval;
  final Duration federationSyncInterval;
  final Duration peerConnectTimeout;
  final Duration peerReconnectBase;

  const HostConfig({
    this.listenAddress = '0.0.0.0',
    this.port = 3000,
    this.announceUrl,
    this.federatedPeers = const [],
    this.relayWindowMs = hostRelayWindowMs,
    this.retentionMs = hostRetentionMs,
    this.maxGossipHops = hostGossipMaxHops,
    this.maxBackfillRounds = hostBackfillMaxRounds,
    this.rateLimitPerWindow = hostRateLimitPerWindow,
    this.liveRateLimitPerWindow = hostRateLimitLivePerWindow,
    this.rateWindowSeconds = hostRateWindowSeconds,
    this.rateLimiterMaxKeys = maxRateLimiterKeys,
    this.trackerSampleSize = maxTrackerPeers,
    this.trackerPeerTtlMs = hostTrackerPeerTtlMs,
    this.maxConnections = maxHostConnections,
    this.pruneInterval = const Duration(hours: 6),
    this.federationSyncInterval = const Duration(minutes: 10),
    this.peerConnectTimeout = const Duration(seconds: 10),
    this.peerReconnectBase = const Duration(seconds: 2),
  });
}