// Package limits mirrors the host half of
// app-src/lib/core/security_limits.dart. Every number here is a copy, not an
// independent choice: when the Dart file changes, this file changes in the
// same commit. The router build is memory-constrained, so the store caps
// ([MaxStoredEnvelopes], [MaxStoredBytes]) are the one deliberate addition;
// they live in security_limits.dart as hostMaxStoredEnvelopes/Bytes.
package limits

import "time"

const (
	// MaxFrameBytes is the largest WebSocket text frame a relay accepts.
	MaxFrameBytes = 256 * 1024

	// MaxGossipItems bounds HAVE/GET ids and ENVELOPES per frame.
	MaxGossipItems = 256

	// GossipMaxScanWindowMs clamps a SUBSCRIBE `since` cursor.
	GossipMaxScanWindowMs int64 = 30 * 24 * 60 * 60 * 1000

	// MaxCapabilities bounds a HELLO/WELCOME capability list.
	MaxCapabilities = 16

	// MaxHostSubscriptionKeys bounds one SUBSCRIBE key list.
	MaxHostSubscriptionKeys = 16

	// HostRelayWindowMs is how long an unsubscribed recipient's envelope
	// is kept (relay cache).
	HostRelayWindowMs int64 = 24 * 60 * 60 * 1000

	// HostRetentionMs is the age-based retention for subscribed keys.
	HostRetentionMs int64 = 30 * 24 * 60 * 60 * 1000

	// HostGossipMaxHops is the federation re-relay ceiling.
	HostGossipMaxHops = 3

	// Rate-limiter defaults (window, stored budget, live budget, key cap).
	HostRateWindowSeconds      = 60
	HostRateLimitPerWindow     = 60
	HostRateLimitLivePerWindow = 1200
	MaxRateLimiterKeys         = 2048

	// HostBackfillMaxRounds bounds one SUBSCRIBE backfill answer.
	HostBackfillMaxRounds = 16

	// HostMaxSyncEnvelopes bounds one WANT answer.
	HostMaxSyncEnvelopes = 4096

	// Tracker and federation topology bounds.
	MaxTrackerPeers            = 64
	MaxTrackerHosts            = 32
	MaxFederatedHosts          = 32
	MaxPresenceKeys            = 64
	MaxKnownPeers              = 8192
	HostTrackerPeerTTLMs int64 = 24 * 60 * 60 * 1000

	// MaxHostConnections is the server-wide socket ceiling. The router
	// default is lower (see server.Config); this is the hard mirror ceiling.
	MaxHostConnections = 512

	// MaxHostSubscriptionRows is the persisted subscription-key ceiling.
	MaxHostSubscriptionRows = 100000

	// Wire bounds for peer addresses and ids.
	MaxPeerAddrsOnWire = 8
	MaxAddrLength      = 256
	MaxPeerIDLength    = 128

	// MaxReasonableTimestamp bounds a peer's lastSeen claim.
	MaxReasonableTimestamp int64 = 4102444800000

	// MaxFutureSkewMs is the envelope timestamp tolerance into the future.
	MaxFutureSkewMs int64 = 5 * 60 * 1000

	// Store caps for the RAM-first relay (security_limits.dart:
	// hostMaxStoredEnvelopes/hostMaxStoredBytes).
	MaxStoredEnvelopes = 20000
	MaxStoredBytes     = 32 * 1024 * 1024
)

// HostIdleTimeout is how long a socket may stay silent before it is dropped.
var HostIdleTimeout = 5 * time.Minute

// Capability strings exchanged in HELLO/WELCOME.
const (
	CapTracker  = "dtm-tracker"
	CapNet      = "dtm-net"
	CapLive     = "dtm-live"
	CapPresence = "dtm-presence"
	CapHost     = "dtm-host"
)
