import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:dtm_app/core/crypto/envelope_crypto.dart';
import 'package:dtm_app/core/crypto/keypair.dart';
import 'package:dtm_app/core/sync/gossip_message.dart';
import 'package:dtm_app/models/envelope.dart';
import 'package:dtm_host/host_config.dart';
import 'package:dtm_host/host_db.dart';
import 'package:dtm_host/host_key.dart';
import 'package:dtm_host/host_server.dart';

/// HostServer backed by a fresh in-memory db on an ephemeral loopback port.
Future<StartedServer> startServer({HostConfig? config}) async {
  final resolved = config ??
      const HostConfig(
        listenAddress: '127.0.0.1',
        port: 0,
        allowInboundFederation: true,
        allowPrivateFederation: true,
      );
  final db = HostDatabase.openInMemory();
  final key = await HostKey.generate();
  final server = HostServer(db: db, key: key, config: resolved);
  await server.start();
  return StartedServer(db: db, key: key, server: server, config: resolved);
}

Future<String> recipientKey() async =>
    (await DtmKeyPair.generate()).x25519PublicKeyHex;

Future<Envelope> envelopeFor(
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

Future<HostClient> connectHost(StartedServer server) async => HostClient(
  await WebSocket.connect(
    'ws://127.0.0.1:${server.server.boundPort}/ws',
  ),
);

class StartedServer {
  final HostDatabase db;
  final HostKey key;
  final HostServer server;
  final HostConfig config;

  StartedServer({
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

class HostClient {
  final WebSocket ws;
  final List<GossipMessage> received = [];

  HostClient(this.ws) {
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

  List<EnvelopesMessage> envelopeFrames() =>
      received.whereType<EnvelopesMessage>().toList(growable: false);

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