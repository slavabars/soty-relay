import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:dtm_app/core/crypto/handshake.dart';
import 'package:dtm_app/core/sync/gossip_message.dart';

/// Verifies that a relay signs WELCOME over the client nonce with the key it
/// advertises (and, optionally, the pinned key). Read-only: it sends one HELLO
/// and never subscribes or requests an envelope.
///
///   dart run tool/verify_welcome.dart --url=wss://soty.su/soty-ws \
///     --pin=fad55cc7...
///
/// Exit codes: 0 PASS, 1 FAIL.
Future<void> main(List<String> args) async {
  final opts = <String, String>{};
  for (final arg in args) {
    if (!arg.startsWith('--')) continue;
    final i = arg.indexOf('=');
    if (i < 0) continue;
    opts[arg.substring(2, i)] = arg.substring(i + 1);
  }
  final url = opts['url'];
  if (url == null || url.isEmpty) {
    stderr.writeln('usage: verify_welcome.dart --url=ws://host:port/ws '
        '[--pin=hex]');
    exit(64);
  }
  final pin = opts['pin'];
  final nonce = randomHandshakeNonce();
  final ws = await WebSocket.connect(url).timeout(const Duration(seconds: 8));
  final welcome = Completer<WelcomeMessage>();
  final sub = ws.listen((frame) {
    final raw = frame is String ? frame : utf8.decode(frame as List<int>);
    final decoded = jsonDecode(raw);
    if (decoded is! Map<String, dynamic>) return;
    final message = GossipMessage.fromJson(decoded);
    if (message is WelcomeMessage && !welcome.isCompleted) {
      welcome.complete(message);
    }
  }, onError: (_) {});

  try {
    ws.add(jsonEncode(HelloMessage(myPeerId: 'verify-welcome', nonce: nonce)
        .toJson()));
    final msg = await welcome.future.timeout(const Duration(seconds: 8));
    final identity = msg.identity;
    final proof = msg.proof;
    if (identity == null || proof == null) {
      stdout.writeln('VERDICT FAIL unsigned WELCOME identity=$identity');
      exit(1);
    }
    if (pin != null && pin.isNotEmpty && pin != identity) {
      stdout.writeln('VERDICT FAIL pinned=$pin identity=$identity');
      exit(1);
    }
    final ok = await verifyHandshakeData(
      publicKeyHex: identity,
      data: welcomeProofData(
        nonce: nonce,
        serverTime: msg.serverTime,
        identity: identity,
        capabilities: msg.capabilities,
      ),
      signatureHex: proof,
    );
    stdout.writeln('VERDICT ${ok ? 'PASS' : 'FAIL'} identity=$identity');
    exit(ok ? 0 : 1);
  } on TimeoutException {
    stdout.writeln('VERDICT FAIL no WELCOME');
    exit(1);
  } finally {
    await sub.cancel();
    await ws.close();
  }
}
