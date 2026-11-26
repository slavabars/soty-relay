import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:dtm_app/core/crypto/keypair.dart';
import 'package:dtm_app/core/sync/gossip_message.dart';

/// Read-only inbound-federation probe.
///
/// Connects as a client that claims `--claimed` (for example a public seed
/// Ed25519 key) or a fresh key, sends HELLO with host/net capabilities and an
/// announce, asks for the id list with WANT, then tries to GET a few of those
/// ids without subscribing to any key. A relay that grants federation by key
/// alone, or open federation by address alone, returns envelopes and the
/// probe prints FAIL. It never prints envelope contents.
///
///   dart run tool/probe_relay_audit.dart \
///     --url=ws://192.168.1.1:3100/ws \
///     --claimed=fad55cc7... \
///     --announce=wss://soty.su/soty-ws
///
/// Exit codes: 0 PASS, 1 FAIL, 2 INCONCLUSIVE.
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
    stderr.writeln('usage: probe_relay_audit.dart --url=ws://host:port/ws '
        '[--claimed=hex] [--announce=ws://...]');
    exit(64);
  }
  final timeout = Duration(seconds: int.tryParse(opts['timeout'] ?? '') ?? 8);
  final announce = opts['announce'] ?? 'ws://127.0.0.1:9/ws';
  final claimed = opts['claimed'];
  final knownId = opts['id'];
  String myPeerId;
  if (claimed != null && claimed.isNotEmpty) {
    myPeerId = claimed;
  } else {
    final keyPair = await DtmKeyPair.generate();
    myPeerId = await keyPair.ed25519PublicKeyHex;
  }

  final ws = await WebSocket.connect(url).timeout(timeout);
  final frames = <GossipMessage>[];
  var parseErrors = 0;
  final sub = ws.listen((frame) {
    final raw = frame is String ? frame : utf8.decode(frame as List<int>);
    final decoded = jsonDecode(raw);
    if (decoded is Map<String, dynamic>) {
      try {
        frames.add(GossipMessage.fromJson(decoded));
      } catch (_) {
        parseErrors++;
      }
    }
  }, onError: (_) {});

  Future<T> waitFor<T extends GossipMessage>(bool Function(T) test) async {
    final deadline = DateTime.now().add(timeout);
    while (DateTime.now().isBefore(deadline)) {
      for (final message in frames) {
        if (message is T && test(message)) return message;
      }
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
    throw TimeoutException('no matching $T');
  }

  try {
    ws.add(jsonEncode(HelloMessage(
      myPeerId: myPeerId,
      capabilities: const ['dtm-host', 'dtm-net'],
      announce: announce,
    ).toJson()));
    await waitFor<WelcomeMessage>((_) => true);

    final ids = <String>[];
    if (knownId != null && knownId.isNotEmpty) {
      ids.add(knownId);
    } else {
      ws.add(jsonEncode(const WantMessage(since: 0).toJson()));
      final have = await waitFor<HaveMessage>((_) => true);
      ids.addAll(have.ids.take(8));
    }
    if (ids.isEmpty) {
      stdout.writeln(
        'VERDICT INCONCLUSIVE ids=0 returned=0 parseerrors=$parseErrors',
      );
      await sub.cancel();
      await ws.close();
      exit(2);
    }

    ws.add(jsonEncode(GetMessage(ids: ids).toJson()));
    final answer = await waitFor<EnvelopesMessage>((m) => m.done);
    stdout.writeln(
      'VERDICT ${answer.envelopes.isEmpty ? 'PASS' : 'FAIL'} '
      'ids=${ids.length} returned=${answer.envelopes.length} '
      'parseerrors=$parseErrors',
    );
    await sub.cancel();
    await ws.close();
    exit(answer.envelopes.isEmpty ? 0 : 1);
  } catch (e) {
    stdout.writeln('VERDICT INCONCLUSIVE error=${e.runtimeType} '
        'parseerrors=$parseErrors');
    await sub.cancel();
    await ws.close();
    exit(2);
  }
}
