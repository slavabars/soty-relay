import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:dtm_app/core/sync/gossip_message.dart';
import 'package:dtm_app/models/envelope.dart';

/// Security probe: connect to a relay as an ordinary client, claim a known
/// host Ed25519 key (the seed's public key) and ask for a stored envelope id.
/// A relay that grants federation by key alone returns the envelope.
Future<void> main(List<String> args) async {
  final url = args.isNotEmpty ? args[0] : 'ws://192.168.1.1:3100/ws';
  final claimed = args.length > 1
      ? args[1]
      : 'fad55cc762eda3f6cbc9c6522030ce8ec29e87143c9c78f452038d24143a4e82';
  final envelopeId = args.length > 2 ? args[2] : '';
  final ws = await WebSocket.connect(url);
  final welcome = Completer<void>();
  final envelopes = Completer<List<Envelope>>();
  final sub = ws.listen((frame) {
    final raw = frame is String ? frame : utf8.decode(frame as List<int>);
    final decoded = jsonDecode(raw);
    if (decoded is! Map<String, dynamic>) return;
    final msg = GossipMessage.fromJson(decoded);
    if (msg is WelcomeMessage && !welcome.isCompleted) welcome.complete();
    if (msg is EnvelopesMessage && !envelopes.isCompleted) {
      envelopes.complete(msg.envelopes);
    }
  });
  ws.add(jsonEncode(HelloMessage(
    myPeerId: claimed,
    capabilities: const ['dtm-host', 'dtm-net'],
    announce: 'wss://soty.su/soty-ws',
  ).toJson()));
  await welcome.future.timeout(const Duration(seconds: 8));
  ws.add(jsonEncode(GetMessage(ids: [envelopeId]).toJson()));
  final got = await envelopes.future.timeout(const Duration(seconds: 8));
  stdout.writeln('claimed=$claimed get=$envelopeId returned=${got.length}');
  for (final e in got) {
    stdout.writeln('id=${e.id} from=${e.senderPubKey.substring(0, 8)} '
        'to=${e.recipientPubKey.substring(0, 8)}');
  }
  await sub.cancel();
  await ws.close();
}
