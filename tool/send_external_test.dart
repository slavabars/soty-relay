import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:dtm_app/core/crypto/envelope_crypto.dart';
import 'package:dtm_app/core/crypto/keypair.dart';
import 'package:dtm_app/core/sync/gossip_message.dart';

Future<void> main(List<String> args) async {
  final recipient = args.isNotEmpty
      ? args[0]
      : '0000000000000000000000000000000000000000000000000000000000000000';
  final text = args.length > 1 ? args[1] : 'bridge test';
  final url = args.length > 2 ? args[2] : 'wss://soty.su/soty-ws';
  final sender = await DtmKeyPair.generate();
  final envelope = await createEnvelopeForPubKey(
    sender: sender,
    recipientX25519PubKeyHex: recipient,
    plaintext: text,
  );
  final ws = await WebSocket.connect(url);
  final ack = Completer<bool>();
  final welcome = Completer<void>();
  final sub = ws.listen((frame) {
    final raw = frame is String ? frame : utf8.decode(frame as List<int>);
    final decoded = jsonDecode(raw);
    if (decoded is! Map<String, dynamic>) return;
    final msg = GossipMessage.fromJson(decoded);
    if (msg is WelcomeMessage && !welcome.isCompleted) welcome.complete();
    if (msg is PublishedMessage && msg.id == envelope.id && !ack.isCompleted) {
      ack.complete(msg.accepted);
    }
  }, onError: (Object e) {
    if (!ack.isCompleted) ack.completeError(e);
  });
  ws.add(jsonEncode(HelloMessage(
    myPeerId: await sender.ed25519PublicKeyHex,
  ).toJson()));
  await welcome.future.timeout(const Duration(seconds: 8));
  ws.add(jsonEncode(PublishMessage(envelope: envelope).toJson()));
  final accepted = await ack.future.timeout(const Duration(seconds: 8));
  stdout.writeln('id=${envelope.id} accepted=$accepted recipient=$recipient');
  await sub.cancel();
  await ws.close();
}
