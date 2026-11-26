// Generates relay-owrt/internal/wire/testdata/vector.json with the app's
// own envelope implementation. Run from host/ with `dart run tool/gen_wire_vector.dart`
// after any wire-format change; the Go wire tests must accept the result.
import 'dart:convert';
import 'dart:io';

import 'package:cryptography/cryptography.dart';
import 'package:dtm_app/core/crypto/hex.dart';
import 'package:dtm_app/models/envelope.dart';

Future<void> main() async {
  final seed = List<int>.generate(32, (i) => i + 1);
  final pair = await Ed25519().newKeyPairFromSeed(seed);
  final sender = bytesToHex((await pair.extractPublicKey()).bytes);
  final recipient = 'aa' * 32;
  final ephemeral = 'bb' * 32;
  final ciphertext = base64Encode(List<int>.generate(64, (i) => i));
  final timestamp = 1700000000000;
  final chain = 'cc' * 32;
  final id = await Envelope.computeId(
    sender,
    recipient,
    ciphertext,
    timestamp,
    chainLink: chain,
  );
  final unsigned = Envelope(
    id: id,
    senderPubKey: sender,
    recipientPubKey: recipient,
    timestamp: timestamp,
    ciphertext: ciphertext,
    ephemeralPubKey: ephemeral,
    signature: '',
    chainLink: chain,
  );
  final sig = await Ed25519().sign(unsigned.signedData, keyPair: pair);
  final envelope = Envelope(
    id: id,
    senderPubKey: sender,
    recipientPubKey: recipient,
    timestamp: timestamp,
    ciphertext: ciphertext,
    ephemeralPubKey: ephemeral,
    signature: bytesToHex(sig.bytes),
    chainLink: chain,
  );
  stdout.write(jsonEncode({
    'seed': bytesToHex(seed),
    'envelope': envelope.toJson(),
  }));
}
