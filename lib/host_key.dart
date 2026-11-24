import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:dtm_app/core/crypto/hex.dart' show bytesToHex, hexToBytes;

/// The relay host's own Ed25519 identity, used only to sign pruned-batch
/// Merkle roots and (optionally) to pin host-host links. It never touches
/// message payloads.
class HostKey {
  final SimpleKeyPair edKeyPair;

  const HostKey(this.edKeyPair);

  static Future<HostKey> generate() async {
    final pair = await Ed25519().newKeyPair();
    return HostKey(pair);
  }

  static Future<HostKey> fromSeedHex(String seedHex) async {
    final pair = await Ed25519().newKeyPairFromSeed(
      Uint8List.fromList(hexToBytes(seedHex)),
    );
    return HostKey(pair);
  }

  Future<String> get hexPub async =>
      (await edKeyPair.extractPublicKey()).bytes.map(
        (b) => b.toRadixString(16).padLeft(2, '0'),
      ).join();

  Future<String> get hexSeed async =>
      bytesToHex(await edKeyPair.extractPrivateKeyBytes());

  Future<String> sign(List<int> data) async {
    final sig = await Ed25519().sign(data, keyPair: edKeyPair);
    return bytesToHex(sig.bytes);
  }
}