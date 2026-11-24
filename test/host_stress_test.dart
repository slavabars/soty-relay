import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:dtm_app/core/crypto/envelope_crypto.dart';
import 'package:dtm_app/core/crypto/keypair.dart';
import 'package:dtm_app/core/sync/gossip_message.dart';
import 'package:dtm_host/host_config.dart';
import 'package:dtm_host/host_db.dart';
import 'package:dtm_host/host_key.dart';
import 'package:dtm_host/host_server.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('host survives 30 messages and live fan-out', () async {
    final config = const HostConfig(listenAddress: '127.0.0.1', port: 0);
    final db = HostDatabase.openInMemory();
    final key = await HostKey.generate();
    final server = HostServer(db: db, key: key, config: config);
    await server.start();
    addTearDown(() => server.stop());

    var uncaught = 0;

    await runZonedGuarded(
      () async {
        final sub = await WebSocket.connect(
          'ws://127.0.0.1:${server.boundPort}/ws',
        );
        sub.add(jsonEncode(const HelloMessage(myPeerId: 'sub').toJson()));
        await Future<void>.delayed(const Duration(milliseconds: 30));
        final recipient = await (await DtmKeyPair.generate())
            .x25519PublicKeyHex;
        sub.add(
          jsonEncode(SubscribeMessage(since: 0, keys: [recipient]).toJson()),
        );
        await Future<void>.delayed(const Duration(milliseconds: 30));

        final pub = await WebSocket.connect(
          'ws://127.0.0.1:${server.boundPort}/ws',
        );
        pub.add(jsonEncode(const HelloMessage(myPeerId: 'pub').toJson()));

        final sender = await DtmKeyPair.generate();
        for (var i = 0; i < 30; i++) {
          final env = await createEnvelopeForPubKey(
            sender: sender,
            recipientX25519PubKeyHex: recipient,
            plaintext: 'msg $i',
          );
          pub.add(jsonEncode(PublishMessage(envelope: env).toJson()));
        }
        await pub.close();
        await Future<void>.delayed(const Duration(seconds: 1));
        await sub.close();
        await Future<void>.delayed(const Duration(milliseconds: 300));
      },
      (_, _) => uncaught++,
    );

    expect(uncaught, 0);
    expect(db.idsSince(0), hasLength(30));
    await server.stop();
    db.dispose();
  });
}