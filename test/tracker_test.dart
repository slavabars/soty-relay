import 'package:dtm_app/core/crypto/keypair.dart';
import 'package:dtm_app/core/host/host_link.dart';
import 'package:dtm_app/core/sync/gossip_message.dart';
import 'package:dtm_host/host_config.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support.dart';

void main() {
  test('WELCOME advertises the tracker capability', () async {
    final server = await startServer();
    final client = await connectHost(server);

    await client.send(const HelloMessage(myPeerId: 'dev'));
    final welcome = await client.waitFor<WelcomeMessage>();

    expect(welcome.capabilities, contains('dtm-tracker'));

    await client.close();
    await server.dispose();
  });

  test('PEER_LIST hands out registered peers with their bindings', () async {
    final server = await startServer();
    final alice = await connectHost(server);
    await alice.send(
      const HelloMessage(
        myPeerId: 'dev-a',
        myAddrs: ['/ip4/10.0.2.2/tcp/5011'],
      ),
    );
    await alice.waitFor<WelcomeMessage>();
    final aliceKey = await (await DtmKeyPair.generate()).x25519PublicKeyHex;
    await alice.send(
      SubscribeMessage(since: 0, keys: [aliceKey]),
    );

    final bob = await connectHost(server);
    await bob.send(const HelloMessage(myPeerId: 'dev-b'));
    await bob.waitFor<WelcomeMessage>();
    await bob.send(const PeerListRequestMessage());
    final list = await bob.waitFor<PeerListMessage>();

    final aliceRef = list.peers.singleWhere((p) => p.peerId == 'dev-a');
    expect(aliceRef.xPubKey, aliceKey);
    expect(aliceRef.addrs, ['/ip4/10.0.2.2/tcp/5011']);

    await alice.close();
    await bob.close();
    await server.dispose();
  });

  test('PEER_LIST excludes the asker itself', () async {
    final server = await startServer();
    final asker = await connectHost(server);
    await asker.send(
      const HelloMessage(
        myPeerId: 'dev-ask',
        myAddrs: ['/ip4/10.0.2.2/tcp/5011'],
      ),
    );
    await asker.waitFor<WelcomeMessage>();

    await asker.send(const PeerListRequestMessage());
    final list = await asker.waitFor<PeerListMessage>();
    expect(list.peers.map((p) => p.peerId), isNot(contains('dev-ask')));

    await asker.close();
    await server.dispose();
  });

  test('PEER_LIST also advertises the operator federated hosts', () async {
    final server = await startServer(
      config: const HostConfig(
        listenAddress: '127.0.0.1',
        port: 0,
        federatedPeers: [
          HostEndpoint(addr: 'ws://host-b.example/ws'),
          HostEndpoint(addr: 'ws://host-c.example/ws'),
        ],
      ),
    );
    final client = await connectHost(server);
    await client.send(const HelloMessage(myPeerId: 'dev'));
    await client.waitFor<WelcomeMessage>();

    await client.send(const PeerListRequestMessage());
    final list = await client.waitFor<PeerListMessage>();
    expect(
      list.hosts.map((h) => h.addr),
      ['ws://host-b.example/ws', 'ws://host-c.example/ws'],
    );

    await client.close();
    await server.dispose();
  });

  test('a malformed myAddrs in HELLO drops the connection', () async {
    final server = await startServer();
    final client = await connectHost(server);
    await client.send(
      const HelloMessage(
        myPeerId: 'evil',
        myAddrs: ['not-a-multiaddr'],
      ),
    );
    await client.waitClosed();

    await server.dispose();
  });
}

extension on HostClient {
  Future<T> waitFor<T>({
    Duration timeout = const Duration(seconds: 4),
  }) async {
    final deadline = DateTime.now().add(timeout);
    while (true) {
      for (final message in received) {
        if (message is T) return message as T;
      }
      if (DateTime.now().isAfter(deadline)) {
        throw Exception('no $T frame within $timeout');
      }
      await Future<void>.delayed(const Duration(milliseconds: 15));
    }
  }
}