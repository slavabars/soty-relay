import 'dart:async';
import 'dart:io';

import 'package:dtm_app/core/host/host_link.dart' show HostEndpoint, HostLink;
import 'package:dtm_host/host_config.dart';
import 'package:dtm_host/host_db.dart';
import 'package:dtm_host/host_key.dart';
import 'package:dtm_host/host_server.dart';

const String _usage = '''
Usage: dart run dtm_host [options]

Relay host for the Soty messenger. Stores only opaque, encrypted envelopes;
joins a relay-host network (--seed/--peer) that syncs so clients reach the
whole network through any single member; serves live relay + backfill on
ws://<listen>:<port>/ws.

Options:
  --db <path>        sqlite database file (default: host.db)
  --listen <addr>    bind address (default: 0.0.0.0)
  --port <port>      listen port (default: 3000)
  --announce <url>   public ws://.../<ws> URL written on the banner and given
                     to the network as this host's address
                     (default: ws://<listen>:<port>/ws)
  --peer <spec>      network member to federate with (repeatable). spec =
                     "<ws url>" or "<ws url>|pkHex" to pin its Ed25519
                     identity. Members the network introduces are kept too.
  --seed <spec>      alias for --peer: the address of an already-running
                     member to join the network through.
  --help             show this message
''';

StreamSubscription<ProcessSignal>? _shutdown;

Future<void> main(List<String> args) async {
  final cli = _parseArgs(args);
  if (cli == null) {
    stderr.writeln(_usage);
    exitCode = 64;
    return;
  }
  final db = await HostDatabase.open(cli.dbPath);
  final key = await _loadOrCreateKey(db);
  final peers = <HostEndpoint>[
    for (final spec in cli.peers) ..._parsePeerSpec(spec),
  ];
  final server = HostServer(
    db: db,
    key: key,
    config: HostConfig(
      listenAddress: cli.listen,
      port: cli.port,
      announceUrl: cli.announce,
      federatedPeers: peers,
    ),
  );
  final pub = await key.hexPub;
  final announce = cli.announce ?? 'ws://${cli.listen}:${cli.port}/ws';
  stdout.writeln('Soty relay host · ed25519 $pub');
  stdout.writeln('listen    ${announce.replaceAll('ws:', 'http:')} '
      '(WebSocket endpoint /ws)');
  stdout.writeln('peers     ${peers.length} (network grows as members join)');
  stdout.writeln('share this invite with your clients:');
  stdout.writeln(HostLink.encode(HostEndpoint(addr: announce, edPubKey: pub)));
  stdout.writeln('ctrl-c to stop');
  await server.start();
  final completer = Completer<void>();
  _shutdown = ProcessSignal.sigint.watch().listen((_) {
    if (!completer.isCompleted) completer.complete();
  });
  await completer.future;
  final shutdown = _shutdown;
  if (shutdown != null) await shutdown.cancel();
  await server.stop();
  db.dispose();
}

Future<HostKey> _loadOrCreateKey(HostDatabase db) async {
  const seedKey = 'ed_seed';
  final existing = db.readState(seedKey);
  if (existing != null) {
    return HostKey.fromSeedHex(existing);
  }
  final key = await HostKey.generate();
  db.writeState(seedKey, await key.hexSeed);
  return key;
}

List<HostEndpoint> _parsePeerSpec(String spec) {
  final sep = spec.lastIndexOf('|');
  if (sep == -1) {
    return [HostEndpoint(addr: spec)];
  }
  final addr = spec.substring(0, sep);
  final pk = spec.substring(sep + 1);
  return [HostEndpoint(addr: addr, edPubKey: pk)];
}

class _Args {
  final String dbPath;
  final String listen;
  final int port;
  final String? announce;
  final List<String> peers;

  const _Args({
    required this.dbPath,
    required this.listen,
    required this.port,
    required this.announce,
    required this.peers,
  });
}

_Args? _parseArgs(List<String> args) {
  var dbPath = 'host.db';
  var listen = '0.0.0.0';
  var port = 3000;
  String? announce;
  final peers = <String>[];
  var i = 0;
  while (i < args.length) {
    final flag = args[i];
    String? value;
    if (flag == '--help' || flag == '-h') return null;
    if (_hasValue(args, i)) {
      value = args[i + 1];
      i += 2;
    } else {
      i++;
    }
    switch (flag) {
      case '--db':
        dbPath = value!;
      case '--listen':
        listen = value!;
      case '--port':
        final parsed = int.tryParse(value!);
        if (parsed == null) return null;
        port = parsed;
      case '--announce':
        announce = value;
      case '--peer':
        peers.add(value!);
      case '--seed':
        peers.add(value!);
      default:
        return null;
    }
  }
  return _Args(
    dbPath: dbPath,
    listen: listen,
    port: port,
    announce: announce,
    peers: peers,
  );
}

bool _hasValue(List<String> args, int i) => i + 1 < args.length;