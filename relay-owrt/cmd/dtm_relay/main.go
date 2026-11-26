// Command dtm_relay is the OpenWrt LAN relay for Soty: a static Go binary
// that speaks the dtm_host WebSocket protocol and stores only opaque
// encrypted envelopes.
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/slavabars/soty-relay-owrt/internal/identity"
	"github.com/slavabars/soty-relay-owrt/internal/server"
	"github.com/slavabars/soty-relay-owrt/internal/store"
	"github.com/slavabars/soty-relay-owrt/internal/wire"
)

const version = "0.1.0"

const usage = `Usage: dtm_relay [options]

LAN relay and tracker for Soty. Stores only opaque encrypted envelopes and
speaks the same ws protocol as dtm_host, so a device can use the router as a
relay when there is no internet. Federation is off unless enabled.

Options:
  --listen <addr>          bind address (default 0.0.0.0)
  --port <port>            listen port (default 3100)
  --announce <url>         public ws:// URL; default ws://<listen>:<port>/ws
  --identity <path>        Ed25519 seed file (default /etc/dtm-relay/identity)
  --storage <memory|disk>  memory (default) or append-only journal
  --path <dir>             journal directory for --storage disk
  --retention-days <n>     subscribed-recipient retention (default 30)
  --max-connections <n>    socket ceiling (default 128, hard cap 512)
  --federation             enable host federation (default off)
  --seed <url>[|<pk>]      federation seed, repeatable; pk pins the identity
  --version                print the version and exit
`

type seedFlag []string

func (s *seedFlag) String() string { return strings.Join(*s, ",") }

func (s *seedFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "dtm_relay:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg := server.DefaultConfig()
	var (
		listen       = flag.String("listen", cfg.Listen, "bind address")
		port         = flag.Int("port", cfg.Port, "listen port")
		announce     = flag.String("announce", "", "public ws URL")
		identityPath = flag.String("identity", "/etc/dtm-relay/identity",
			"Ed25519 seed file")
		storage       = flag.String("storage", "memory", "memory or disk")
		path          = flag.String("path", "/tmp/dtm-relay", "journal directory")
		retentionDays = flag.Int("retention-days",
			int(cfg.RetentionMs/(24*60*60*1000)), "retention in days")
		maxConnections = flag.Int("max-connections", cfg.MaxConnections,
			"socket ceiling")
		federation  = flag.Bool("federation", false, "enable federation")
		showVersion = flag.Bool("version", false, "print version")
	)
	var seeds seedFlag
	flag.Var(&seeds, "seed", "federation seed url[|pk]")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return nil
	}
	if flag.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", flag.Arg(0))
	}
	if *storage != "memory" && *storage != "disk" {
		return fmt.Errorf("--storage must be memory or disk, got %q", *storage)
	}
	if *retentionDays < 1 {
		return fmt.Errorf("--retention-days must be positive")
	}

	cfg.Listen = *listen
	cfg.Port = *port
	cfg.Announce = *announce
	cfg.RetentionMs = int64(*retentionDays) * 24 * 60 * 60 * 1000
	cfg.MaxConnections = *maxConnections
	cfg.Federation = *federation
	cfg.Version = version
	for _, spec := range seeds {
		ep, err := parseSeed(spec)
		if err != nil {
			return err
		}
		cfg.Seeds = append(cfg.Seeds, ep)
	}

	id, err := identity.LoadOrCreate(*identityPath)
	if err != nil {
		return err
	}
	st, err := store.New(store.Options{
		Disk:         *storage == "disk",
		Dir:          *path,
		MaxEnvelopes: cfg.MaxStoredEnvelopes,
		MaxBytes:     cfg.MaxStoredBytes,
	})
	if err != nil {
		return err
	}
	logger := log.New(os.Stderr, "", log.LstdFlags)
	srv := server.New(cfg, st, id, logger)
	if err := srv.Start(); err != nil {
		_ = st.Close()
		return err
	}

	fmt.Printf("Soty router relay · dtm_relay %s\n", version)
	fmt.Printf("ed25519   %s\n", id.PubHex())
	fmt.Printf("listen    %s (WebSocket endpoint /ws)\n", srv.Announce())
	if cfg.Federation {
		fmt.Printf("federation on, %d seed(s)\n", len(cfg.Seeds))
	} else {
		fmt.Printf("federation off (LAN relay only)\n")
	}
	fmt.Println("share this invite with your clients:")
	fmt.Println(invite(srv.Announce(), id.PubHex()))
	fmt.Println("ctrl-c to stop")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	signal.Stop(sig)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Printf("[relay] shutdown: %v", err)
	}
	if err := st.Close(); err != nil {
		return err
	}
	return nil
}

func parseSeed(spec string) (wire.HostEndpoint, error) {
	addr := spec
	pk := ""
	if i := strings.LastIndex(spec, "|"); i >= 0 {
		addr = spec[:i]
		pk = spec[i+1:]
	}
	if !wire.ValidRelayAddr(addr) {
		return wire.HostEndpoint{}, fmt.Errorf("invalid seed url %q", addr)
	}
	if pk != "" {
		if raw, err := hex.DecodeString(pk); err != nil || len(raw) != 32 {
			return wire.HostEndpoint{}, fmt.Errorf("seed pk must be 32-byte hex")
		}
	}
	return wire.HostEndpoint{Addr: addr, EdPubKey: pk}, nil
}

func invite(addr, pub string) string {
	q := url.Values{}
	q.Set("addr", addr)
	q.Set("pk", pub)
	return "soty://host?" + q.Encode()
}
