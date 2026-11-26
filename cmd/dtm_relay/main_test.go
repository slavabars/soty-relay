package main

import (
	"net/url"
	"strings"
	"testing"
)

func TestParseSeed(t *testing.T) {
	pk := strings.Repeat("a", 64)
	ep, err := parseSeed("wss://relay.example/soty-ws|" + pk)
	if err != nil {
		t.Fatal(err)
	}
	if ep.Addr != "wss://relay.example/soty-ws" || ep.EdPubKey != pk {
		t.Fatalf("ep=%+v", ep)
	}

	ep, err = parseSeed("ws://192.168.1.1:3100/ws")
	if err != nil {
		t.Fatal(err)
	}
	if ep.EdPubKey != "" {
		t.Fatalf("pk=%q", ep.EdPubKey)
	}

	for _, bad := range []string{
		"relay.example",
		"http://relay.example/ws",
		"ws://relay.example/ws|zz",
		"ws://relay.example/ws|" + strings.Repeat("a", 62),
	} {
		if _, err := parseSeed(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestInviteRoundTrips(t *testing.T) {
	pk := strings.Repeat("b", 64)
	link := invite("ws://192.168.1.1:3100/ws", pk)
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "soty" || u.Host != "host" {
		t.Fatalf("link=%s", link)
	}
	if u.Query().Get("addr") != "ws://192.168.1.1:3100/ws" ||
		u.Query().Get("pk") != pk {
		t.Fatalf("query=%v", u.Query())
	}
}
