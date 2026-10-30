/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/userwireguard/conn"
	"github.com/urnetwork/userwireguard/conn/bindtest"
	"github.com/urnetwork/userwireguard/logger"
	"github.com/urnetwork/userwireguard/tun/tuntest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// The server side of every on-demand test has no peer configured up front.
// Clients are ordinary devices that know the server's key and endpoint.

var missServerIp = netip.MustParseAddr("10.77.0.1")

type missEndpoint struct {
	dev    *Device
	tun    *tuntest.ChannelTUN
	public NoisePublicKey
	ip     netip.Addr
}

func missKeyPair(tb testing.TB) (NoisePrivateKey, NoisePublicKey) {
	tb.Helper()
	sk, err := newPrivateKey()
	if err != nil {
		tb.Fatalf("generate private key: %v", err)
	}
	return sk, sk.publicKey()
}

func missWgKey(tb testing.TB, b [32]byte) wgtypes.Key {
	tb.Helper()
	key, err := wgtypes.NewKey(b[:])
	if err != nil {
		tb.Fatalf("convert key: %v", err)
	}
	return key
}

func missClientIp(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{10, 78, byte(i >> 8), byte(i)})
}

// startMissServer brings up a device with a private key and no peers. A nil
// settings leaves on-demand peers off, as for an ordinary device.
func startMissServer(tb testing.TB, bind conn.Bind, settings *PeerMissSettings) *missEndpoint {
	tb.Helper()
	sk, pk := missKeyPair(tb)
	tun := tuntest.NewChannelTUN()
	dev := NewDevice(tun.TUN(), bind, logger.NewLogger(logger.LogLevelError, "server: "))
	privateKey := missWgKey(tb, sk)
	port := 0
	if err := dev.IpcSet(&wgtypes.Config{PrivateKey: &privateKey, ListenPort: &port}); err != nil {
		dev.Close()
		tb.Fatalf("configure server: %v", err)
	}
	if settings != nil {
		dev.SetPeerMissSettings(settings)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		tb.Fatalf("bring server up: %v", err)
	}
	tb.Cleanup(dev.Close)
	return &missEndpoint{dev: dev, tun: tun, public: pk, ip: missServerIp}
}

// startMissClient brings up a client device configured with the server as
// its one peer.
func startMissClient(tb testing.TB, bind conn.Bind, server *missEndpoint, ip netip.Addr) *missEndpoint {
	tb.Helper()
	sk, pk := missKeyPair(tb)
	tun := tuntest.NewChannelTUN()
	dev := NewDevice(tun.TUN(), bind, logger.NewLogger(logger.LogLevelError, "client: "))
	privateKey := missWgKey(tb, sk)
	serverKey := missWgKey(tb, server.public)
	port := 0
	config := wgtypes.Config{
		PrivateKey:   &privateKey,
		ListenPort:   &port,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:         serverKey,
				ReplaceAllowedIPs: true,
				AllowedIPs: []net.IPNet{
					{IP: net.IP(missServerIp.AsSlice()), Mask: net.CIDRMask(32, 32)},
				},
				Endpoint: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(server.dev.net.port)},
			},
		},
	}
	if err := dev.IpcSet(&config); err != nil {
		dev.Close()
		tb.Fatalf("configure client: %v", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		tb.Fatalf("bring client up: %v", err)
	}
	tb.Cleanup(dev.Close)
	return &missEndpoint{dev: dev, tun: tun, public: pk, ip: ip}
}

// missDirectory is a test handler: it accepts the keys it knows, each with
// its client address, and counts every call.
type missDirectory struct {
	mutex   sync.Mutex
	allowed map[NoisePublicKey]netip.Addr
	perKey  map[NoisePublicKey]int
	calls   atomic.Int64
}

func newMissDirectory() *missDirectory {
	return &missDirectory{
		allowed: map[NoisePublicKey]netip.Addr{},
		perKey:  map[NoisePublicKey]int{},
	}
}

func (self *missDirectory) allow(publicKey NoisePublicKey, ip netip.Addr) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.allowed[publicKey] = ip
}

func (self *missDirectory) callsFor(publicKey NoisePublicKey) int {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return self.perKey[publicKey]
}

func (self *missDirectory) handler(publicKey NoisePublicKey) (PeerMissConfig, bool) {
	self.calls.Add(1)
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.perKey[publicKey] += 1
	ip, ok := self.allowed[publicKey]
	if !ok {
		return PeerMissConfig{}, false
	}
	return PeerMissConfig{AllowedIPs: []netip.Prefix{netip.PrefixFrom(ip, 32)}}, true
}

func missSettings(handler PeerMissHandler) *PeerMissSettings {
	settings := DefaultPeerMissSettings()
	settings.Handler = handler
	return settings
}

// transit sends one ping from `from` and waits for it at `to`, ignoring
// anything else that arrives.
func transit(from *missEndpoint, to *missEndpoint, timeout time.Duration) error {
	msg := tuntest.Ping(to.ip, from.ip)
	select {
	case from.tun.Outbound <- msg:
	case <-time.After(timeout):
		return fmt.Errorf("%s could not queue a packet", from.ip)
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case got := <-to.tun.Inbound:
			if bytes.Equal(got, msg) {
				return nil
			}
		case <-timer.C:
			return fmt.Errorf("packet %s -> %s did not transit within %s", from.ip, to.ip, timeout)
		}
	}
}

func requireTransit(tb testing.TB, from *missEndpoint, to *missEndpoint) {
	tb.Helper()
	if err := transit(from, to, 3*time.Second); err != nil {
		tb.Fatal(err)
	}
}

func clientPeerOf(tb testing.TB, client *missEndpoint, server *missEndpoint) *Peer {
	tb.Helper()
	peer := client.dev.LookupPeer(server.public)
	if peer == nil {
		tb.Fatal("client has no peer for the server")
	}
	return peer
}

// allowResendNow lets the next SendHandshakeInitiation through its
// RekeyTimeout pacing.
func allowResendNow(peer *Peer) {
	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now().Add(-(RekeyTimeout + time.Second))
	peer.handshake.mutex.Unlock()
}

func waitFor(tb testing.TB, timeout time.Duration, what string, done func() bool) {
	tb.Helper()
	deadline := time.Now().Add(timeout)
	for !done() {
		if time.Now().After(deadline) {
			tb.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// An unknown key reaches the handler once; the device creates the peer and
// completes the same initiation, and data then flows both ways.
func TestPeerMissUnknownKeyCreatesPeerAndMovesDataBothWays(t *testing.T) {
	goroutineLeakCheck(t)
	binds := bindtest.NewChannelBinds()
	directory := newMissDirectory()
	server := startMissServer(t, binds[0], missSettings(directory.handler))
	client := startMissClient(t, binds[1], server, missClientIp(1))
	directory.allow(client.public, client.ip)

	if server.dev.LookupPeer(client.public) != nil {
		t.Fatal("server has a peer before any initiation")
	}
	requireTransit(t, client, server)
	requireTransit(t, server, client)
	requireTransit(t, client, server)

	if calls := directory.callsFor(client.public); calls != 1 {
		t.Fatalf("handler calls for the client = %d, want 1", calls)
	}
	peer := server.dev.LookupPeer(client.public)
	if peer == nil || !peer.isRunning.Load() {
		t.Fatal("server has no running peer for the client")
	}
	if got := server.dev.allowedips.Lookup(client.ip.AsSlice()); got != peer {
		t.Fatal("client address is not routed to the created peer")
	}
	if stats := server.dev.PeerMissStats(); stats.Accepted != 1 || stats.Refused != 0 {
		t.Fatalf("stats = %+v, want one acceptance", stats)
	}
	if count := server.dev.PeerCount(); count != 1 {
		t.Fatalf("peer count = %d, want 1", count)
	}
}

// Without a handler an unknown key is dropped exactly as before.
func TestPeerMissOffLeavesUnknownKeysDropped(t *testing.T) {
	goroutineLeakCheck(t)
	binds := bindtest.NewChannelBinds()
	server := startMissServer(t, binds[0], nil)
	client := startMissClient(t, binds[1], server, missClientIp(1))
	if err := transit(client, server, 500*time.Millisecond); err == nil {
		t.Fatal("a packet from an unknown key transited with on-demand peers off")
	}
	if server.dev.PeerCount() != 0 {
		t.Fatal("a peer was created with on-demand peers off")
	}
}

// A refused key is remembered for NegativeTtl and asked again after it, and a
// cleared refusal is asked again at once.
func TestPeerMissRefusalIsCachedForItsTtl(t *testing.T) {
	directory := newMissDirectory()
	settings := missSettings(directory.handler)
	settings.NegativeTtl = 10 * time.Second
	server := startMissServer(t, bindtest.NewChannelBinds()[0], settings)
	now := time.Unix(1_000_000, 0)
	server.dev.peerMiss.now = func() time.Time { return now }

	_, unknown := missKeyPair(t)
	for i := 0; i < 5; i++ {
		if server.dev.resolvePeerMiss(unknown) {
			t.Fatal("an unknown key was accepted")
		}
	}
	if calls := directory.callsFor(unknown); calls != 1 {
		t.Fatalf("handler calls inside the ttl = %d, want 1", calls)
	}
	if stats := server.dev.PeerMissStats(); stats.Refused != 1 || stats.NegativeCacheHits != 4 {
		t.Fatalf("stats = %+v, want 1 refusal and 4 cache hits", stats)
	}

	now = now.Add(9 * time.Second)
	server.dev.resolvePeerMiss(unknown)
	if calls := directory.callsFor(unknown); calls != 1 {
		t.Fatalf("handler calls before expiry = %d, want 1", calls)
	}
	now = now.Add(2 * time.Second)
	server.dev.resolvePeerMiss(unknown)
	if calls := directory.callsFor(unknown); calls != 2 {
		t.Fatalf("handler calls after expiry = %d, want 2", calls)
	}

	// a key that becomes valid is not held back by its cached refusal once
	// the owner clears it
	directory.allow(unknown, missClientIp(9))
	server.dev.ClearPeerMissRefusal(unknown)
	if !server.dev.resolvePeerMiss(unknown) {
		t.Fatal("a cleared refusal was not asked again")
	}
	if server.dev.LookupPeer(unknown) == nil {
		t.Fatal("the accepted key has no peer")
	}
}

// Refusals are bounded: past NegativeMaxEntries the cache does not grow.
func TestPeerMissRefusalCacheIsBounded(t *testing.T) {
	directory := newMissDirectory()
	settings := missSettings(directory.handler)
	settings.NegativeMaxEntries = 64
	settings.RatePerSecond = 1e9
	settings.Burst = 1 << 20
	server := startMissServer(t, bindtest.NewChannelBinds()[0], settings)
	for i := 0; i < 1000; i++ {
		_, key := missKeyPair(t)
		server.dev.resolvePeerMiss(key)
	}
	server.dev.peerMiss.mutex.Lock()
	size := len(server.dev.peerMiss.refused)
	server.dev.peerMiss.mutex.Unlock()
	if size > 64 {
		t.Fatalf("refusal cache holds %d keys, bound is 64", size)
	}
}

// Concurrent initiations for one key call the handler once and create one
// peer; the rest are coalesced while the first resolution runs.
func TestPeerMissConcurrentInitiationsFromOneKeyCallOnce(t *testing.T) {
	_, key := missKeyPair(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int64
	var once sync.Once
	settings := missSettings(func(publicKey NoisePublicKey) (PeerMissConfig, bool) {
		calls.Add(1)
		once.Do(func() { close(entered) })
		<-release
		return PeerMissConfig{AllowedIPs: []netip.Prefix{netip.PrefixFrom(missClientIp(1), 32)}}, true
	})
	settings.HandlerTimeout = 10 * time.Second
	server := startMissServer(t, bindtest.NewChannelBinds()[0], settings)

	first := make(chan bool, 1)
	go func() { first <- server.dev.resolvePeerMiss(key) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("the first initiation never reached the handler")
	}

	const others = 32
	results := make(chan bool, others)
	var wg sync.WaitGroup
	for i := 0; i < others; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- server.dev.resolvePeerMiss(key)
		}()
	}
	wg.Wait()
	close(results)
	for accepted := range results {
		if accepted {
			t.Fatal("a coalesced initiation reported a peer while the first was still resolving")
		}
	}
	close(release)
	if !<-first {
		t.Fatal("the first resolution did not create the peer")
	}
	if calls.Load() != 1 {
		t.Fatalf("handler calls = %d, want 1", calls.Load())
	}
	if stats := server.dev.PeerMissStats(); stats.Coalesced != others || stats.Accepted != 1 {
		t.Fatalf("stats = %+v, want %d coalesced and 1 accepted", stats, others)
	}
	if count := server.dev.PeerCount(); count != 1 {
		t.Fatalf("peer count = %d, want 1", count)
	}
	// later initiations find the peer and never reach the handler
	if !server.dev.resolvePeerMiss(key) || calls.Load() != 1 {
		t.Fatal("an existing peer went back to the handler")
	}
}

// Concurrent creations of one key share one peer object.
func TestAddPeerOnDemandConcurrentCreatesOnePeer(t *testing.T) {
	server := startMissServer(t, bindtest.NewChannelBinds()[0], nil)
	_, key := missKeyPair(t)
	config := PeerMissConfig{AllowedIPs: []netip.Prefix{netip.PrefixFrom(missClientIp(1), 32)}}

	const n = 64
	peers := make([]*Peer, n)
	errs := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			peers[i], errs[i] = server.dev.AddPeerOnDemand(key, config)
		}(i)
	}
	close(start)
	wg.Wait()
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("creation %d: %v", i, errs[i])
		}
		if peers[i] != peers[0] || peers[i] == nil {
			t.Fatal("concurrent creations returned different peers")
		}
	}
	if server.dev.PeerCount() != 1 || !peers[0].isRunning.Load() {
		t.Fatal("want exactly one running peer")
	}
}

// Many distinct keys at once: each is asked once and gets its own peer.
func TestPeerMissManyDistinctKeysAtOnce(t *testing.T) {
	directory := newMissDirectory()
	settings := missSettings(directory.handler)
	settings.RatePerSecond = 1e9
	settings.Burst = 1 << 20
	// every worker waits for its answer here; the bound on that wait has
	// its own test
	settings.HandlerTimeout = 30 * time.Second
	server := startMissServer(t, bindtest.NewChannelBinds()[0], settings)

	const n = 1000
	keys := make([]NoisePublicKey, n)
	for i := range keys {
		_, keys[i] = missKeyPair(t)
		directory.allow(keys[i], missClientIp(i))
	}
	var wg sync.WaitGroup
	var accepted atomic.Int64
	for i := range keys {
		wg.Add(1)
		go func(key NoisePublicKey) {
			defer wg.Done()
			if server.dev.resolvePeerMiss(key) {
				accepted.Add(1)
			}
		}(keys[i])
	}
	wg.Wait()
	if accepted.Load() != n || directory.calls.Load() != n {
		t.Fatalf("accepted %d with %d handler calls, want %d each", accepted.Load(), directory.calls.Load(), n)
	}
	if server.dev.PeerCount() != n {
		t.Fatalf("peer count = %d, want %d", server.dev.PeerCount(), n)
	}
	if stats := server.dev.PeerMissStats(); stats.Accepted != n || stats.Coalesced != 0 {
		t.Fatalf("stats = %+v, want %d accepted and none coalesced", stats, n)
	}
	for i, key := range keys {
		peer := server.dev.LookupPeer(key)
		if peer == nil || server.dev.allowedips.Lookup(missClientIp(i).AsSlice()) != peer {
			t.Fatalf("key %d is not routed to its own peer", i)
		}
	}
}

// Many real clients handshaking at the same moment all complete.
func TestPeerMissManyClientsHandshakeAtOnce(t *testing.T) {
	goroutineLeakCheck(t)
	directory := newMissDirectory()
	server := startMissServer(t, conn.NewDefaultBind(), missSettings(directory.handler))

	const n = 24
	clients := make([]*missEndpoint, n)
	for i := range clients {
		clients[i] = startMissClient(t, conn.NewDefaultBind(), server, missClientIp(i+1))
		directory.allow(clients[i].public, clients[i].ip)
	}
	// every client sends at the same moment; one reader collects the
	// distinct sources as they arrive
	for _, client := range clients {
		go func(client *missEndpoint) {
			client.tun.Outbound <- tuntest.Ping(server.ip, client.ip)
		}(client)
	}
	seen := map[netip.Addr]bool{}
	timeout := time.After(10 * time.Second)
	for len(seen) < n {
		select {
		case packet := <-server.tun.Inbound:
			seen[netip.AddrFrom4([4]byte(packet[12:16]))] = true
		case <-timeout:
			t.Fatalf("%d of %d clients reached the server", len(seen), n)
		}
	}
	for _, client := range clients {
		if server.dev.LookupPeer(client.public) == nil {
			t.Fatalf("client %s has no peer", client.ip)
		}
		if calls := directory.callsFor(client.public); calls != 1 {
			t.Fatalf("client %s: handler calls = %d, want 1", client.ip, calls)
		}
	}
	// and each can reach the server on its own
	for _, client := range clients {
		requireTransit(t, client, server)
	}
}

// A handler that panics is a refusal that is not cached, and the device keeps
// serving other keys.
func TestPeerMissHandlerPanicIsContained(t *testing.T) {
	_, bad := missKeyPair(t)
	_, good := missKeyPair(t)
	settings := missSettings(func(publicKey NoisePublicKey) (PeerMissConfig, bool) {
		if publicKey == bad {
			panic("directory unavailable")
		}
		return PeerMissConfig{AllowedIPs: []netip.Prefix{netip.PrefixFrom(missClientIp(2), 32)}}, true
	})
	server := startMissServer(t, bindtest.NewChannelBinds()[0], settings)
	if server.dev.resolvePeerMiss(bad) {
		t.Fatal("a panicking handler created a peer")
	}
	if !server.dev.resolvePeerMiss(good) {
		t.Fatal("the device stopped serving after a handler panic")
	}
	stats := server.dev.PeerMissStats()
	if stats.HandlerFailures != 1 || stats.NegativeCacheHits != 0 {
		t.Fatalf("stats = %+v, want one handler failure and nothing cached", stats)
	}
	// a failure is not a refusal: the key is asked again
	server.dev.resolvePeerMiss(bad)
	if stats := server.dev.PeerMissStats(); stats.HandlerFailures != 2 {
		t.Fatalf("stats = %+v, want the failed key asked again", stats)
	}
}

// A slow handler holds a handshake worker for at most HandlerTimeout. Its
// late answer still creates the peer, so the client's retry completes.
func TestPeerMissSlowHandlerNeverBlocksWorkers(t *testing.T) {
	_, slow := missKeyPair(t)
	_, fast := missKeyPair(t)
	release := make(chan struct{})
	settings := missSettings(func(publicKey NoisePublicKey) (PeerMissConfig, bool) {
		if publicKey == slow {
			<-release
		}
		return PeerMissConfig{AllowedIPs: []netip.Prefix{netip.PrefixFrom(missClientIp(3), 32)}}, true
	})
	settings.HandlerTimeout = 50 * time.Millisecond
	server := startMissServer(t, bindtest.NewChannelBinds()[0], settings)

	start := time.Now()
	if server.dev.resolvePeerMiss(slow) {
		t.Fatal("a handler that has not answered created a peer")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("a slow handler held the worker for %s", elapsed)
	}
	// other keys resolve while the slow handler is still out
	if !server.dev.resolvePeerMiss(fast) {
		t.Fatal("a fast key was blocked behind a slow one")
	}
	if stats := server.dev.PeerMissStats(); stats.HandlerTimeouts != 1 {
		t.Fatalf("stats = %+v, want one handler timeout", stats)
	}
	// the late answer is applied when it arrives
	close(release)
	waitFor(t, 3*time.Second, "the late answer to create the peer", func() bool {
		return server.dev.LookupPeer(slow) != nil
	})
}

// Handler calls past the rate are refused without asking the handler.
func TestPeerMissRateLimitBoundsHandlerCalls(t *testing.T) {
	directory := newMissDirectory()
	settings := missSettings(directory.handler)
	settings.RatePerSecond = 1
	settings.Burst = 2
	server := startMissServer(t, bindtest.NewChannelBinds()[0], settings)
	now := time.Unix(2_000_000, 0)
	server.dev.peerMiss.now = func() time.Time { return now }

	keys := make([]NoisePublicKey, 5)
	for i := range keys {
		_, keys[i] = missKeyPair(t)
		directory.allow(keys[i], missClientIp(i))
	}
	accepted := 0
	for _, key := range keys {
		if server.dev.resolvePeerMiss(key) {
			accepted++
		}
	}
	if accepted != 2 || directory.calls.Load() != 2 {
		t.Fatalf("accepted %d with %d handler calls, want the burst of 2", accepted, directory.calls.Load())
	}
	if stats := server.dev.PeerMissStats(); stats.RateLimited != 3 {
		t.Fatalf("stats = %+v, want 3 rate limited", stats)
	}
	now = now.Add(time.Second)
	if !server.dev.resolvePeerMiss(keys[2]) {
		t.Fatal("a token did not refill after a second")
	}
}

// A peer evicted while idle comes back through the handler on the client's
// next handshake.
func TestPeerMissEvictedPeerRehandshakesThroughHandler(t *testing.T) {
	goroutineLeakCheck(t)
	binds := bindtest.NewChannelBinds()
	directory := newMissDirectory()
	server := startMissServer(t, binds[0], missSettings(directory.handler))
	client := startMissClient(t, binds[1], server, missClientIp(1))
	directory.allow(client.public, client.ip)

	requireTransit(t, client, server)
	removed := server.dev.RemoveIdlePeers(0)
	if len(removed) != 1 || removed[0] != client.public {
		t.Fatalf("removed %d peers, want the client", len(removed))
	}
	if server.dev.LookupPeer(client.public) != nil || server.dev.allowedips.Lookup(client.ip.AsSlice()) != nil {
		t.Fatal("the evicted peer is still reachable")
	}

	// the client's session is gone on the server; its next handshake (here
	// forced, as its rekey timer would) goes through the handler again
	clientPeer := clientPeerOf(t, client, server)
	clientPeer.ExpireCurrentKeypairs()
	allowResendNow(clientPeer)
	requireTransit(t, client, server)
	requireTransit(t, server, client)
	if calls := directory.callsFor(client.public); calls != 2 {
		t.Fatalf("handler calls = %d, want 2 (first contact and reconnect)", calls)
	}
}

// Rekeying and re-handshaking after expiry run on the existing on-demand peer,
// without another handler call and without replacing the peer. A keypair is
// pushed past its threshold by message count: RekeyAfterMessages and
// RejectAfterMessages sit in the same conditions as RekeyAfterTime (120 s) and
// RejectAfterTime (180 s) (send.go keepKeyFreshSending and SendStagedPackets),
// so they drive the same rekey and re-initiation paths. The age thresholds are
// not rewritten here: the device reads a keypair's creation time without a
// lock, so rewriting it would race.
func TestPeerMissRekeyAndExpiryKeepThePeer(t *testing.T) {
	goroutineLeakCheck(t)
	binds := bindtest.NewChannelBinds()
	directory := newMissDirectory()
	server := startMissServer(t, binds[0], missSettings(directory.handler))
	client := startMissClient(t, binds[1], server, missClientIp(1))
	directory.allow(client.public, client.ip)

	requireTransit(t, client, server)
	requireTransit(t, server, client)
	serverPeer := server.dev.LookupPeer(client.public)
	clientPeer := clientPeerOf(t, client, server)

	pushPast := func(peer *Peer, messages uint64) *Keypair {
		keypair := peer.keypairs.Current()
		if keypair == nil {
			t.Fatal("the peer has no current keypair")
		}
		keypair.sendNonce.Store(messages)
		return keypair
	}
	// A real client rekeys minutes after its last handshake. Here it is
	// milliseconds, so first wait out the 16.7 ms granularity of handshake
	// timestamps and the 50 ms initiation flood guard, either of which would
	// otherwise reject the next initiation as a replay.
	settle := func() { time.Sleep(150 * time.Millisecond) }

	// rekey: the initiator starts a new handshake on its next send, which
	// itself still goes out on the old keys
	settle()
	before := pushPast(clientPeer, RekeyAfterMessages+1)
	allowResendNow(clientPeer)
	requireTransit(t, client, server)
	waitFor(t, 3*time.Second, "the rekey", func() bool {
		return clientPeer.keypairs.Current() != before
	})
	requireTransit(t, client, server)
	requireTransit(t, server, client)

	// expiry: both sides' keys are spent, so each side's next packet is
	// staged behind a new handshake; the server's comes from the server
	// re-initiating toward the client it learned on demand
	settle()
	pushPast(clientPeer, RejectAfterMessages)
	pushPast(serverPeer, RejectAfterMessages)
	allowResendNow(clientPeer)
	allowResendNow(serverPeer)
	requireTransit(t, client, server)
	settle()
	pushPast(serverPeer, RejectAfterMessages)
	allowResendNow(serverPeer)
	requireTransit(t, server, client)

	if calls := directory.callsFor(client.public); calls != 1 {
		t.Fatalf("handler calls = %d, want 1", calls)
	}
	if server.dev.LookupPeer(client.public) != serverPeer {
		t.Fatal("the server replaced the peer instead of rekeying it")
	}
}

// A client that moves to another source port keeps its session: the server
// follows the authenticated packets to the new endpoint.
func TestPeerMissEndpointRoaming(t *testing.T) {
	goroutineLeakCheck(t)
	directory := newMissDirectory()
	server := startMissServer(t, conn.NewDefaultBind(), missSettings(directory.handler))
	client := startMissClient(t, conn.NewDefaultBind(), server, missClientIp(1))
	directory.allow(client.public, client.ip)

	requireTransit(t, client, server)
	requireTransit(t, server, client)
	endpointPort := func() uint16 {
		for _, snapshot := range server.dev.PeerSnapshots() {
			if snapshot.PublicKey == client.public {
				return snapshot.Endpoint.Port()
			}
		}
		return 0
	}
	oldPort := endpointPort()
	if oldPort == 0 {
		t.Fatal("the server learned no endpoint for the client")
	}

	// rebind the client to a fresh port
	newPort := 0
	if err := client.dev.IpcSet(&wgtypes.Config{ListenPort: &newPort}); err != nil {
		t.Fatalf("rebind client: %v", err)
	}
	requireTransit(t, client, server)
	waitFor(t, 3*time.Second, "the server to learn the new endpoint", func() bool {
		port := endpointPort()
		return port != 0 && port != oldPort
	})
	requireTransit(t, server, client)
	if calls := directory.callsFor(client.public); calls != 1 {
		t.Fatalf("handler calls = %d, want 1", calls)
	}
}

// Under load an initiation must carry a valid cookie (mac2) before it can
// reach the handler; the client earns one from the cookie reply.
func TestPeerMissUnderLoadRequiresCookieBeforeHandler(t *testing.T) {
	goroutineLeakCheck(t)
	binds := bindtest.NewChannelBinds()
	directory := newMissDirectory()
	server := startMissServer(t, binds[0], missSettings(directory.handler))
	client := startMissClient(t, binds[1], server, missClientIp(1))
	directory.allow(client.public, client.ip)

	underLoad := func() { server.dev.rate.underLoadUntil.Store(time.Now().Add(time.Hour).UnixNano()) }
	underLoad()
	clientPeer := clientPeerOf(t, client, server)

	// the first initiation has no cookie: the server answers with a cookie
	// reply and never consults the handler
	if err := transit(client, server, 500*time.Millisecond); err == nil {
		t.Fatal("an initiation without a cookie completed under load")
	}
	if directory.calls.Load() != 0 {
		t.Fatalf("handler calls = %d before a valid cookie, want 0", directory.calls.Load())
	}
	waitFor(t, 3*time.Second, "the client to hold a cookie", func() bool {
		clientPeer.cookieGenerator.RLock()
		defer clientPeer.cookieGenerator.RUnlock()
		return !clientPeer.cookieGenerator.mac2.cookieSet.IsZero()
	})

	// the retry carries mac2, passes the check and reaches the handler
	underLoad()
	allowResendNow(clientPeer)
	clientPeer.SendHandshakeInitiation(true)
	waitFor(t, 3*time.Second, "the handshake to complete", func() bool {
		peer := server.dev.LookupPeer(client.public)
		return peer != nil && peer.keypairs.next.Load() != nil || peer != nil && peer.keypairs.Current() != nil
	})
	requireTransit(t, client, server)
	if calls := directory.callsFor(client.public); calls != 1 {
		t.Fatalf("handler calls = %d, want 1", calls)
	}
}

// Under load the handler is behind the cookie checks. A flood from fresh keys
// without a valid cookie never reaches it; a source that has earned a cookie
// reaches it only at the per-source rate of the handshake rate limiter.
func TestPeerMissFloodUnderLoadIsCheckedBeforeHandler(t *testing.T) {
	binds := bindtest.NewChannelBinds()
	directory := newMissDirectory()
	server := startMissServer(t, binds[0], missSettings(directory.handler))
	server.dev.rate.underLoadUntil.Store(time.Now().Add(time.Hour).UnixNano())

	forger := startMissClient(t, binds[1], server, missClientIp(1))
	forgerPeer := clientPeerOf(t, forger, server)
	forge := func(endpoint conn.Endpoint) {
		sk, _ := missKeyPair(t)
		if err := forger.dev.SetPrivateKey(sk); err != nil {
			t.Fatalf("rotate forger key: %v", err)
		}
		msg, err := forger.dev.CreateMessageInitiation(forgerPeer)
		if err != nil {
			t.Fatalf("create initiation: %v", err)
		}
		packet := make([]byte, MessageInitiationSize)
		if err := msg.marshal(packet); err != nil {
			t.Fatalf("marshal initiation: %v", err)
		}
		forgerPeer.cookieGenerator.AddMacs(packet)
		server.dev.queue.handshake.c <- QueueHandshakeElement{
			msgType:  MessageInitiationType,
			packet:   packet,
			buffer:   server.dev.GetMessageBuffer(),
			endpoint: endpoint,
		}
	}
	drain := func() {
		waitFor(t, 3*time.Second, "the flood to drain", func() bool {
			return len(server.dev.queue.handshake.c) == 0
		})
		time.Sleep(50 * time.Millisecond)
	}

	// a source that cannot receive the cookie reply never gets past mac2
	const n = 256
	unreachable := bindtest.ChannelEndpoint(99)
	for i := 0; i < n; i++ {
		forge(unreachable)
	}
	drain()
	if directory.calls.Load() != 0 {
		t.Fatalf("handler calls = %d during a cookie-less flood, want 0", directory.calls.Load())
	}

	// the forger's own source earns a cookie from the reply to its first
	// initiation; after that its initiations carry mac2 and only the
	// per-source rate limiter stands between them and the handler
	forge(bindtest.ChannelEndpoint(1))
	waitFor(t, 3*time.Second, "the forger to hold a cookie", func() bool {
		forgerPeer.cookieGenerator.RLock()
		defer forgerPeer.cookieGenerator.RUnlock()
		return !forgerPeer.cookieGenerator.mac2.cookieSet.IsZero()
	})
	start := time.Now()
	for i := 0; i < n; i++ {
		forge(bindtest.ChannelEndpoint(1))
	}
	drain()
	elapsed := time.Since(start).Seconds()
	// ratelimiter: 5 burst and 20 per second per source
	bound := int64(5 + 20*elapsed + 2)
	if calls := directory.calls.Load(); calls == 0 || bound < calls {
		t.Fatalf("handler calls = %d for %d cookie-carrying initiations over %.2fs, want 1..%d", calls, n, elapsed, bound)
	}
	if server.dev.PeerCount() != 0 {
		t.Fatal("a flood of unknown keys created peers")
	}
}

// Eviction removes exactly the peers whose newest handshake, or creation when
// they never completed one, is older than the idle bound, and releases their
// goroutines and routes.
func TestRemoveIdlePeersEvictsOnlyIdlePeers(t *testing.T) {
	server := startMissServer(t, bindtest.NewChannelBinds()[0], nil)
	type entry struct {
		key  NoisePublicKey
		ip   netip.Addr
		peer *Peer
	}
	entries := make([]entry, 4)
	for i := range entries {
		_, entries[i].key = missKeyPair(t)
		entries[i].ip = missClientIp(i + 1)
		peer, err := server.dev.AddPeerOnDemand(entries[i].key, PeerMissConfig{
			AllowedIPs: []netip.Prefix{netip.PrefixFrom(entries[i].ip, 32)},
		})
		if err != nil {
			t.Fatalf("create peer %d: %v", i, err)
		}
		entries[i].peer = peer
	}
	now := time.Now()
	// 0: created long ago, never handshook -> idle
	entries[0].peer.createdNano.Store(now.Add(-20 * time.Minute).UnixNano())
	// 1: handshook long ago -> idle
	entries[1].peer.createdNano.Store(now.Add(-60 * time.Minute).UnixNano())
	entries[1].peer.lastHandshakeNano.Store(now.Add(-20 * time.Minute).UnixNano())
	// 2: created long ago but handshook recently -> kept
	entries[2].peer.createdNano.Store(now.Add(-60 * time.Minute).UnixNano())
	entries[2].peer.lastHandshakeNano.Store(now.Add(-time.Minute).UnixNano())
	// 3: just created -> kept

	goroutinesBefore := runtime.NumGoroutine()
	removed := server.dev.RemoveIdlePeers(10 * time.Minute)
	if len(removed) != 2 {
		t.Fatalf("removed %d peers, want 2", len(removed))
	}
	removedSet := map[NoisePublicKey]bool{}
	for _, key := range removed {
		removedSet[key] = true
	}
	for i, e := range entries {
		evicted := i <= 1
		if removedSet[e.key] != evicted {
			t.Fatalf("peer %d: evicted = %v, want %v", i, removedSet[e.key], evicted)
		}
		if evicted {
			if server.dev.LookupPeer(e.key) != nil || e.peer.isRunning.Load() {
				t.Fatalf("evicted peer %d is still registered or running", i)
			}
			if server.dev.allowedips.Lookup(e.ip.AsSlice()) != nil {
				t.Fatalf("evicted peer %d still owns its route", i)
			}
		} else if server.dev.LookupPeer(e.key) != e.peer || !e.peer.isRunning.Load() {
			t.Fatalf("kept peer %d was disturbed", i)
		}
	}
	waitFor(t, 3*time.Second, "the evicted peers' routines to exit", func() bool {
		return runtime.NumGoroutine() <= goroutinesBefore-4
	})
	if server.dev.PeerCount() != 2 {
		t.Fatalf("peer count = %d, want 2", server.dev.PeerCount())
	}
}

// Snapshots report each peer's key, endpoint and newest handshake.
func TestPeerSnapshotsReportSessions(t *testing.T) {
	binds := bindtest.NewChannelBinds()
	directory := newMissDirectory()
	server := startMissServer(t, binds[0], missSettings(directory.handler))
	client := startMissClient(t, binds[1], server, missClientIp(1))
	directory.allow(client.public, client.ip)
	requireTransit(t, client, server)
	requireTransit(t, server, client)

	snapshots := server.dev.PeerSnapshots()
	if len(snapshots) != 1 || snapshots[0].PublicKey != client.public {
		t.Fatalf("snapshots = %+v, want the client", snapshots)
	}
	if !snapshots[0].Endpoint.IsValid() || snapshots[0].LastHandshake.IsZero() {
		t.Fatalf("snapshot = %+v, want an endpoint and a handshake time", snapshots[0])
	}
}
