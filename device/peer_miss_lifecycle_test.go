/* SPDX-License-Identifier: MIT */

package device

// Exercises revocation and construction at controlled handler and configuration barriers.

import (
	"bytes"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/userwireguard/v2026/conn/bindtest"
	"github.com/urnetwork/userwireguard/v2026/logger"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Waits for an observable result; the deadline only bounds a broken test.
func awaitPeerResult[T any](t *testing.T, result <-chan T) T {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("peer operation did not finish")
		var zero T
		return zero
	}
}

// Captures a directory answer before revocation, then verifies it cannot
// restore the key or steal the replacement client's allowed-address route.
func TestPeerMissRevocationDiscardsCapturedAnswer(t *testing.T) {
	server := startMissServer(t, bindtest.NewChannelBinds()[0], nil)
	_, revokedKey := missKeyPair(t)
	_, replacementKey := missKeyPair(t)
	prefix := netip.MustParsePrefix("192.0.2.2/32")
	captured, release := make(chan struct{}), make(chan struct{})
	releaseOnce := sync.OnceFunc(func() { close(release) })
	defer releaseOnce()
	settings := missSettings(func(key NoisePublicKey) (PeerMissConfig, bool) {
		close(captured)
		<-release
		return PeerMissConfig{AllowedIPs: []netip.Prefix{prefix}}, true
	})
	settings.HandlerTimeout = time.Minute
	server.dev.SetPeerMissSettings(settings)
	resolved := make(chan bool, 1)
	go func() { resolved <- server.dev.resolvePeerMiss(revokedKey) }()
	awaitPeerResult(t, captured)
	server.dev.RemovePeer(revokedKey)
	replacement, err := server.dev.AddPeerOnDemand(replacementKey, PeerMissConfig{AllowedIPs: []netip.Prefix{prefix}})
	if err != nil {
		t.Fatal(err)
	}
	releaseOnce()
	if awaitPeerResult(t, resolved) {
		t.Fatal("revoked handler answer was accepted")
	}
	if server.dev.LookupPeer(revokedKey) != nil {
		t.Fatal("revoked key regained a peer")
	}
	if server.dev.allowedips.Lookup(prefix.Addr().AsSlice()) != replacement {
		t.Fatal("revoked key replaced the current client's route")
	}
}

// An update-only IPC removal must invalidate an accepted miss whose peer has
// not been published yet, just like a direct RemovePeer call.
func TestPeerMissIpcRemovalInvalidatesUnpublishedPeer(t *testing.T) {
	server := startMissServer(t, bindtest.NewChannelBinds()[0], nil)
	_, key := missKeyPair(t)
	captured, release := make(chan struct{}), make(chan struct{})
	releaseOnce := sync.OnceFunc(func() { close(release) })
	defer releaseOnce()
	settings := missSettings(func(key NoisePublicKey) (PeerMissConfig, bool) {
		close(captured)
		<-release
		return PeerMissConfig{}, true
	})
	settings.HandlerTimeout = time.Minute
	server.dev.SetPeerMissSettings(settings)
	resolved := make(chan bool, 1)
	go func() { resolved <- server.dev.resolvePeerMiss(key) }()
	awaitPeerResult(t, captured)
	if err := server.dev.IpcSet(&wgtypes.Config{Peers: []wgtypes.PeerConfig{{
		PublicKey:  wgtypes.Key(key),
		Remove:     true,
		UpdateOnly: true,
	}}}); err != nil {
		t.Fatal(err)
	}
	releaseOnce()
	if awaitPeerResult(t, resolved) || server.dev.LookupPeer(key) != nil {
		t.Fatal("update-only removal allowed a pending answer to restore the peer")
	}
}

// Invalidating an older refusal must neither cache it nor erase a newer call
// for the same key. Only the newer call may cache a refusal.
func TestPeerMissInvalidationPreservesNewResolution(t *testing.T) {
	server := startMissServer(t, bindtest.NewChannelBinds()[0], nil)
	_, key := missKeyPair(t)
	entered := make(chan chan struct{}, 2)
	var releases []func()
	defer func() {
		for _, release := range releases {
			release()
		}
	}()
	settings := missSettings(func(key NoisePublicKey) (PeerMissConfig, bool) {
		release := make(chan struct{})
		entered <- release
		<-release
		return PeerMissConfig{}, false
	})
	settings.HandlerTimeout = time.Minute
	server.dev.SetPeerMissSettings(settings)
	oldResult := make(chan bool, 1)
	go func() { oldResult <- server.dev.resolvePeerMiss(key) }()
	oldRelease := awaitPeerResult(t, entered)
	releases = append(releases, sync.OnceFunc(func() { close(oldRelease) }))
	server.dev.ClearPeerMissRefusal(key)
	newResult := make(chan bool, 1)
	go func() { newResult <- server.dev.resolvePeerMiss(key) }()
	newRelease := awaitPeerResult(t, entered)
	releases = append(releases, sync.OnceFunc(func() { close(newRelease) }))
	releases[0]()
	if awaitPeerResult(t, oldResult) {
		t.Fatal("invalidated answer was accepted")
	}
	server.dev.peerMiss.stateLock.Lock()
	_, refused := server.dev.peerMiss.refused[key]
	_, pending := server.dev.peerMiss.publicKeyResolutions[key]
	server.dev.peerMiss.stateLock.Unlock()
	if refused || !pending {
		t.Fatalf("old answer modified newer state: refused=%t pending=%t", refused, pending)
	}
	releases[1]()
	if awaitPeerResult(t, newResult) {
		t.Fatal("refusal was accepted")
	}
	if server.dev.PeerMissStats().Refused != 1 {
		t.Fatal("invalidated refusal was counted")
	}
}

// Replacing the handler or clearing all peers revokes every earlier answer.
func TestPeerMissResetDiscardsCapturedAnswers(t *testing.T) {
	for _, reset := range []struct {
		name  string
		apply func(*Device)
	}{
		{name: "remove all", apply: func(dev *Device) { dev.RemoveAllPeers() }},
		{name: "disable handler", apply: func(dev *Device) { dev.SetPeerMissSettings(nil) }},
	} {
		func() {
			server := startMissServer(t, bindtest.NewChannelBinds()[0], nil)
			_, key := missKeyPair(t)
			captured, release := make(chan struct{}), make(chan struct{})
			releaseOnce := sync.OnceFunc(func() { close(release) })
			defer releaseOnce()
			settings := missSettings(func(key NoisePublicKey) (PeerMissConfig, bool) {
				close(captured)
				<-release
				return PeerMissConfig{}, true
			})
			settings.HandlerTimeout = time.Minute
			server.dev.SetPeerMissSettings(settings)
			result := make(chan bool, 1)
			go func() { result <- server.dev.resolvePeerMiss(key) }()
			awaitPeerResult(t, captured)
			reset.apply(server.dev)
			releaseOnce()
			if awaitPeerResult(t, result) || server.dev.LookupPeer(key) != nil {
				t.Fatalf("%s allowed a previous handler's answer", reset.name)
			}
		}()
	}
}

// Stops construction after allocation and before configuration/start. The
// normal logger is the barrier, so production needs no test-specific hook.
func startPausedPeerServer(t *testing.T) (*Device, <-chan *Peer, func()) {
	t.Helper()
	captured := make(chan *Peer, 1)
	release := make(chan struct{})
	releaseOnce := sync.OnceFunc(func() { close(release) })
	log := logger.NewLogger(logger.LogLevelError, "server: ")
	log.Verbosef = func(format string, args ...any) {
		if format == "%v - Configuring on-demand peer" {
			captured <- args[0].(*Peer)
			<-release
		}
	}
	server := startMissServerWithLogger(t, bindtest.NewChannelBinds()[0], nil, log)
	t.Cleanup(releaseOnce)
	return server.dev, captured, releaseOnce
}

// Waits until the competing operation either finishes or is actually blocked
// on a mutex. A held configuration barrier fixes the schedule; stack sampling
// only observes arrival at that barrier, without a sleep or timing assertion.
func awaitPeerOperationBarrier(t *testing.T, done <-chan struct{}, method string) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	stack := make([]byte, 1024*1024)
	for {
		select {
		case <-done:
			return
		case <-deadline.C:
			t.Fatalf("%s neither blocked nor completed", method)
		default:
		}
		length := runtime.Stack(stack, true)
		for _, goroutine := range bytes.Split(stack[:length], []byte("\n\n")) {
			header, _, _ := bytes.Cut(goroutine, []byte("\n"))
			if bytes.Contains(header, []byte("[sync.")) && bytes.Contains(goroutine, []byte(method)) && bytes.Contains(goroutine, []byte("sync.(*RWMutex).Lock(")) {
				return
			}
		}
		runtime.Gosched()
	}
}

// A removal racing construction must join the started peer, including both
// packet routines, rather than stop an unstarted peer that subsequently runs.
func TestPeerMissRemovalJoinsCreatingPeer(t *testing.T) {
	dev, captured, release := startPausedPeerServer(t)
	_, key := missKeyPair(t)
	defer release()
	created := make(chan error, 1)
	go func() {
		_, err := dev.AddPeerOnDemand(key, PeerMissConfig{})
		created <- err
	}()
	peer := awaitPeerResult(t, captured)
	removed := make(chan struct{})
	go func() {
		dev.RemovePeer(key)
		close(removed)
	}()
	awaitPeerOperationBarrier(t, removed, "(*Device).RemovePeer(")
	release()
	if err := awaitPeerResult(t, created); err != nil {
		t.Fatal(err)
	}
	awaitPeerResult(t, removed)
	defer peer.Stop()
	if peer.isRunning.Load() || dev.LookupPeer(key) != nil {
		t.Fatal("removed peer started after removal and escaped device ownership")
	}
}

// A second creator must return only after the first peer has its route,
// preshared key and packet routines. Packet lookup must not see partial state.
func TestPeerMissConcurrentCreateWaitsForConfiguration(t *testing.T) {
	dev, captured, release := startPausedPeerServer(t)
	_, key := missKeyPair(t)
	_, presharedKeyBytes := missKeyPair(t)
	presharedKey := NoisePresharedKey(presharedKeyBytes)
	prefix := netip.MustParsePrefix("192.0.2.3/32")
	config := PeerMissConfig{PresharedKey: &presharedKey, AllowedIPs: []netip.Prefix{prefix}}
	defer release()
	created := make(chan error, 1)
	go func() {
		_, err := dev.AddPeerOnDemand(key, config)
		created <- err
	}()
	first := awaitPeerResult(t, captured)
	if dev.LookupPeer(key) != nil {
		t.Error("packet lookup exposed an unconfigured peer")
	}
	ready := make(chan struct{})
	var second *Peer
	var secondErr error
	var running bool
	var configuredPresharedKey NoisePresharedKey
	var route *Peer
	go func() {
		second, secondErr = dev.AddPeerOnDemand(key, config)
		if second != nil {
			running = second.isRunning.Load()
			second.handshake.mutex.RLock()
			configuredPresharedKey = second.handshake.presharedKey
			second.handshake.mutex.RUnlock()
			route = dev.allowedips.Lookup(prefix.Addr().AsSlice())
		}
		close(ready)
	}()
	awaitPeerOperationBarrier(t, ready, "(*Device).AddPeerOnDemand(")
	release()
	if err := awaitPeerResult(t, created); err != nil {
		t.Fatal(err)
	}
	awaitPeerResult(t, ready)
	if secondErr != nil || second != first || !running || configuredPresharedKey != presharedKey || route != first {
		t.Fatalf("concurrent creation returned incomplete peer: err=%v same=%t running=%t psk=%t route=%t",
			secondErr, second == first, running, configuredPresharedKey == presharedKey, route == first)
	}
}
