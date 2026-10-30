/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/urnetwork/userwireguard/conn"
)

// On-demand peers. A device with a miss handler does not need every peer
// configured up front: when a handshake initiation decrypts to a static key
// that has no peer, the handshake worker asks the handler. An accepted key gets
// a peer created and started with the handler's configuration, and the same
// initiation is then consumed against it, so the client's first handshake
// completes without a retry. RemoveIdlePeers lets the owner evict peers that
// stopped handshaking, so the number of peers, and of their goroutines and
// queues, follows use rather than configuration.
//
// Only an initiation that passed the cookie checks reaches the handler: MAC1
// always, and under load MAC2 and the per-source rate limiter (see
// RoutineHandshake). At the handler the initiator has proven that it knows the
// device's public key, but not that it holds the private key of the static key
// it names; that proof comes with the rest of the handshake, after the peer
// exists. So a handler must only accept keys the owner would configure anyway.

// PeerMissConfig is the configuration a PeerMissHandler supplies for a key it
// accepts. The device creates the peer with exactly these settings.
type PeerMissConfig struct {
	// nil leaves the peer without a preshared key
	PresharedKey *NoisePresharedKey
	AllowedIPs   []netip.Prefix
	// seconds; 0 disables persistent keepalive
	PersistentKeepaliveInterval uint32
}

// PeerMissHandler resolves the static public key of a handshake initiation
// for which the device has no peer. ok=false refuses the key, and the refusal
// is remembered for PeerMissSettings.NegativeTtl.
//
// The handler should answer from memory. A handshake worker waits for it for
// at most PeerMissSettings.HandlerTimeout and then drops the initiation; an
// answer that arrives later is still applied, so the client's next initiation
// (sent after RekeyTimeout) finds the peer. A handler that panics refuses the
// key without the refusal being remembered.
type PeerMissHandler func(publicKey NoisePublicKey) (config PeerMissConfig, ok bool)

// PeerMissSettings configures how the device resolves initiations from keys
// it has no peer for.
type PeerMissSettings struct {
	Handler PeerMissHandler
	// how long a refused key is not asked about again; <= 0 does not
	// remember refusals
	NegativeTtl time.Duration
	// bound on remembered refusals; <= 0 is the default bound
	NegativeMaxEntries int
	// handler calls admitted per second, and the burst above that rate;
	// a nonpositive rate does not limit the calls
	RatePerSecond float64
	Burst         int
	// the longest a handshake worker waits for the handler; <= 0 is the
	// default
	HandlerTimeout time.Duration
}

const (
	defaultPeerMissNegativeMaxEntries = 1 << 16
	defaultPeerMissHandlerTimeout     = 100 * time.Millisecond
)

func DefaultPeerMissSettings() *PeerMissSettings {
	return &PeerMissSettings{
		NegativeTtl:        10 * time.Second,
		NegativeMaxEntries: defaultPeerMissNegativeMaxEntries,
		RatePerSecond:      1024,
		Burst:              2048,
		HandlerTimeout:     defaultPeerMissHandlerTimeout,
	}
}

// PeerMissStats counts the outcomes of handshake initiations from keys without
// a peer, since the device was created.
type PeerMissStats struct {
	// keys the handler accepted and the device created a peer for
	Accepted uint64
	// keys the handler refused
	Refused uint64
	// initiations dropped because their key's refusal was remembered
	NegativeCacheHits uint64
	// initiations dropped because their key was already being resolved
	Coalesced uint64
	// initiations dropped because the handler call rate was exhausted
	RateLimited uint64
	// handler calls that panicked
	HandlerFailures uint64
	// handler calls a worker stopped waiting for
	HandlerTimeouts uint64
	// accepted keys the device could not create a peer for
	CreateFailures uint64
}

type peerMissState struct {
	enabled atomic.Bool

	mutex    sync.Mutex
	settings PeerMissSettings
	now      func() time.Time
	// refusal expiry by key
	refused   map[NoisePublicKey]time.Time
	lastPurge time.Time
	// keys whose handler call has not finished
	inflight map[NoisePublicKey]struct{}
	tokens   float64
	refilled time.Time

	acceptedCount         atomic.Uint64
	refusedCount          atomic.Uint64
	negativeCacheHitCount atomic.Uint64
	coalescedCount        atomic.Uint64
	rateLimitedCount      atomic.Uint64
	handlerFailureCount   atomic.Uint64
	handlerTimeoutCount   atomic.Uint64
	createFailureCount    atomic.Uint64
}

func (self *peerMissState) clock() time.Time {
	if self.now != nil {
		return self.now()
	}
	return time.Now()
}

// burstLocked is the token bucket capacity.
func (self *peerMissState) burstLocked() float64 {
	if 0 < self.settings.Burst {
		return float64(self.settings.Burst)
	}
	return max(1, self.settings.RatePerSecond)
}

// takeTokenLocked admits one handler call against the rate.
func (self *peerMissState) takeTokenLocked(now time.Time) bool {
	if self.settings.RatePerSecond <= 0 {
		return true
	}
	burst := self.burstLocked()
	if elapsed := now.Sub(self.refilled); 0 < elapsed {
		self.tokens = min(burst, self.tokens+elapsed.Seconds()*self.settings.RatePerSecond)
	}
	self.refilled = now
	if self.tokens < 1 {
		return false
	}
	self.tokens -= 1
	return true
}

// refuseLocked remembers a refusal within the entry bound. Expired refusals
// are purged at most once a second; a full cache past that drops an arbitrary
// entry, which keeps every insertion constant time.
func (self *peerMissState) refuseLocked(publicKey NoisePublicKey, now time.Time) {
	if self.settings.NegativeTtl <= 0 {
		return
	}
	maxEntries := self.settings.NegativeMaxEntries
	if maxEntries <= 0 {
		maxEntries = defaultPeerMissNegativeMaxEntries
	}
	if maxEntries <= len(self.refused) {
		if time.Second <= now.Sub(self.lastPurge) {
			self.lastPurge = now
			for key, expiry := range self.refused {
				if !now.Before(expiry) {
					delete(self.refused, key)
				}
			}
		}
		for key := range self.refused {
			if len(self.refused) < maxEntries {
				break
			}
			delete(self.refused, key)
		}
	}
	self.refused[publicKey] = now.Add(self.settings.NegativeTtl)
}

// SetPeerMissSettings installs the miss handler and its bounds. A nil
// settings or a nil handler turns on-demand peers off. Remembered refusals
// and the call budget start over.
func (device *Device) SetPeerMissSettings(settings *PeerMissSettings) {
	state := &device.peerMiss
	state.mutex.Lock()
	defer state.mutex.Unlock()
	if settings == nil {
		state.settings = PeerMissSettings{}
	} else {
		state.settings = *settings
	}
	if state.settings.HandlerTimeout <= 0 {
		state.settings.HandlerTimeout = defaultPeerMissHandlerTimeout
	}
	state.refused = map[NoisePublicKey]time.Time{}
	if state.inflight == nil {
		state.inflight = map[NoisePublicKey]struct{}{}
	}
	state.refilled = state.clock()
	state.tokens = state.burstLocked()
	state.enabled.Store(state.settings.Handler != nil)
}

// ClearPeerMissRefusal forgets a remembered refusal for the key, so the next
// initiation from it asks the handler again. An owner calls this when it
// starts accepting a key.
func (device *Device) ClearPeerMissRefusal(publicKey NoisePublicKey) {
	state := &device.peerMiss
	state.mutex.Lock()
	defer state.mutex.Unlock()
	delete(state.refused, publicKey)
}

func (device *Device) PeerMissStats() PeerMissStats {
	state := &device.peerMiss
	return PeerMissStats{
		Accepted:          state.acceptedCount.Load(),
		Refused:           state.refusedCount.Load(),
		NegativeCacheHits: state.negativeCacheHitCount.Load(),
		Coalesced:         state.coalescedCount.Load(),
		RateLimited:       state.rateLimitedCount.Load(),
		HandlerFailures:   state.handlerFailureCount.Load(),
		HandlerTimeouts:   state.handlerTimeoutCount.Load(),
		CreateFailures:    state.createFailureCount.Load(),
	}
}

// resolvePeerMiss reports whether a peer for the key exists once the handler
// has answered. It runs on a handshake worker and holds it for at most the
// handler timeout. A refused, remembered, coalesced or rate-limited key
// reports false and the initiation is dropped; its client retries.
func (device *Device) resolvePeerMiss(publicKey NoisePublicKey) bool {
	state := &device.peerMiss
	if !state.enabled.Load() {
		return false
	}
	if peer := device.LookupPeer(publicKey); peer != nil {
		return true
	}

	state.mutex.Lock()
	handler := state.settings.Handler
	if handler == nil {
		state.mutex.Unlock()
		return false
	}
	now := state.clock()
	if expiry, ok := state.refused[publicKey]; ok {
		if now.Before(expiry) {
			state.mutex.Unlock()
			state.negativeCacheHitCount.Add(1)
			return false
		}
		delete(state.refused, publicKey)
	}
	if _, ok := state.inflight[publicKey]; ok {
		state.mutex.Unlock()
		state.coalescedCount.Add(1)
		return false
	}
	if !state.takeTokenLocked(now) {
		state.mutex.Unlock()
		state.rateLimitedCount.Add(1)
		return false
	}
	state.inflight[publicKey] = struct{}{}
	timeout := state.settings.HandlerTimeout
	state.mutex.Unlock()

	// The resolution owns the key's in-flight entry and applies the answer
	// whenever it arrives; the worker only waits for it, within the bound.
	done := make(chan bool, 1)
	go device.completePeerMiss(handler, publicKey, done)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case accepted := <-done:
		return accepted
	case <-timer.C:
		state.handlerTimeoutCount.Add(1)
		return false
	}
}

// completePeerMiss asks the handler and applies its answer: a peer for an
// accepted key, a remembered refusal for a refused one. The key stays in
// flight until the peer exists, so no second handler call can start for it.
func (device *Device) completePeerMiss(handler PeerMissHandler, publicKey NoisePublicKey, done chan<- bool) {
	state := &device.peerMiss
	accepted := false
	defer func() {
		done <- accepted
	}()

	config, ok, failed := callPeerMissHandler(handler, publicKey)
	var createErr error
	if !failed && ok {
		_, createErr = device.AddPeerOnDemand(publicKey, config)
	}

	state.mutex.Lock()
	delete(state.inflight, publicKey)
	switch {
	case failed:
		state.handlerFailureCount.Add(1)
	case !ok:
		state.refusedCount.Add(1)
		state.refuseLocked(publicKey, state.clock())
	case createErr != nil:
		state.createFailureCount.Add(1)
	default:
		state.acceptedCount.Add(1)
		accepted = true
	}
	state.mutex.Unlock()

	if failed {
		device.log.Errorf("Peer miss handler failed for %x…", publicKey[:4])
	} else if createErr != nil {
		device.log.Errorf("Could not create on-demand peer %x…: %v", publicKey[:4], createErr)
	}
}

// callPeerMissHandler contains a handler panic as a failed call.
func callPeerMissHandler(handler PeerMissHandler, publicKey NoisePublicKey) (config PeerMissConfig, ok bool, failed bool) {
	defer func() {
		if r := recover(); r != nil {
			config, ok, failed = PeerMissConfig{}, false, true
		}
	}()
	config, ok = handler(publicKey)
	return
}

// AddPeerOnDemand creates and starts a peer for the key with the given
// configuration, or returns the peer the key already has, unchanged. It is
// the miss handler's path to the device, and an owner's path for a peer it
// must reach first (for example to initiate a handshake).
func (device *Device) AddPeerOnDemand(publicKey NoisePublicKey, config PeerMissConfig) (*Peer, error) {
	// serialize with configuration and with Up/Down/Close, as IpcSet does, so
	// a peer is never created into a device that is changing state
	device.ipcMutex.RLock()
	defer device.ipcMutex.RUnlock()

	if peer := device.LookupPeer(publicKey); peer != nil {
		return peer, nil
	}
	device.staticIdentity.RLock()
	own := device.staticIdentity.publicKey.Equals(publicKey)
	device.staticIdentity.RUnlock()
	if own {
		return nil, errors.New("peer key is the device's own key")
	}

	peer, err := device.NewPeer(publicKey)
	if err != nil {
		// a concurrent creation won; its peer is the key's peer
		if existing := device.LookupPeer(publicKey); existing != nil {
			return existing, nil
		}
		return nil, err
	}
	if config.PresharedKey != nil {
		peer.handshake.mutex.Lock()
		peer.handshake.presharedKey = *config.PresharedKey
		peer.handshake.mutex.Unlock()
	}
	pkaOn := false
	if 0 < config.PersistentKeepaliveInterval {
		peer.persistentKeepaliveInterval.Store(config.PersistentKeepaliveInterval)
		pkaOn = true
	}
	for _, prefix := range config.AllowedIPs {
		if !prefix.IsValid() {
			device.RemovePeer(publicKey)
			return nil, fmt.Errorf("invalid allowed ip %v", prefix)
		}
		device.allowedips.Insert(prefix.Masked(), peer)
	}
	handlePeerPostConfig(peer, true, pkaOn)
	return peer, nil
}

// peerLastActive is the newest of a peer's creation and its newest completed
// handshake. Traffic needs keys, and keys are rejected RejectAfterTime after
// the handshake that made them, so a peer with no handshake for longer than
// that carries no traffic.
func peerLastActive(peer *Peer) int64 {
	return max(peer.createdNano.Load(), peer.lastHandshakeNano.Load())
}

// RemoveIdlePeers removes every peer whose newest completed handshake, or
// creation when it never completed one, is older than idle, and returns their
// keys. An idle bound above RejectAfterTime removes only peers that can carry
// no traffic. Each removal takes the peer lock on its own, so handshakes for
// other keys proceed between removals.
func (device *Device) RemoveIdlePeers(idle time.Duration) []NoisePublicKey {
	cutoff := time.Now().Add(-idle).UnixNano()
	type candidate struct {
		key  NoisePublicKey
		peer *Peer
	}
	candidates := []candidate{}
	device.peers.RLock()
	for key, peer := range device.peers.keyMap {
		if peerLastActive(peer) < cutoff {
			candidates = append(candidates, candidate{key: key, peer: peer})
		}
	}
	device.peers.RUnlock()

	removed := []NoisePublicKey{}
	for _, c := range candidates {
		func() {
			device.peers.Lock()
			defer device.peers.Unlock()
			// a handshake or a replacement since the scan keeps the peer
			if device.peers.keyMap[c.key] != c.peer || cutoff <= peerLastActive(c.peer) {
				return
			}
			removePeerLocked(device, c.peer, c.key)
			removed = append(removed, c.key)
		}()
	}
	return removed
}

// PeerCount is the number of peers on the device.
func (device *Device) PeerCount() int {
	device.peers.RLock()
	defer device.peers.RUnlock()
	return len(device.peers.keyMap)
}

// PeerSnapshot is one peer's identity and session facts.
type PeerSnapshot struct {
	PublicKey NoisePublicKey
	// invalid when the device has never learned or been given one
	Endpoint netip.AddrPort
	// zero when the peer has never completed a handshake
	LastHandshake time.Time
}

// PeerSnapshots reads every peer's session facts without the string encoding
// and parsing of IpcGet. Its cost follows the number of peers on the device.
func (device *Device) PeerSnapshots() []PeerSnapshot {
	device.peers.RLock()
	defer device.peers.RUnlock()
	snapshots := make([]PeerSnapshot, 0, len(device.peers.keyMap))
	for key, peer := range device.peers.keyMap {
		snapshot := PeerSnapshot{PublicKey: key}
		if nano := peer.lastHandshakeNano.Load(); nano != 0 {
			snapshot.LastHandshake = time.Unix(0, nano)
		}
		peer.endpoint.Lock()
		if endpoint := peer.endpoint.val; endpoint != nil {
			snapshot.Endpoint = endpointAddrPort(endpoint)
		}
		peer.endpoint.Unlock()
		snapshots = append(snapshots, snapshot)
	}
	return snapshots
}

func endpointAddrPort(endpoint conn.Endpoint) netip.AddrPort {
	if std, ok := endpoint.(*conn.StdNetEndpoint); ok {
		return std.AddrPort
	}
	addrPort, err := netip.ParseAddrPort(endpoint.ToString())
	if err != nil {
		return netip.AddrPort{}
	}
	return addrPort
}
