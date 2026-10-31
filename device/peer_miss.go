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

	"github.com/urnetwork/userwireguard/v2026/conn"
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
// answer that arrives later is still applied unless configuration changes
// invalidated it, so the client's next initiation (sent after RekeyTimeout)
// finds the peer. A handler that panics refuses the key without caching it.
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

// Returns the default limits for resolving unknown peer keys.
func DefaultPeerMissSettings() *PeerMissSettings {
	return &PeerMissSettings{
		NegativeTtl:        10 * time.Second,
		NegativeMaxEntries: 64 * 1024,
		RatePerSecond:      1024,
		Burst:              2048,
		HandlerTimeout:     100 * time.Millisecond,
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

// Identifies one handler call, including its authority to install a peer.
type peerMissResolution struct {
	done chan bool
}

// Tracks resolution ownership, rate limits and remembered refusals.
type peerMissState struct {
	enabled atomic.Bool

	stateLock sync.Mutex
	settings  PeerMissSettings
	now       func() time.Time
	// refusal expiry by key
	refused   map[NoisePublicKey]time.Time
	lastPurge time.Time
	// keys whose handler call has not finished
	publicKeyResolutions map[NoisePublicKey]*peerMissResolution
	tokens               float64
	refilled             time.Time

	acceptedCount         atomic.Uint64
	refusedCount          atomic.Uint64
	negativeCacheHitCount atomic.Uint64
	coalescedCount        atomic.Uint64
	rateLimitedCount      atomic.Uint64
	handlerFailureCount   atomic.Uint64
	handlerTimeoutCount   atomic.Uint64
	createFailureCount    atomic.Uint64
}

// Reads the clock used for refusal expiry and rate limits.
func (self *peerMissState) clock() time.Time {
	if self.now != nil {
		return self.now()
	}
	return time.Now()
}

// Returns the token bucket capacity while the state lock is held.
func (self *peerMissState) burstWithLock() float64 {
	if 0 < self.settings.Burst {
		return float64(self.settings.Burst)
	}
	return max(1, self.settings.RatePerSecond)
}

// Admits one handler call against the rate while the state lock is held.
func (self *peerMissState) takeTokenWithLock(now time.Time) bool {
	if self.settings.RatePerSecond <= 0 {
		return true
	}
	burst := self.burstWithLock()
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

// Remembers a refusal within the entry bound while the state lock is held. Expired refusals
// are purged at most once a second; a full cache past that drops an arbitrary
// entry, which keeps every insertion constant time.
func (self *peerMissState) refuseWithLock(publicKey NoisePublicKey, now time.Time) {
	if self.settings.NegativeTtl <= 0 {
		return
	}
	maxEntries := self.settings.NegativeMaxEntries
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
// and the call budget start over. Pending answers from the previous handler
// are discarded.
func (self *Device) SetPeerMissSettings(settings *PeerMissSettings) {
	self.ipcMutex.Lock()
	defer self.ipcMutex.Unlock()
	state := &self.peerMiss
	state.stateLock.Lock()
	defer state.stateLock.Unlock()
	if settings == nil {
		state.settings = PeerMissSettings{}
	} else {
		state.settings = *settings
	}
	defaults := DefaultPeerMissSettings()
	if state.settings.HandlerTimeout <= 0 {
		state.settings.HandlerTimeout = defaults.HandlerTimeout
	}
	if state.settings.NegativeMaxEntries <= 0 {
		state.settings.NegativeMaxEntries = defaults.NegativeMaxEntries
	}
	state.refused = map[NoisePublicKey]time.Time{}
	state.publicKeyResolutions = map[NoisePublicKey]*peerMissResolution{}
	state.refilled = state.clock()
	state.tokens = state.burstWithLock()
	state.enabled.Store(state.settings.Handler != nil)
}

// ClearPeerMissRefusal forgets a remembered refusal for the key, so the next
// initiation from it asks the handler again. An owner calls this when it
// starts accepting a key. Pending answers for the old configuration are
// discarded as well, so an earlier refusal cannot replace this decision.
func (self *Device) ClearPeerMissRefusal(publicKey NoisePublicKey) {
	self.ipcMutex.Lock()
	defer self.ipcMutex.Unlock()
	self.invalidatePeerMissWithLock(publicKey)
}

// Invalidates a key's pending answer and refusal while the configuration lock is held.
func (self *Device) invalidatePeerMissWithLock(publicKey NoisePublicKey) {
	state := &self.peerMiss
	state.stateLock.Lock()
	defer state.stateLock.Unlock()
	delete(state.refused, publicKey)
	delete(state.publicKeyResolutions, publicKey)
}

// Invalidates all pending answers and refusals while the configuration lock is held.
func (self *Device) invalidatePeerMissesWithLock() {
	state := &self.peerMiss
	state.stateLock.Lock()
	defer state.stateLock.Unlock()
	state.refused = map[NoisePublicKey]time.Time{}
	state.publicKeyResolutions = map[NoisePublicKey]*peerMissResolution{}
}

// Returns cumulative resolution counters.
func (self *Device) PeerMissStats() PeerMissStats {
	state := &self.peerMiss
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
func (self *Device) resolvePeerMiss(publicKey NoisePublicKey) bool {
	state := &self.peerMiss
	if !state.enabled.Load() {
		return false
	}
	if peer := self.LookupPeer(publicKey); peer != nil {
		return true
	}

	state.stateLock.Lock()
	handler := state.settings.Handler
	if handler == nil {
		state.stateLock.Unlock()
		return false
	}
	now := state.clock()
	if expiry, ok := state.refused[publicKey]; ok {
		if now.Before(expiry) {
			state.stateLock.Unlock()
			state.negativeCacheHitCount.Add(1)
			return false
		}
		delete(state.refused, publicKey)
	}
	if _, ok := state.publicKeyResolutions[publicKey]; ok {
		state.stateLock.Unlock()
		state.coalescedCount.Add(1)
		return false
	}
	if !state.takeTokenWithLock(now) {
		state.stateLock.Unlock()
		state.rateLimitedCount.Add(1)
		return false
	}
	resolution := &peerMissResolution{done: make(chan bool, 1)}
	state.publicKeyResolutions[publicKey] = resolution
	timeout := state.settings.HandlerTimeout
	state.stateLock.Unlock()

	// The resolution may apply its answer only while it owns this key. The
	// worker's timeout does not revoke that ownership; configuration does.
	go self.completePeerMiss(handler, publicKey, resolution)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case accepted := <-resolution.done:
		return accepted
	case <-timer.C:
		state.handlerTimeoutCount.Add(1)
		return false
	}
}

// completePeerMiss asks the handler and applies its answer: a peer for an
// accepted key, a remembered refusal for a refused one. The key stays in
// flight until the peer exists, so no second handler call can start for it.
func (self *Device) completePeerMiss(handler PeerMissHandler, publicKey NoisePublicKey, resolution *peerMissResolution) {
	state := &self.peerMiss
	accepted := false
	defer func() {
		resolution.done <- accepted
	}()

	config, ok, failed := callPeerMissHandler(handler, publicKey)
	self.ipcMutex.Lock()
	defer self.ipcMutex.Unlock()
	current := func() bool {
		state.stateLock.Lock()
		defer state.stateLock.Unlock()
		return state.publicKeyResolutions[publicKey] == resolution
	}()
	if !current {
		return
	}
	var createErr error
	if !failed && ok {
		_, createErr = self.addPeerOnDemandWithLock(publicKey, config)
	}

	state.stateLock.Lock()
	delete(state.publicKeyResolutions, publicKey)
	switch {
	case failed:
		state.handlerFailureCount.Add(1)
	case !ok:
		state.refusedCount.Add(1)
		state.refuseWithLock(publicKey, state.clock())
	case createErr != nil:
		state.createFailureCount.Add(1)
	default:
		state.acceptedCount.Add(1)
		accepted = true
	}
	state.stateLock.Unlock()

	if failed {
		self.log.Errorf("Peer miss handler failed for %x…", publicKey[:4])
	} else if createErr != nil {
		self.log.Errorf("Could not create on-demand peer %x…: %v", publicKey[:4], createErr)
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
func (self *Device) AddPeerOnDemand(publicKey NoisePublicKey, config PeerMissConfig) (*Peer, error) {
	self.ipcMutex.Lock()
	defer self.ipcMutex.Unlock()
	return self.addPeerOnDemandWithLock(publicKey, config)
}

// Configures and starts a peer while the configuration lock is held.
func (self *Device) addPeerOnDemandWithLock(publicKey NoisePublicKey, config PeerMissConfig) (*Peer, error) {
	if peer := self.LookupPeer(publicKey); peer != nil {
		return peer, nil
	}
	self.staticIdentity.RLock()
	own := self.staticIdentity.publicKey.Equals(publicKey)
	self.staticIdentity.RUnlock()
	if own {
		return nil, errors.New("peer key is the device's own key")
	}

	for _, prefix := range config.AllowedIPs {
		if !prefix.IsValid() {
			return nil, fmt.Errorf("invalid allowed ip %v", prefix)
		}
	}
	peer, err := self.preparePeerWithLock(publicKey)
	if err != nil {
		return nil, err
	}
	self.log.Verbosef("%v - Configuring on-demand peer", peer)
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
		self.allowedips.Insert(prefix.Masked(), peer)
	}
	handlePeerPostConfig(peer, true, pkaOn)
	self.peers.Lock()
	self.peers.keyMap[publicKey] = peer
	self.peers.Unlock()
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
func (self *Device) RemoveIdlePeers(idle time.Duration) []NoisePublicKey {
	cutoff := time.Now().Add(-idle).UnixNano()
	type candidate struct {
		key  NoisePublicKey
		peer *Peer
	}
	candidates := []candidate{}
	self.peers.RLock()
	for key, peer := range self.peers.keyMap {
		if peerLastActive(peer) < cutoff {
			candidates = append(candidates, candidate{key: key, peer: peer})
		}
	}
	self.peers.RUnlock()

	removed := []NoisePublicKey{}
	for _, c := range candidates {
		func() {
			self.ipcMutex.Lock()
			defer self.ipcMutex.Unlock()
			self.peers.Lock()
			defer self.peers.Unlock()
			// a handshake or a replacement since the scan keeps the peer
			if self.peers.keyMap[c.key] != c.peer || cutoff <= peerLastActive(c.peer) {
				return
			}
			self.invalidatePeerMissWithLock(c.key)
			removePeerWithLock(self, c.peer, c.key)
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
