/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/urnetwork/userwireguard/conn"
	"github.com/urnetwork/userwireguard/logger"
	"github.com/urnetwork/userwireguard/ratelimiter"
	"github.com/urnetwork/userwireguard/tun"
)

type Device struct {
	state struct {
		// state holds the device's state. It is accessed atomically.
		// Use the device.deviceState method to read it.
		// device.deviceState does not acquire the mutex, so it captures only a snapshot.
		// During state transitions, the state variable is updated before the device itself.
		// The state is thus either the current state of the device or
		// the intended future state of the device.
		// For example, while executing a call to Up, state will be deviceStateUp.
		// There is no guarantee that that intended future state of the device
		// will become the actual state; Up can fail.
		// The device can also change state multiple times between time of check and time of use.
		// Unsynchronized uses of state must therefore be advisory/best-effort only.
		state atomic.Uint32 // actually a deviceState, but typed uint32 for convenience
		// stopping blocks until all inputs to Device have been closed.
		stopping sync.WaitGroup
		// mu protects state changes.
		sync.Mutex
	}

	net struct {
		stopping sync.WaitGroup
		sync.RWMutex
		bind          conn.Bind // bind interface
		bindIpv4      string
		bindIpv6      string
		port          uint16 // listening port
		fwmark        uint32 // mark value (0 = disabled)
		brokenRoaming bool
	}

	staticIdentity struct {
		sync.RWMutex
		privateKey NoisePrivateKey
		publicKey  NoisePublicKey
	}

	peers struct {
		sync.RWMutex // protects keyMap
		keyMap       map[NoisePublicKey]*Peer
	}

	rate struct {
		underLoadUntil atomic.Int64
		limiter        ratelimiter.Ratelimiter
	}

	receive struct {
		peerQueueDropPacketCount       atomic.Uint64
		decryptionQueueDropPacketCount atomic.Uint64
		routineFailureCount            atomic.Uint64
	}

	allowedips    AllowedIPs
	indexTable    IndexTable
	cookieChecker CookieChecker

	peerMiss peerMissState

	pool struct {
		inboundElementsContainer  *WaitPool
		outboundElementsContainer *WaitPool
		messageBuffers            *WaitPool
		inboundElements           *WaitPool
		outboundElements          *WaitPool
	}

	queue struct {
		encryption *outboundQueue
		decryption *inboundQueue
		handshake  *handshakeQueue
	}

	tun struct {
		device tun.Device
		mtu    atomic.Int32
	}

	// Serializes complete peer configuration, miss-result installation and
	// removal. Packet lookup never takes this lock.
	ipcMutex sync.RWMutex
	closed   chan struct{}
	log      *logger.Logger
}

// deviceState represents the state of a Device.
// There are three states: down, up, closed.
// Transitions:
//
//	down -----+
//	  ↑↓      ↓
//	  up -> closed
type deviceState uint32

//go:generate go run golang.org/x/tools/cmd/stringer -type deviceState -trimprefix=deviceState
const (
	deviceStateDown deviceState = iota
	deviceStateUp
	deviceStateClosed
)

// deviceState returns device.state.state as a deviceState
// See those docs for how to interpret this value.
func (device *Device) deviceState() deviceState {
	return deviceState(device.state.state.Load())
}

// isClosed reports whether the device is closed (or is closing).
// See device.state.state comments for how to interpret this value.
func (device *Device) isClosed() bool {
	return device.deviceState() == deviceStateClosed
}

// isUp reports whether the device is up (or is attempting to come up).
// See device.state.state comments for how to interpret this value.
func (device *Device) isUp() bool {
	return device.deviceState() == deviceStateUp
}

// Stops and removes a peer while the configuration and peer-map locks are held.
func removePeerWithLock(device *Device, peer *Peer, key NoisePublicKey) {
	// stop routing and processing of packets
	device.allowedips.RemoveByPeer(peer)
	peer.Stop()

	// remove from peer map
	delete(device.peers.keyMap, key)
}

// changeState attempts to change the device state to match want.
func (self *Device) changeState(want deviceState) (err error) {
	self.state.Lock()
	defer self.state.Unlock()
	self.ipcMutex.Lock()
	defer self.ipcMutex.Unlock()
	old := self.deviceState()
	if old == deviceStateClosed {
		// once closed, always closed
		self.log.Verbosef("Interface closed, ignored requested state %s", want)
		return nil
	}
	switch want {
	case old:
		return nil
	case deviceStateUp:
		self.state.state.Store(uint32(deviceStateUp))
		err = self.upWithLock()
		if err == nil {
			break
		}
		fallthrough // up failed; bring the device all the way back down
	case deviceStateDown:
		self.state.state.Store(uint32(deviceStateDown))
		errDown := self.downWithLock()
		if err == nil {
			err = errDown
		}
	}
	self.log.Verbosef("Interface state was %s, requested %s, now %s", old, want, self.deviceState())
	return
}

// Brings the device up with the state and configuration locks held.
func (self *Device) upWithLock() error {
	if err := self.BindUpdate(); err != nil {
		self.log.Errorf("Unable to update bind: %v", err)
		return err
	}

	self.peers.RLock()
	for _, peer := range self.peers.keyMap {
		peer.Start()
		if peer.persistentKeepaliveInterval.Load() > 0 {
			peer.SendKeepalive()
		}
	}
	self.peers.RUnlock()
	return nil
}

// Brings the device down with the state and configuration locks held.
func (self *Device) downWithLock() error {
	err := self.BindClose()
	if err != nil {
		self.log.Errorf("Bind close failed: %v", err)
	}

	self.peers.RLock()
	for _, peer := range self.peers.keyMap {
		peer.Stop()
	}
	self.peers.RUnlock()
	return err
}

func (device *Device) Up() error {
	return device.changeState(deviceStateUp)
}

func (device *Device) Down() error {
	return device.changeState(deviceStateDown)
}

func (device *Device) IsUnderLoad() bool {
	// check if currently under load
	now := time.Now()
	underLoad := len(device.queue.handshake.c) >= QueueHandshakeSize/8
	if underLoad {
		device.rate.underLoadUntil.Store(now.Add(UnderLoadAfterTime).UnixNano())
		return true
	}
	// check if recently under load
	return device.rate.underLoadUntil.Load() > now.UnixNano()
}

// InboundPeerQueueDropPacketCount reports encrypted-datagram admission drops
// made to keep one overloaded peer from parking the shared socket receiver.
func (device *Device) InboundPeerQueueDropPacketCount() uint64 {
	return device.receive.peerQueueDropPacketCount.Load()
}

// InboundDecryptionQueueDropPacketCount reports ingress packets refused when
// the device-global crypto workers had no queue capacity. Refusal keeps CPU
// saturation from parking either shared socket receiver.
func (device *Device) InboundDecryptionQueueDropPacketCount() uint64 {
	return device.receive.decryptionQueueDropPacketCount.Load()
}

// ReceiveRoutineFailureCount reports socket receive routines which ended on
// an unexpected error and forced the device to close for owner-level recovery.
func (device *Device) ReceiveRoutineFailureCount() uint64 {
	return device.receive.routineFailureCount.Load()
}

// Changes the device identity without overlapping peer configuration.
func (self *Device) SetPrivateKey(sk NoisePrivateKey) error {
	self.ipcMutex.Lock()
	defer self.ipcMutex.Unlock()
	return self.setPrivateKeyWithLock(sk)
}

// Changes the identity with the configuration lock held.
func (self *Device) setPrivateKeyWithLock(sk NoisePrivateKey) error {
	// lock required resources

	self.staticIdentity.Lock()
	defer self.staticIdentity.Unlock()

	if sk.Equals(self.staticIdentity.privateKey) {
		return nil
	}
	self.invalidatePeerMissesWithLock()

	self.peers.Lock()
	defer self.peers.Unlock()

	lockedPeers := make([]*Peer, 0, len(self.peers.keyMap))
	for _, peer := range self.peers.keyMap {
		peer.handshake.mutex.RLock()
		lockedPeers = append(lockedPeers, peer)
	}

	// remove peers with matching public keys

	publicKey := sk.publicKey()
	for key, peer := range self.peers.keyMap {
		if peer.handshake.remoteStatic.Equals(publicKey) {
			peer.handshake.mutex.RUnlock()
			removePeerWithLock(self, peer, key)
			peer.handshake.mutex.RLock()
		}
	}

	// update key material

	self.staticIdentity.privateKey = sk
	self.staticIdentity.publicKey = publicKey
	self.cookieChecker.Init(publicKey)

	// do static-static DH pre-computations

	expiredPeers := make([]*Peer, 0, len(self.peers.keyMap))
	for _, peer := range self.peers.keyMap {
		handshake := &peer.handshake
		handshake.precomputedStaticStatic, _ = self.staticIdentity.privateKey.sharedSecret(handshake.remoteStatic)
		expiredPeers = append(expiredPeers, peer)
	}

	for _, peer := range lockedPeers {
		peer.handshake.mutex.RUnlock()
	}
	for _, peer := range expiredPeers {
		peer.ExpireCurrentKeypairs()
	}

	return nil
}

func NewDevice(tunDevice tun.Device, bind conn.Bind, logger *logger.Logger) *Device {
	device := new(Device)
	device.state.state.Store(uint32(deviceStateDown))
	device.closed = make(chan struct{})
	device.log = logger
	device.net.bind = bind
	device.tun.device = tunDevice
	mtu := device.tun.device.MTU()
	if mtu < 0 {
		device.log.Errorf("Negative MTU %d, assuming default %d", mtu, DefaultMTU)
		mtu = DefaultMTU
	}
	device.tun.mtu.Store(int32(mtu))
	device.peers.keyMap = make(map[NoisePublicKey]*Peer)
	device.rate.limiter.Init()
	device.indexTable.Init()

	device.PopulatePools()

	// create queues

	device.queue.handshake = newHandshakeQueue()
	device.queue.encryption = newOutboundQueue()
	device.queue.decryption = newInboundQueue()

	// start workers

	cpus := runtime.NumCPU()
	device.state.stopping.Wait()
	device.queue.encryption.wg.Add(cpus) // One for each RoutineHandshake
	for i := 0; i < cpus; i++ {
		go device.RoutineEncryption(i + 1)
		go device.RoutineDecryption(i + 1)
		go device.RoutineHandshake(i + 1)
	}

	device.state.stopping.Add(1)      // RoutineReadFromTUN
	device.queue.encryption.wg.Add(1) // RoutineReadFromTUN
	go device.RoutineReadFromTUN()
	go device.RoutineTUNEventReader()

	return device
}

// BatchSize returns the BatchSize for the device as a whole which is the max of
// the bind batch size and the tun batch size. The batch size reported by device
// is the size used to construct memory pools, and is the allowed batch size for
// the lifetime of the device.
func (device *Device) BatchSize() int {
	size := device.net.bind.BatchSize()
	dSize := device.tun.device.BatchSize()
	if size < dSize {
		size = dSize
	}
	return size
}

func (device *Device) LookupPeer(pk NoisePublicKey) *Peer {
	device.peers.RLock()
	defer device.peers.RUnlock()

	return device.peers.keyMap[pk]
}

// Removes a peer and invalidates pending resolutions, even if no peer exists yet.
func (self *Device) RemovePeer(key NoisePublicKey) {
	self.ipcMutex.Lock()
	defer self.ipcMutex.Unlock()
	self.removePeerWithLock(key)
}

// Removes one generation with the configuration lock held.
func (self *Device) removePeerWithLock(key NoisePublicKey) {
	self.invalidatePeerMissWithLock(key)
	self.peers.Lock()
	defer self.peers.Unlock()
	// stop peer and remove from routing

	peer, ok := self.peers.keyMap[key]
	if ok {
		removePeerWithLock(self, peer, key)
	}
}

// Removes all peers and invalidates resolutions started before the removal.
func (self *Device) RemoveAllPeers() {
	self.ipcMutex.Lock()
	defer self.ipcMutex.Unlock()
	self.removeAllPeersWithLock()
}

// Removes all generations with the configuration lock held.
func (self *Device) removeAllPeersWithLock() {
	self.invalidatePeerMissesWithLock()
	self.peers.Lock()
	defer self.peers.Unlock()

	for key, peer := range self.peers.keyMap {
		removePeerWithLock(self, peer, key)
	}

	self.peers.keyMap = make(map[NoisePublicKey]*Peer)
}

func (self *Device) Close() {
	self.state.Lock()
	defer self.state.Unlock()
	self.ipcMutex.Lock()
	defer self.ipcMutex.Unlock()
	if self.isClosed() {
		return
	}
	self.state.state.Store(uint32(deviceStateClosed))
	self.log.Verbosef("Device closing")

	self.tun.device.Close()
	self.downWithLock()

	// Remove peers before closing queues,
	// because peers assume that queues are active.
	self.removeAllPeersWithLock()

	// We kept a reference to the encryption and decryption queues,
	// in case we started any new peers that might write to them.
	// No new peers are coming; we are done with these queues.
	self.queue.encryption.wg.Done()
	self.queue.decryption.wg.Done()
	self.queue.handshake.wg.Done()
	self.state.stopping.Wait()

	self.rate.limiter.Close()

	self.log.Verbosef("Device closed")
	close(self.closed)
}

func (device *Device) Wait() chan struct{} {
	return device.closed
}

func (device *Device) SendKeepalivesToPeersWithCurrentKeypair() {
	if !device.isUp() {
		return
	}

	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.keypairs.RLock()
		sendKeepalive := peer.keypairs.current != nil && !peer.keypairs.current.created.Add(RejectAfterTime).Before(time.Now())
		peer.keypairs.RUnlock()
		if sendKeepalive {
			peer.SendKeepalive()
		}
	}
	device.peers.RUnlock()
}

// closeBindLocked closes the device's net.bind.
// The caller must hold the net mutex.
func closeBindLocked(device *Device) error {
	var err error
	netc := &device.net
	if netc.bind != nil {
		err = netc.bind.Close()
	}
	netc.stopping.Wait()
	return err
}

func (device *Device) Bind() conn.Bind {
	device.net.Lock()
	defer device.net.Unlock()
	return device.net.bind
}

func (device *Device) BindSetMark(mark uint32) error {
	device.net.Lock()
	defer device.net.Unlock()

	// check if modified
	if device.net.fwmark == mark {
		return nil
	}

	// update fwmark on existing bind
	device.net.fwmark = mark
	if device.isUp() && device.net.bind != nil {
		device.log.Verbosef("Setting fwmark is not supported.")
		if err := device.net.bind.SetMark(mark); err != nil {
			return err
		}
	}

	return nil
}

func (device *Device) BindUpdate() error {
	device.net.Lock()
	defer device.net.Unlock()

	// close existing sockets
	if err := closeBindLocked(device); err != nil {
		return err
	}

	// open new sockets
	if !device.isUp() {
		return nil
	}

	// bind to new port
	var err error
	var recvFns []conn.ReceiveFunc
	netc := &device.net

	recvFns, netc.port, err = netc.bind.Open(netc.bindIpv4, netc.bindIpv6, netc.port)
	if err != nil {
		netc.port = 0
		return err
	}

	// set fwmark
	if netc.fwmark != 0 {
		err = netc.bind.SetMark(netc.fwmark)
		if err != nil {
			return err
		}
	}

	// start receiving routines
	device.net.stopping.Add(len(recvFns))
	device.queue.decryption.wg.Add(len(recvFns)) // each RoutineReceiveIncoming goroutine writes to device.queue.decryption
	device.queue.handshake.wg.Add(len(recvFns))  // each RoutineReceiveIncoming goroutine writes to device.queue.handshake
	batchSize := netc.bind.BatchSize()
	for _, fn := range recvFns {
		go device.RoutineReceiveIncoming(batchSize, fn)
	}

	device.log.Verbosef("UDP bind has been updated")
	return nil
}

func (device *Device) BindClose() error {
	device.net.Lock()
	err := closeBindLocked(device)
	device.net.Unlock()
	return err
}
