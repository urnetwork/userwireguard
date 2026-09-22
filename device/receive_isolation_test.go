package device

import (
	"testing"
	"time"

	"github.com/urnetwork/userwireguard/v2026/conn"
	"github.com/urnetwork/userwireguard/v2026/logger"
	"github.com/urnetwork/userwireguard/v2026/tun/tuntest"
)

type permanentReceiveError struct{}

func (permanentReceiveError) Error() string   { return "permanent receive failure" }
func (permanentReceiveError) Timeout() bool   { return false }
func (permanentReceiveError) Temporary() bool { return false }

type temporaryReceiveError struct{}

func (temporaryReceiveError) Error() string   { return "temporary receive failure" }
func (temporaryReceiveError) Timeout() bool   { return false }
func (temporaryReceiveError) Temporary() bool { return true }

func newInboundIsolationTestDevice() *Device {
	device := &Device{}
	device.net.bind = &fakeBindSized{size: 1}
	device.tun.device = &fakeTUNDeviceSized{size: 1}
	device.PopulatePools()
	device.queue.decryption = &inboundQueue{
		c: make(chan *QueueInboundElementsContainer, QueueInboundSize),
	}
	return device
}

func newInboundIsolationTestPeer(device *Device) *Peer {
	peer := &Peer{device: device}
	peer.queue.inbound = newAutodrainingInboundQueue(device)
	peer.isRunning.Store(true)
	return peer
}

func inboundIsolationTestContainer(device *Device, packetCount int) *QueueInboundElementsContainer {
	container := device.GetInboundElementsContainer()
	container.Lock()
	for i := 0; i < packetCount; i++ {
		elem := device.GetInboundElement()
		elem.buffer = device.GetMessageBuffer()
		container.elems = append(container.elems, elem)
	}
	return container
}

// One saturated peer used to block the shared UDP receive routine before it
// could service any other WireGuard peer on the same address family.
func TestFullPeerInboundQueueRefusesWithoutBlockingSharedReceiver(t *testing.T) {
	device := newInboundIsolationTestDevice()
	overloaded := newInboundIsolationTestPeer(device)
	for i := 0; i < cap(overloaded.queue.inbound.c); i++ {
		overloaded.queue.inbound.c <- &QueueInboundElementsContainer{}
	}

	if device.dispatchInboundElements(overloaded, inboundIsolationTestContainer(device, 3)) {
		t.Fatal("saturated peer queue accepted another datagram batch")
	}
	if got := device.InboundPeerQueueDropPacketCount(); got != 3 {
		t.Fatalf("peer queue drop packets = %d, want 3", got)
	}

	healthy := newInboundIsolationTestPeer(device)
	container := inboundIsolationTestContainer(device, 1)
	if !device.dispatchInboundElements(healthy, container) {
		t.Fatal("healthy peer was refused after an unrelated peer saturated")
	}
	if got := <-healthy.queue.inbound.c; got != container {
		t.Fatal("healthy peer received the wrong batch")
	}
	if got := <-device.queue.decryption.c; got != container {
		t.Fatal("crypto queue received the wrong healthy-peer batch")
	}
	container.Unlock()
	device.releaseInboundElements(container)
}

// A peer lifecycle transition must be a refusal boundary rather than another
// way for its shared socket reader to wait or enqueue behind the terminal nil.
func TestPeerLifecycleLockRefusesSharedReceiver(t *testing.T) {
	device := newInboundIsolationTestDevice()
	peer := newInboundIsolationTestPeer(device)
	peer.state.Lock()

	container := inboundIsolationTestContainer(device, 2)
	if device.dispatchInboundElements(peer, container) {
		t.Fatal("peer lifecycle transition accepted a datagram batch")
	}
	peer.state.Unlock()

	if got := device.InboundPeerQueueDropPacketCount(); got != 2 {
		t.Fatalf("peer lifecycle drop packets = %d, want 2", got)
	}
}

// Device-wide crypto saturation is the adjacent shared boundary. It must not
// recreate the same socket-reader stall after the per-peer queue is isolated.
func TestFullDecryptionQueueRefusesWithoutBlockingSharedReceiver(t *testing.T) {
	device := newInboundIsolationTestDevice()
	for i := 0; i < cap(device.queue.decryption.c); i++ {
		device.queue.decryption.c <- &QueueInboundElementsContainer{}
	}
	peer := newInboundIsolationTestPeer(device)
	container := inboundIsolationTestContainer(device, 4)

	if device.dispatchInboundElements(peer, container) {
		t.Fatal("saturated decryption queue accepted another datagram batch")
	}
	if got := device.InboundDecryptionQueueDropPacketCount(); got != 4 {
		t.Fatalf("decryption queue drop packets = %d, want 4", got)
	}
	if got := <-peer.queue.inbound.c; got != container {
		t.Fatal("peer cleanup received the wrong refused batch")
	}
	if !container.TryLock() {
		t.Fatal("refused encrypted batch remained locked without a crypto owner")
	}
	container.Unlock()
	device.releaseInboundElements(container)
}

// A receive goroutine used to return while leaving its UDP socket and the rest
// of the WireGuard device alive, producing an indefinitely full kernel queue.
func TestPermanentSocketReceiveFailureClosesDeviceForOwnerRecovery(t *testing.T) {
	tunDevice := tuntest.NewChannelTUN()
	// Consume the synthetic Up event before NewDevice starts its event reader;
	// this fixture drives the receive routine directly and must not race an
	// automatic BindUpdate while installing its matching WaitGroup references.
	<-tunDevice.TUN().Events()
	device := NewDevice(
		tunDevice.TUN(),
		&fakeBindSized{size: 1},
		logger.NewLogger(logger.LogLevelSilent, ""),
	)
	defer device.Close()

	receiveCalled := make(chan struct{})
	receive := func([][]byte, []int, []conn.Endpoint) (int, error) {
		close(receiveCalled)
		return 0, permanentReceiveError{}
	}
	device.net.stopping.Add(1)
	device.queue.decryption.wg.Add(1)
	device.queue.handshake.wg.Add(1)
	go device.RoutineReceiveIncoming(1, receive)

	<-receiveCalled
	select {
	case <-device.Wait():
	case <-time.After(5 * time.Second):
		t.Fatal("device remained alive after its socket receive routine failed")
	}
	if got := device.ReceiveRoutineFailureCount(); got != 1 {
		t.Fatalf("receive routine failures = %d, want 1", got)
	}
}

func TestExhaustedTemporarySocketReceiveFailuresCloseDeviceForOwnerRecovery(t *testing.T) {
	tunDevice := tuntest.NewChannelTUN()
	<-tunDevice.TUN().Events()
	device := NewDevice(
		tunDevice.TUN(),
		&fakeBindSized{size: 1},
		logger.NewLogger(logger.LogLevelSilent, ""),
	)
	defer device.Close()

	receiveCalls := make(chan struct{}, 11)
	receive := func([][]byte, []int, []conn.Endpoint) (int, error) {
		receiveCalls <- struct{}{}
		return 0, temporaryReceiveError{}
	}
	device.net.stopping.Add(1)
	device.queue.decryption.wg.Add(1)
	device.queue.handshake.wg.Add(1)
	go device.RoutineReceiveIncoming(1, receive)

	select {
	case <-device.Wait():
	case <-time.After(6 * time.Second):
		t.Fatal("device remained alive after its socket receive retry budget was exhausted")
	}
	if got := len(receiveCalls); got != 11 {
		t.Fatalf("receive calls = %d, want 11", got)
	}
	if got := device.ReceiveRoutineFailureCount(); got != 1 {
		t.Fatalf("receive routine failures = %d, want 1", got)
	}
}
