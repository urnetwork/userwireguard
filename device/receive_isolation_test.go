package device

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
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
	device.log = logger.NewLogger(logger.LogLevelSilent, "")
	device.net.bind = &fakeBindSized{size: 1}
	device.tun.device = &fakeTUNDeviceSized{size: 1}
	device.PopulatePools()
	// Enable accounting even on platforms with unbounded production pools.
	// Only a handful of real elements are allocated; saturated queues below
	// contain placeholders, not pool allocations.
	device.pool.messageBuffers.max = 4096
	device.pool.inboundElements.max = 4096
	device.pool.inboundElementsContainer.max = 4096
	device.queue.decryption = &inboundQueue{
		c: make(chan *QueueInboundElementsContainer, QueueInboundSize),
	}
	return device
}

func newInboundIsolationTestPeer(device *Device) *Peer {
	peer := &Peer{device: device}
	peer.queue.inbound = &autodrainingInboundQueue{c: make(chan *QueueInboundElementsContainer, QueueInboundSize)}
	peer.isRunning.Store(true)
	return peer
}

func inboundIsolationTestContainer(device *Device, packetCount int) *QueueInboundElementsContainer {
	container := device.GetInboundElementsContainer()
	container.Lock()
	for i := 0; i < packetCount; i++ {
		elem := device.GetInboundElement()
		elem.buffer = device.GetMessageBuffer()
		elem.packet = elem.buffer[:MessageTransportSize]
		elem.packet[0] = MessageTransportType
		container.elems = append(container.elems, elem)
	}
	return container
}

func checkInboundIsolationPoolCounts(t *testing.T, device *Device, buffers, elements, containers uint32) {
	t.Helper()
	for _, check := range []struct {
		name string
		pool *WaitPool
		want uint32
	}{
		{"message buffers", device.pool.messageBuffers, buffers},
		{"inbound elements", device.pool.inboundElements, elements},
		{"inbound containers", device.pool.inboundElementsContainer, containers},
	} {
		check.pool.lock.Lock()
		got := check.pool.count
		check.pool.lock.Unlock()
		if got != check.want {
			t.Errorf("outstanding %s = %d, want %d", check.name, got, check.want)
		}
	}
}

// The queue state or held mutex triggers each bug deterministically. The timer
// only bounds a regression that blocks, and unblock lets its goroutine finish.
func dispatchInboundForTest(t *testing.T, device *Device, peer *Peer, container *QueueInboundElementsContainer, unblock func()) bool {
	t.Helper()
	done := make(chan bool, 1)
	go func() { done <- device.dispatchInboundElements(peer, container) }()
	select {
	case admitted := <-done:
		return admitted
	case <-time.After(2 * time.Second):
		unblock()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("shared receiver remained blocked after removing the test obstruction")
		}
		t.Fatal("shared receiver blocked on an unavailable peer or decryption queue")
		return false
	}
}

// One saturated peer used to block the shared UDP receive routine before it
// could service any other WireGuard peer on the same address family.
func TestFullPeerInboundQueueRefusesWithoutBlockingSharedReceiver(t *testing.T) {
	device := newInboundIsolationTestDevice()
	overloaded := newInboundIsolationTestPeer(device)
	for i := 0; i < cap(overloaded.queue.inbound.c); i++ {
		overloaded.queue.inbound.c <- &QueueInboundElementsContainer{}
	}

	container := inboundIsolationTestContainer(device, 3)
	checkInboundIsolationPoolCounts(t, device, 3, 3, 1)
	if dispatchInboundForTest(t, device, overloaded, container, func() { <-overloaded.queue.inbound.c }) {
		t.Fatal("saturated peer queue accepted another datagram batch")
	}
	if got := device.InboundPeerQueueDropPacketCount(); got != 3 {
		t.Fatalf("peer queue drop packets = %d, want 3", got)
	}
	checkInboundIsolationPoolCounts(t, device, 0, 0, 0)
	if len(device.queue.decryption.c) != 0 {
		t.Fatal("refused peer batch reached the crypto queue")
	}

	healthy := newInboundIsolationTestPeer(device)
	container = inboundIsolationTestContainer(device, 1)
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
	checkInboundIsolationPoolCounts(t, device, 0, 0, 0)
}

// A peer lifecycle transition must be a refusal boundary rather than another
// way for its shared socket reader to wait or enqueue behind the terminal nil.
func TestPeerLifecycleLockRefusesSharedReceiver(t *testing.T) {
	device := newInboundIsolationTestDevice()
	peer := newInboundIsolationTestPeer(device)
	peer.state.Lock()
	locked := true
	defer func() {
		if locked {
			peer.state.Unlock()
		}
	}()

	container := inboundIsolationTestContainer(device, 2)
	if dispatchInboundForTest(t, device, peer, container, func() {
		peer.state.Unlock()
		locked = false
	}) {
		t.Fatal("peer lifecycle transition accepted a datagram batch")
	}
	peer.state.Unlock()
	locked = false

	if got := device.InboundPeerQueueDropPacketCount(); got != 2 {
		t.Fatalf("peer lifecycle drop packets = %d, want 2", got)
	}
	if len(peer.queue.inbound.c) != 0 || len(device.queue.decryption.c) != 0 {
		t.Fatal("lifecycle-refused batch was enqueued")
	}
	checkInboundIsolationPoolCounts(t, device, 0, 0, 0)
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

	if dispatchInboundForTest(t, device, peer, container, func() { <-device.queue.decryption.c }) {
		t.Fatal("saturated decryption queue accepted another datagram batch")
	}
	if got := device.InboundDecryptionQueueDropPacketCount(); got != 4 {
		t.Fatalf("decryption queue drop packets = %d, want 4", got)
	}
	for _, elem := range container.elems {
		if elem.packet != nil {
			t.Fatal("refused batch still exposes undecrypted ciphertext to the sequential receiver")
		}
	}
	if !container.TryLock() {
		t.Fatal("refused encrypted batch remained locked without a crypto owner")
	}
	container.Unlock()
	checkInboundIsolationPoolCounts(t, device, 4, 4, 1)
	// Run the real cleanup consumer after refusal, then its shutdown marker.
	// It must skip the ciphertext and release every buffer exactly once.
	peer.queue.inbound.c <- nil
	peer.stopping.Add(1)
	peer.RoutineSequentialReceiver(1)
	peer.stopping.Wait()
	checkInboundIsolationPoolCounts(t, device, 0, 0, 0)
	if peer.rxBytes.Load() != 0 {
		t.Fatal("refused ciphertext was counted as authenticated traffic")
	}
}

func TestStoppedPeerRefusesBatchAfterTerminalMarker(t *testing.T) {
	device := newInboundIsolationTestDevice()
	peer := newInboundIsolationTestPeer(device)
	peer.isRunning.Store(false)
	peer.queue.inbound.c <- nil
	if device.dispatchInboundElements(peer, inboundIsolationTestContainer(device, 2)) {
		t.Fatal("stopped peer admitted a batch after its shutdown marker")
	}
	if len(peer.queue.inbound.c) != 1 || <-peer.queue.inbound.c != nil || len(device.queue.decryption.c) != 0 {
		t.Fatal("stopped peer changed receive queues")
	}
	if device.InboundPeerQueueDropPacketCount() != 0 || device.InboundDecryptionQueueDropPacketCount() != 0 {
		t.Fatal("normal peer shutdown was counted as queue overload")
	}
	checkInboundIsolationPoolCounts(t, device, 0, 0, 0)
}

// Exercise admission through the actual socket-receive routine. A full first
// peer must not stop it from reading the next datagram for a different peer.
func TestRoutineReceiveIncomingIsolatesFullPeerQueue(t *testing.T) {
	device := newInboundIsolationTestDevice()
	device.queue.handshake = &handshakeQueue{}
	device.indexTable.Init()
	overloaded := newInboundIsolationTestPeer(device)
	overloaded.queue.inbound.c = make(chan *QueueInboundElementsContainer, 1)
	overloaded.queue.inbound.c <- &QueueInboundElementsContainer{}
	healthy := newInboundIsolationTestPeer(device)
	for i, peer := range []*Peer{overloaded, healthy} {
		device.indexTable.table[uint32(i+1)] = IndexTableEntry{peer: peer, keypair: &Keypair{created: time.Now()}}
	}
	calls := 0
	receive := func(bufs [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		calls++
		if calls > 2 {
			return 0, net.ErrClosed
		}
		binary.LittleEndian.PutUint32(bufs[0], MessageTransportType)
		binary.LittleEndian.PutUint32(bufs[0][MessageTransportOffsetReceiver:], uint32(calls))
		sizes[0] = MessageTransportSize
		return 1, nil
	}
	device.net.stopping.Add(1)
	device.queue.decryption.wg.Add(1)
	device.queue.handshake.wg.Add(1)
	done := make(chan struct{})
	go func() {
		device.RoutineReceiveIncoming(1, receive)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		<-overloaded.queue.inbound.c
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("socket receiver did not finish after releasing the full peer queue")
		}
		t.Fatal("one full peer queue prevented reading the healthy peer's next datagram")
	}
	if calls != 3 || len(healthy.queue.inbound.c) != 1 || len(device.queue.decryption.c) != 1 {
		t.Fatalf("receive calls = %d, healthy batches = %d, crypto batches = %d", calls, len(healthy.queue.inbound.c), len(device.queue.decryption.c))
	}
	container := <-healthy.queue.inbound.c
	if <-device.queue.decryption.c != container {
		t.Fatal("healthy peer and crypto queue received different batches")
	}
	if device.InboundPeerQueueDropPacketCount() != 1 || device.ReceiveRoutineFailureCount() != 0 {
		t.Fatal("unexpected receive drop or failure counts")
	}
	container.Unlock()
	device.releaseInboundElements(container)
	checkInboundIsolationPoolCounts(t, device, 0, 0, 0)
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
	for _, receiveError := range []error{temporaryReceiveError{}, errors.New("unclassified receive failure")} {
		t.Run(receiveError.Error(), func(t *testing.T) {
			sequence := make([]error, 11)
			for i := range sequence {
				sequence[i] = receiveError
			}
			testReceiveErrorSequence(t, sequence, 10, true)
		})
	}
}

func TestSuccessfulSocketReadResetsReceiveRetryBudget(t *testing.T) {
	sequence := make([]error, 0, 22)
	for i := 0; i < 10; i++ {
		sequence = append(sequence, temporaryReceiveError{})
	}
	sequence = append(sequence, nil) // successful empty read resets deathSpiral
	for i := 0; i < 10; i++ {
		sequence = append(sequence, temporaryReceiveError{})
	}
	sequence = append(sequence, net.ErrClosed)
	testReceiveErrorSequence(t, sequence, 20, false)
}

func TestClosedSocketReceiveDoesNotCloseDeviceForRecovery(t *testing.T) {
	// Wrapped closure is normal during BindUpdate too; it must not tear down the
	// replacement bind by treating the old receiver's shutdown as a failure.
	testReceiveErrorSequence(t, []error{fmt.Errorf("old bind: %w", net.ErrClosed)}, 0, false)
}

func testReceiveErrorSequence(t *testing.T, sequence []error, wantRetries int, wantClosed bool) {
	t.Helper()
	device := newUAPIRegressionDevice(t, &fakeBindSized{size: 1})
	receiveCalls, retries := 0, 0
	receive := func([][]byte, []int, []conn.Endpoint) (int, error) {
		if receiveCalls >= len(sequence) {
			t.Fatal("receiver exceeded the supplied error sequence")
		}
		err := sequence[receiveCalls]
		receiveCalls++
		return 0, err
	}
	retryWait := func(delay time.Duration) {
		retries++
		if delay != time.Second/3 {
			t.Errorf("retry delay = %v, want %v", delay, time.Second/3)
		}
	}
	// Drive the production state machine synchronously with a controlled retry
	// waiter. No wall-clock delay or scheduler ordering triggers this failure.
	device.net.stopping.Add(1)
	device.queue.decryption.wg.Add(1)
	device.queue.handshake.wg.Add(1)
	device.routineReceiveIncoming(1, receive, retryWait)
	if receiveCalls != len(sequence) || retries != wantRetries {
		t.Fatalf("receive calls/retries = %d/%d, want %d/%d", receiveCalls, retries, len(sequence), wantRetries)
	}
	wantFailures := uint64(0)
	if wantClosed {
		wantFailures = 1
		select {
		case <-device.Wait():
		case <-time.After(5 * time.Second):
			t.Fatal("device remained alive after its socket receive retry budget was exhausted")
		}
	} else if device.isClosed() {
		t.Fatal("normal socket closure or recovered temporary errors closed the device")
	}
	if got := device.ReceiveRoutineFailureCount(); got != wantFailures {
		t.Fatalf("receive routine failures = %d, want %d", got, wantFailures)
	}
}
