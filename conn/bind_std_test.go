package conn

import (
	"errors"
	"net"
	"testing"
)

func TestStdNetBindReceiveFuncAfterClose(t *testing.T) {
	bind := NewStdNetBind().(*StdNetBind)
	// empty bind addresses are "any", which is what the upstream Open(0) meant
	// before this fork added explicit ipv4/ipv6 bind addresses
	fns, _, err := bind.Open("", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := bind.Close(); err != nil {
		t.Fatal(err)
	}
	bufs := make([][]byte, 1)
	bufs[0] = make([]byte, 1)
	sizes := make([]int, 1)
	eps := make([]Endpoint, 1)
	for _, fn := range fns {
		// The ReceiveFuncs must not access conn-related fields on StdNetBind
		// unguarded. Close() nils the conn-related fields resulting in a panic
		// if they violate the mutex.
		if n, err := fn(bufs, sizes, eps); n != 0 || !errors.Is(err, net.ErrClosed) {
			t.Fatalf("receive after Close = (%d, %v), want (0, net.ErrClosed)", n, err)
		}
	}
}

// Ignoring the fork's bind addresses silently exposes the socket on wildcard
// interfaces. Inspect the actual listeners rather than only the stored config.
func TestStdNetBindExplicitAddressesAndSharedPort(t *testing.T) {
	bind := NewStdNetBind().(*StdNetBind)
	fns, port, err := bind.Open("127.0.0.1", "::1", 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := bind.Close(); err != nil {
			t.Error(err)
		}
	})
	if port == 0 || len(fns) == 0 {
		t.Fatalf("Open returned %d receive functions and port %d", len(fns), port)
	}
	if bind.ipv4 == nil {
		t.Fatal("IPv4 listener is missing")
	}
	wantIPv4 := net.ParseIP("127.0.0.1")
	wantIPv6 := net.ParseIP("::1")
	listeners := []*net.UDPConn{bind.ipv4, bind.ipv6}
	wantIPs := []net.IP{wantIPv4, wantIPv6}
	for i, listener := range listeners {
		// Open permits an unavailable address family; still verify every socket
		// that exists, and require the IPv4 loopback listener above.
		if listener == nil {
			continue
		}
		address := listener.LocalAddr().(*net.UDPAddr)
		if !address.IP.Equal(wantIPs[i]) || address.Port != int(port) {
			t.Errorf("listener address = %s, want %s:%d", address, wantIPs[i], port)
		}
	}
}
