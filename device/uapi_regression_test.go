package device

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/urnetwork/userwireguard/conn"
	"github.com/urnetwork/userwireguard/logger"
	"github.com/urnetwork/userwireguard/tun/tuntest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Keep the device down until the test explicitly starts it. In particular, the
// synthetic TUN's initial Up event must not race configuration or assertions.
func newUAPIRegressionDevice(t *testing.T, bind conn.Bind) *Device {
	t.Helper()
	tunDevice := tuntest.NewChannelTUN()
	<-tunDevice.TUN().Events()
	d := NewDevice(tunDevice.TUN(), bind, logger.NewLogger(logger.LogLevelSilent, ""))
	t.Cleanup(d.Close)
	return d
}

type uapiRegressionBind struct {
	fakeBindSized
	parseEndpoint func(string) (conn.Endpoint, error)
	opened        []uapiBindAddress
}

type uapiBindAddress struct {
	ipv4, ipv6 string
	port       uint16
}

func (b *uapiRegressionBind) Open(ipv4, ipv6 string, port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.opened = append(b.opened, uapiBindAddress{ipv4, ipv6, port})
	return nil, port, nil
}

func (b *uapiRegressionBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	if b.parseEndpoint != nil {
		return b.parseEndpoint(s)
	}
	return conn.NewStdNetBind().ParseEndpoint(s)
}

func newUAPIRegressionBind() *uapiRegressionBind {
	return &uapiRegressionBind{fakeBindSized: fakeBindSized{size: 1}}
}

func uapiRegressionPeer(t *testing.T, d *Device, key wgtypes.Key) *Peer {
	t.Helper()
	if err := d.IpcSet(&wgtypes.Config{Peers: []wgtypes.PeerConfig{{PublicKey: key}}}); err != nil {
		t.Fatal(err)
	}
	peer := d.LookupPeer(NoisePublicKey(key))
	if peer == nil {
		t.Fatal("configured peer is missing")
	}
	// If removal regresses, the peer is running but no longer in the device's
	// peer map. Stop it explicitly so the failing test still closes cleanly.
	t.Cleanup(peer.Stop)
	return peer
}

// Removing an active peer used to fall through to handlePeerPostConfig, which
// restarted its routines after it had been removed from the device's peer map.
func TestIpcSetRemovedPeerStaysStopped(t *testing.T) {
	d := newUAPIRegressionDevice(t, newUAPIRegressionBind())
	if err := d.Up(); err != nil {
		t.Fatal(err)
	}
	key := (wgtypes.Key{1}).PublicKey()
	peer := uapiRegressionPeer(t, d, key)
	if !peer.isRunning.Load() {
		t.Fatal("test requires a running peer before removal")
	}
	oldPrefix := netip.MustParsePrefix("192.0.2.1/32")
	d.allowedips.Insert(oldPrefix, peer)
	newPresharedKey := wgtypes.Key{2}
	newIP := net.IPv4(198, 51, 100, 1)
	err := d.IpcSet(&wgtypes.Config{Peers: []wgtypes.PeerConfig{{
		PublicKey:         key,
		Remove:            true,
		PresharedKey:      &newPresharedKey,
		ReplaceAllowedIPs: true,
		AllowedIPs:        []net.IPNet{{IP: newIP, Mask: net.CIDRMask(32, 32)}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if peer.isRunning.Load() {
		t.Error("removed peer's routines were restarted by post-configuration handling")
	}
	if d.LookupPeer(NoisePublicKey(key)) != nil {
		t.Error("removed peer remains in the peer map")
	}
	if d.allowedips.Lookup(oldPrefix.Addr().AsSlice()) != nil {
		t.Error("removed peer retained its old route")
	}
	if d.allowedips.Lookup(newIP.To4()) != nil {
		t.Error("configuration after Remove installed a route to the removed peer")
	}
	peer.handshake.mutex.RLock()
	presharedKey := peer.handshake.presharedKey
	peer.handshake.mutex.RUnlock()
	if presharedKey != (NoisePresharedKey{}) {
		t.Error("configuration after Remove changed the removed peer's preshared key")
	}
}

func TestIpcSetRemoveIgnoresFollowingEndpoint(t *testing.T) {
	bind := newUAPIRegressionBind()
	d := newUAPIRegressionDevice(t, bind)
	key := (wgtypes.Key{1}).PublicKey()
	uapiRegressionPeer(t, d, key)
	bind.parseEndpoint = func(string) (conn.Endpoint, error) {
		t.Error("endpoint after Remove was parsed")
		return nil, errors.New("endpoint must be ignored after Remove")
	}
	if err := d.IpcSet(&wgtypes.Config{Peers: []wgtypes.PeerConfig{{
		PublicKey: key, Remove: true,
		Endpoint: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 51820},
	}}}); err != nil {
		t.Fatal(err)
	}
}

// The endpoint mutex used to be deferred until the entire IpcSet returned.
// Inspect it at the second ParseEndpoint call, before the old implementation
// would self-deadlock trying to acquire it again. Returning an error on that
// path lets the regression fail immediately and release the deferred mutex.
func TestIpcSetRepeatedPeerEndpointReleasesLock(t *testing.T) {
	bind := newUAPIRegressionBind()
	d := newUAPIRegressionDevice(t, bind)
	key := (wgtypes.Key{1}).PublicKey()
	peer := uapiRegressionPeer(t, d, key)
	parseCalls := 0
	bind.parseEndpoint = func(s string) (conn.Endpoint, error) {
		parseCalls++
		if !peer.endpoint.TryLock() {
			return nil, errors.New("previous peer block still holds the endpoint mutex")
		}
		peer.endpoint.Unlock()
		return conn.NewStdNetBind().ParseEndpoint(s)
	}
	first := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 51820}
	last := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 51821}
	err := d.IpcSet(&wgtypes.Config{Peers: []wgtypes.PeerConfig{
		{PublicKey: key, Endpoint: first},
		{PublicKey: key, Endpoint: last},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if parseCalls != 2 {
		t.Fatalf("endpoint parse calls = %d, want 2", parseCalls)
	}
	if got := peer.endpoint.val.ToString(); got != last.String() {
		t.Fatalf("endpoint = %s, want last configured endpoint %s", got, last)
	}
}

// Hand-built IP:port formatting rejected IPv6 and discarded scoped IPv6 zones.
func TestIpcSetEndpointAddressFamilies(t *testing.T) {
	for _, address := range []string{"192.0.2.1:51820", "[2001:db8::1]:51820", "[fe80::1%testzone]:51820"} {
		t.Run(address, func(t *testing.T) {
			d := newUAPIRegressionDevice(t, newUAPIRegressionBind())
			key := (wgtypes.Key{1}).PublicKey()
			endpoint := net.UDPAddrFromAddrPort(netip.MustParseAddrPort(address))
			if err := d.IpcSet(&wgtypes.Config{Peers: []wgtypes.PeerConfig{{PublicKey: key, Endpoint: endpoint}}}); err != nil {
				t.Fatal(err)
			}
			peer := d.LookupPeer(NoisePublicKey(key))
			if got := peer.endpoint.val.ToString(); got != address {
				t.Fatalf("stored endpoint = %s, want %s", got, address)
			}
			config, err := d.IpcGet()
			if err != nil {
				t.Fatal(err)
			}
			if len(config.Peers) != 1 || config.Peers[0].Endpoint.String() != address {
				t.Fatalf("endpoint did not survive IpcSet/IpcGet: %+v", config.Peers)
			}
		})
	}
}

type uapiMalformedEndpoint struct{ conn.Endpoint }

func (uapiMalformedEndpoint) ToString() string { return "[invalid" }

func TestIpcGetEndpointParseErrorReleasesLock(t *testing.T) {
	d := newUAPIRegressionDevice(t, newUAPIRegressionBind())
	peer := uapiRegressionPeer(t, d, (wgtypes.Key{1}).PublicKey())
	peer.endpoint.val = uapiMalformedEndpoint{}
	if _, err := d.IpcGet(); err == nil {
		t.Fatal("malformed endpoint was accepted")
	}
	if !peer.endpoint.TryLock() {
		// Release the mutex leaked by the regression before running cleanup.
		peer.endpoint.Unlock()
		t.Fatal("IpcGet error left the peer endpoint mutex locked")
	}
	peer.endpoint.val = nil
	peer.endpoint.Unlock()
	if _, err := d.IpcGet(); err != nil {
		t.Fatalf("IpcGet after clearing the invalid endpoint: %v", err)
	}
}

func TestIpcSetBindAddressesReachOpen(t *testing.T) {
	bind := newUAPIRegressionBind()
	d := newUAPIRegressionDevice(t, bind)
	ipv4, ipv6, port := "192.0.2.1", "2001:db8::1", 51820
	if err := d.IpcSet2(&Config{BindIpv4: &ipv4, BindIpv6: &ipv6, Config: wgtypes.Config{ListenPort: &port}}); err != nil {
		t.Fatal(err)
	}
	if len(bind.opened) != 0 {
		t.Fatal("down device opened its bind")
	}
	if err := d.Up(); err != nil {
		t.Fatal(err)
	}
	want := uapiBindAddress{ipv4, ipv6, uint16(port)}
	if len(bind.opened) != 1 || bind.opened[0] != want {
		t.Fatalf("Open calls = %+v, want %+v", bind.opened, want)
	}
	newIPv6 := "2001:db8::2"
	if err := d.IpcSet2(&Config{BindIpv6: &newIPv6}); err != nil {
		t.Fatal(err)
	}
	want.ipv6 = newIPv6
	if len(bind.opened) != 2 || bind.opened[1] != want {
		t.Fatalf("Open calls after IPv6-only update = %+v, want final %+v", bind.opened, want)
	}
}
