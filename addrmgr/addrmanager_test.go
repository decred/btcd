// Copyright (c) 2013-2014 The btcsuite developers
// Copyright (c) 2015-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package addrmgr

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// Put some IP in here for convenience. Points to google.
var someIP = "173.194.115.66"

// addAddressByIP is a convenience function that adds an address from an ip
// address string and port, rather than a wire.NetAddress.
func (a *AddrManager) addAddressByIP(addr string, port uint16) {
	ip := net.ParseIP(addr)
	na := NewNetAddress(ip, port, 0)
	a.addOrUpdateAddress(na, na)
}

// TestStartStop tests the behavior of the address manager when it is started
// and stopped.
func TestStartStop(t *testing.T) {
	dir, err := ioutil.TempDir("", "teststartstop")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	// Ensure the peers file does not exist before starting the address manager.
	peersFile := filepath.Join(dir, peersFilename)
	if _, err := os.Stat(peersFile); !os.IsNotExist(err) {
		t.Fatalf("peers file exists though it should not: %s", peersFile)
	}

	amgr := New(dir)
	amgr.Start()

	// Add single network address to the address manager.
	amgr.addAddressByIP(someIP, 8333)

	// Stop the address manager to force the known addresses to be flushed
	// to the peers file.
	if err := amgr.Stop(); err != nil {
		t.Fatalf("address manager failed to stop: %v", err)
	}

	// Verify that the the peers file has been written to.
	if _, err := os.Stat(peersFile); err != nil {
		t.Fatalf("peers file does not exist: %s", peersFile)
	}

	// Start a new address manager, which initializes it from the peers file.
	amgr = New(dir)
	amgr.Start()

	knownAddress := amgr.GetAddress()
	if knownAddress == nil {
		t.Fatal("address manager should contain known address")
	}

	// Verify that the known address matches what was added to the address
	// manager previously.
	wantNetAddrKey := someIP + ":8333"
	gotNetAddrKey := knownAddress.na.Key()
	if gotNetAddrKey != wantNetAddrKey {
		t.Fatal("address manager does not contain expected address -- "+
			"got %v, want %v", gotNetAddrKey, wantNetAddrKey)
	}

	if err := amgr.Stop(); err != nil {
		t.Fatalf("address manager failed to stop: %v", err)
	}
}

func TestAddOrUpdateAddress(t *testing.T) {
	amgr := New("testaddaddressupdate")
	amgr.Start()
	if ka := amgr.GetAddress(); ka != nil {
		t.Fatal("Address Manager should contain no addresses")
	}
	ip := net.ParseIP(someIP)
	if ip == nil {
		t.Fatalf("Invalid IP address %s", someIP)
	}
	na := NewNetAddress(net.ParseIP(someIP), 8333, 0)
	amgr.addOrUpdateAddress(na, na)
	ka := amgr.GetAddress()
	if ka == nil {
		t.Fatal("Address Manager should contain known address")
	}
	if !reflect.DeepEqual(ka.NetAddress(), na) {
		t.Fatal("Address Manager should contain address that was added")
	}
	// add address again, but with different time stamp (to trigger update)
	ts := na.Timestamp.Add(time.Second)
	na.Timestamp = ts
	amgr.addOrUpdateAddress(na, na)
	// address should be in there
	ka = amgr.GetAddress()
	if ka == nil {
		t.Fatal("Address Manager should contain known address")
	}
	if !reflect.DeepEqual(ka.NetAddress(), na) {
		t.Fatal("Address Manager should contain address that was added")
	}
	if !ka.NetAddress().Timestamp.Equal(ts) {
		t.Fatal("Address Manager did not update timestamp")
	}
	if err := amgr.Stop(); err != nil {
		t.Fatalf("Address Manager failed to stop: %v", err)
	}
}

func TestAddLocalAddress(t *testing.T) {
	var tests = []struct {
		name     string
		ip       net.IP
		priority AddressPriority
		valid    bool
	}{
		{
			name:     "unroutable local IPv4 address",
			ip:       net.ParseIP("192.168.0.100"),
			priority: InterfacePrio,
			valid:    false,
		},
		{
			name:     "routable IPv4 address",
			ip:       net.ParseIP("204.124.1.1"),
			priority: InterfacePrio,
			valid:    true,
		},
		{
			name:     "routable IPv4 address with bound priority",
			ip:       net.ParseIP("204.124.1.1"),
			priority: BoundPrio,
			valid:    true,
		},
		{
			name:     "unroutable local IPv6 address",
			ip:       net.ParseIP("::1"),
			priority: InterfacePrio,
			valid:    false,
		},
		{
			name:     "unroutable local IPv6 address 2",
			ip:       net.ParseIP("fe80::1"),
			priority: InterfacePrio,
			valid:    false,
		},
		{
			name:     "routable IPv6 address",
			ip:       net.ParseIP("2620:100::1"),
			priority: InterfacePrio,
			valid:    true,
		},
	}

	const testPort = 8333
	const testServices = sfNodeNetwork

	amgr := New("testaddlocaladdress")
	validLocalAddresses := make(map[string]struct{})
	for _, test := range tests {
		netAddr := NewNetAddress(test.ip, testPort, testServices)
		result := amgr.AddLocalAddress(netAddr, test.priority)
		if result == nil && !test.valid {
			t.Errorf("%q: address should have been accepted", test.name)
			continue
		}
		if result != nil && test.valid {
			t.Errorf("%q: address should not have been accepted", test.name)
			continue
		}
		if test.valid && !amgr.HasLocalAddress(netAddr) {
			t.Errorf("%q: expected to have local address", test.name)
			continue
		}
		if !test.valid && amgr.HasLocalAddress(netAddr) {
			t.Errorf("%q: expected to not have local address", test.name)
			continue
		}
		if test.valid {
			// Set up data to test behavior of a call to LocalAddresses() for
			// addresses that were added to the local address manager.
			validLocalAddresses[netAddr.Key()] = struct{}{}
		}
	}

	// Ensure that all of the addresses that were expected to be added to the
	// address manager are also returned from a call to LocalAddresses.
	for _, localAddr := range amgr.LocalAddresses() {
		localAddrIP := net.ParseIP(localAddr.Address)
		netAddr := NewNetAddress(localAddrIP, testPort, testServices)
		netAddrKey := netAddr.Key()
		if _, ok := validLocalAddresses[netAddrKey]; !ok {
			t.Errorf("expected to find local address with key %v", netAddrKey)
		}
	}
}

func TestAttempt(t *testing.T) {
	n := New("testattempt")

	// Add a new address and get it
	n.addAddressByIP(someIP, 8333)
	ka := n.GetAddress()

	if !ka.LastAttempt().IsZero() {
		t.Fatal("Address should not have attempts, but does")
	}

	na := ka.NetAddress()
	err := n.Attempt(na)
	if err != nil {
		t.Fatalf("Marking address as attempted failed -- %v", err)
	}

	if ka.LastAttempt().IsZero() {
		t.Fatal("Address should have an attempt, but does not")
	}

	// Attempt an ip not known to the address manager.
	unknownIP := net.ParseIP("1.2.3.4")
	unknownNetAddress := NewNetAddress(unknownIP, 1234, sfNodeNetwork)
	err = n.Attempt(unknownNetAddress)
	if err == nil {
		t.Fatal("Attempting unknown address should have returned an error")
	}
}

func TestConnected(t *testing.T) {
	n := New("testconnected")

	// Add a new address and get it
	n.addAddressByIP(someIP, 8333)
	ka := n.GetAddress()
	na := ka.NetAddress()
	// make it an hour ago
	na.Timestamp = time.Unix(time.Now().Add(time.Hour*-1).Unix(), 0)

	err := n.Connected(na)
	if err != nil {
		t.Fatalf("Marking address as connected failed - %v", err)
	}

	if !ka.NetAddress().Timestamp.After(na.Timestamp) {
		t.Error("Address should have a new timestamp, but does not")
	}

	// Attempt to flag an ip address not known to the address manager as
	// connected.
	unknownIP := net.ParseIP("1.2.3.4")
	unknownNetAddress := NewNetAddress(unknownIP, 1234, sfNodeNetwork)
	err = n.Connected(unknownNetAddress)
	if err == nil {
		t.Fatal("Marking unknown address as connected should have errored")
	}
}

func TestNeedMoreAddresses(t *testing.T) {
	n := New("testneedmoreaddresses")
	addrsToAdd := 1500
	b := n.NeedMoreAddresses()
	if !b {
		t.Error("Expected that we need more addresses")
	}
	addrs := make([]*NetAddress, addrsToAdd)

	for i := 0; i < addrsToAdd; i++ {
		s := fmt.Sprintf("%d.%d.173.147", i/128+60, i%128+60)
		addrs[i] = NewNetAddress(net.ParseIP(s), 8333, sfNodeNetwork)
	}

	srcAddr := NewNetAddress(net.ParseIP("173.144.173.111"), 8333, 0)

	n.AddAddresses(addrs, srcAddr)
	numAddrs := n.numAddresses()
	if numAddrs > addrsToAdd {
		t.Errorf("Number of addresses is too many %d vs %d", numAddrs, addrsToAdd)
	}

	b = n.NeedMoreAddresses()
	if b {
		t.Error("Expected that we don't need more addresses")
	}
}

func TestGood(t *testing.T) {
	n := New("testgood")
	addrsToAdd := 64 * 64
	addrs := make([]*NetAddress, addrsToAdd)

	for i := 0; i < addrsToAdd; i++ {
		s := fmt.Sprintf("%d.173.147.%d", i/64+60, i%64+60)
		addrs[i] = NewNetAddress(net.ParseIP(s), 8333, sfNodeNetwork)
	}

	srcAddr := NewNetAddress(net.ParseIP("173.144.173.111"), 8333, sfNodeNetwork)

	n.AddAddresses(addrs, srcAddr)
	for _, addr := range addrs {
		n.Good(addr)
	}

	numAddrs := n.numAddresses()
	if numAddrs >= addrsToAdd {
		t.Errorf("Number of addresses is too many: %d vs %d", numAddrs, addrsToAdd)
	}

	numCache := len(n.AddressCache(TORv2Address))
	if numCache >= numAddrs/4 {
		t.Errorf("Number of addresses in cache: got %d, want %d", numCache, numAddrs/4)
	}

	// Test internal behavior of how addresses are managed between the new and
	// tried address buckets. When an address is initially added it should enter
	// the new bucket, and when marked good it should move to the tried bucket.
	// If the tried bucket is full then it should make room for the newly tried
	// address by moving the old one back to the new bucket.
	n = New("testgood_tried_overflow")
	n.triedBucketSize = 1
	n.getNewBucket = func(netAddr, srcAddr *NetAddress) int {
		return 0
	}
	n.getTriedBucket = func(netAddr *NetAddress) int {
		return 0
	}

	addrA := NewNetAddress(net.ParseIP("173.144.173.1"), 8333, 0)
	addrB := NewNetAddress(net.ParseIP("173.144.173.2"), 8333, 0)
	addrAKey := addrA.Key()
	addrBKey := addrB.Key()

	// Neither address should exist in the addrIndex bucket prior to being
	// added to the address manager. The new and tried buckets should also be
	// empty.
	if len(n.addrIndex) > 0 {
		t.Fatal("Expected address index to be empty prior to adding addresses" +
			" to the address manager")
	}
	if len(n.addrNew[0]) > 0 {
		t.Fatal("Expected new bucket to be empty prior to adding addresses" +
			" to the address manager")
	}
	if len(n.addrTried[0]) > 0 {
		t.Fatal("Expected tried bucket to be empty prior to adding addresses" +
			" to the address manager")
	}

	n.AddAddresses([]*NetAddress{addrA, addrB}, srcAddr)

	// Both addresses should exist in the address index and new bucket after
	// being added to the address manager.  The tried bucket should be empty.
	if _, exists := n.addrIndex[addrAKey]; !exists {
		t.Fatal("Expected addrA to exist in address index")
	}
	if _, exists := n.addrIndex[addrBKey]; !exists {
		t.Fatal("Expected addrB to exist in address index")
	}
	if _, exists := n.addrNew[0][addrAKey]; !exists {
		t.Fatal("Expected addrA to exist in new bucket")
	}
	if _, exists := n.addrNew[0][addrBKey]; !exists {
		t.Fatal("Expected addrB to exist in new bucket")
	}
	if len(n.addrTried[0]) > 0 {
		t.Fatal("Expected tried bucket to contain no elements")
	}

	// Flagging addrA as good should move it to the tried bucket and remove
	// it from the new bucket.
	n.Good(addrA)
	if _, exists := n.addrNew[0][addrAKey]; exists {
		t.Fatal("Expected addrA to not exist in new bucket")
	}
	if len(n.addrTried[0]) != 1 {
		t.Fatal("Expected tried bucket to contain exactly one element.")
	}
	if n.addrTried[0][0].na.Key() != addrAKey {
		t.Fatal("Expected addrA to exist in tried bucket")
	}

	// Flagging addrB as good should cause addrB to move from the new bucket to
	// the tried bucket. It should also cause addrA to be evicted from the tried
	// bucket and move back to the new bucket since the tried bucket has been
	// limited in capacity to one element.
	n.Good(addrB)
	if _, exists := n.addrNew[0][addrBKey]; exists {
		t.Fatal("Expected addrB to not exist in the new bucket")
	}
	if len(n.addrTried[0]) != 1 {
		t.Fatalf("Expected tried bucket to contain exactly one element, got %d",
			len(n.addrTried[0]))
	}
	if n.addrTried[0][0].na.Key() != addrBKey {
		t.Error("Expected addrB to exist in tried bucket")
	}
	if _, exists := n.addrNew[0][addrAKey]; !exists {
		t.Error("Expected addrA to exist in the new bucket after being " +
			"evicted from the tried bucket")
	}
}

func TestGetAddress(t *testing.T) {
	n := New("testgetaddress")

	// Get an address from an empty set (should error)
	if rv := n.GetAddress(); rv != nil {
		t.Errorf("GetAddress failed: got: %v want: %v\n", rv, nil)
	}

	// Add a new address and get it
	n.addAddressByIP(someIP, 8333)
	ka := n.GetAddress()
	if ka == nil {
		t.Fatal("Did not get an address where there is one in the pool")
	}

	ipStringA := ka.NetAddress().ipString()
	if ipStringA != someIP {
		t.Fatalf("Wrong IP -- got %v, want %v", ipStringA, someIP)
	}

	// Mark this as a good address and get it
	err := n.Good(ka.NetAddress())
	if err != nil {
		t.Fatalf("Marking address as good failed: %v", err)
	}

	ka = n.GetAddress()
	if ka == nil {
		t.Fatal("Did not get an address where there is one in the pool")
	}

	ipStringB := ka.NetAddress().ipString()
	if ipStringB != someIP {
		t.Fatalf("Wrong IP -- got %v, want %v", ipStringB, someIP)
	}

	numAddrs := n.numAddresses()
	if numAddrs != 1 {
		t.Fatalf("wrong number of addresses -- got %d, want %d", numAddrs, 1)
	}

	// Marking an address not known to the address manager as good should return
	// an error.
	unknownIP := net.ParseIP("1.2.3.4")
	unknownNetAddress := NewNetAddress(unknownIP, 1234, sfNodeNetwork)
	err = n.Good(unknownNetAddress)
	if err == nil {
		t.Fatal("Attempting unknown address should have returned an error")
	}
}

func TestGetBestLocalAddress(t *testing.T) {
	newAddressFromIP := func(ip net.IP) *NetAddress {
		const port = 0
		return NewNetAddress(ip, port, sfNodeNetwork)
	}

	localAddrs := []*NetAddress{
		newAddressFromIP(net.ParseIP("192.168.0.100")),
		newAddressFromIP(net.ParseIP("::1")),
		newAddressFromIP(net.ParseIP("fe80::1")),
		newAddressFromIP(net.ParseIP("2001:470::1")),
	}

	var tests = []struct {
		remoteAddr *NetAddress
		want0      *NetAddress
		want1      *NetAddress
		want2      *NetAddress
		want3      *NetAddress
	}{
		{
			// Remote connection from public IPv4
			newAddressFromIP(net.ParseIP("204.124.8.1")),
			newAddressFromIP(net.IPv4zero),
			newAddressFromIP(net.IPv4zero),
			newAddressFromIP(net.ParseIP("204.124.8.100")),
			newAddressFromIP(net.ParseIP("fd87:d87e:eb43:25::1")),
		},
		{
			// Remote connection from private IPv4
			newAddressFromIP(net.ParseIP("172.16.0.254")),
			newAddressFromIP(net.IPv4zero),
			newAddressFromIP(net.IPv4zero),
			newAddressFromIP(net.IPv4zero),
			newAddressFromIP(net.IPv4zero),
		},
		{
			// Remote connection from public IPv6
			newAddressFromIP(net.ParseIP("2602:100:abcd::102")),
			newAddressFromIP(net.IPv6zero),
			newAddressFromIP(net.ParseIP("2001:470::1")),
			newAddressFromIP(net.ParseIP("2001:470::1")),
			newAddressFromIP(net.ParseIP("2001:470::1")),
		},
		/* XXX
		{
			// Remote connection from Tor
			wire.NetAddress{IP: net.ParseIP("fd87:d87e:eb43::100")},
			wire.NetAddress{IP: net.IPv4zero},
			wire.NetAddress{IP: net.ParseIP("204.124.8.100")},
			wire.NetAddress{IP: net.ParseIP("fd87:d87e:eb43:25::1")},
		},
		*/
	}

	amgr := New("testgetbestlocaladdress")

	// Test against default when there's no address
	for x, test := range tests {
		got := amgr.GetBestLocalAddress(test.remoteAddr, IPv6Address)
		if !reflect.DeepEqual(test.want0.IP, got.IP) {
			t.Errorf("TestGetBestLocalAddress test1 #%d failed for remote address %s: want %s got %s",
				x, test.remoteAddr.IP, test.want1.IP, got.IP)
			continue
		}
	}

	for _, localAddr := range localAddrs {
		amgr.AddLocalAddress(localAddr, InterfacePrio)
	}

	// Test against want1
	for x, test := range tests {
		got := amgr.GetBestLocalAddress(test.remoteAddr, IPv6Address)
		if !reflect.DeepEqual(test.want1.IP, got.IP) {
			t.Errorf("TestGetBestLocalAddress test1 #%d failed for remote address %s: want %s got %s",
				x, test.remoteAddr.IP, test.want1.IP, got.IP)
			continue
		}
	}

	// Add a public IP to the list of local addresses.
	localAddr := newAddressFromIP(net.ParseIP("204.124.8.100"))
	amgr.AddLocalAddress(localAddr, InterfacePrio)

	// Test against want2
	for x, test := range tests {
		got := amgr.GetBestLocalAddress(test.remoteAddr, IPv6Address)
		if !reflect.DeepEqual(test.want2.IP, got.IP) {
			t.Errorf("TestGetBestLocalAddress test2 #%d failed for remote address %s: want %s got %s",
				x, test.remoteAddr.IP, test.want2.IP, got.IP)
			continue
		}
	}
	/*
		// Add a Tor generated IP address
		localAddr = wire.NetAddress{IP: net.ParseIP("fd87:d87e:eb43:25::1")}
		amgr.AddLocalAddress(&localAddr, ManualPrio)

		// Test against want3
		for x, test := range tests {
			got := amgr.GetBestLocalAddress(&test.remoteAddr)
			if !test.want3.IP.Equal(got.IP) {
				t.Errorf("TestGetBestLocalAddress test3 #%d failed for remote address %s: want %s got %s",
					x, test.remoteAddr.IP, test.want3.IP, got.IP)
				continue
			}
		}
	*/
}

func TestCorruptPeersFile(t *testing.T) {
	dir, err := ioutil.TempDir("", "testcorruptpeersfile")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	peersFile := filepath.Join(dir, peersFilename)
	// create corrupt (empty) peers file
	fp, err := os.Create(peersFile)
	if err != nil {
		t.Fatalf("Could not create empty peers file: %s", peersFile)
	}
	if err := fp.Close(); err != nil {
		t.Fatalf("Could not write empty peers file: %s", peersFile)
	}
	amgr := New(dir)
	amgr.Start()
	amgr.Stop()
	if _, err := os.Stat(peersFile); err != nil {
		t.Fatalf("Corrupt peers file has not been removed: %s", peersFile)
	}
}

// TestValidatePeerNa tests whether a remote address is considered reachable
// from a local address.
func TestValidatePeerNa(t *testing.T) {
	const unroutableIpv4Address = "0.0.0.0"
	const unroutableIpv6Address = "::1"
	const routableIpv4Address = "12.1.2.3"
	const routableIpv6Address = "2003::"
	onionCatTorV2Address := onionCatNet.IP.String()
	rfc4380IPAddress := rfc4380Net.IP.String()
	rfc3964IPAddress := rfc3964Net.IP.String()
	rfc6052IPAddress := rfc6052Net.IP.String()
	rfc6145IPAddress := rfc6145Net.IP.String()

	tests := []struct {
		name          string
		localAddress  string
		remoteAddress string
		valid         bool
		reach         NetAddressReach
	}{
		{
			name:          "torv2 to torv2",
			localAddress:  onionCatTorV2Address,
			remoteAddress: onionCatTorV2Address,
			valid:         false,
			reach:         Private,
		},
		{
			name:          "routable ipv4 to torv2",
			localAddress:  routableIpv4Address,
			remoteAddress: onionCatTorV2Address,
			valid:         true,
			reach:         Ipv4,
		},
		{
			name:          "unroutable ipv4 to torv2",
			localAddress:  unroutableIpv4Address,
			remoteAddress: onionCatTorV2Address,
			valid:         false,
			reach:         Default,
		},
		{
			name:          "routable ipv6 to torv2",
			localAddress:  routableIpv6Address,
			remoteAddress: onionCatTorV2Address,
			valid:         false,
			reach:         Default,
		},
		{
			name:          "unroutable ipv6 to torv2",
			localAddress:  unroutableIpv6Address,
			remoteAddress: onionCatTorV2Address,
			valid:         false,
			reach:         Default,
		},
		{
			name:          "rfc4380 to rfc4380",
			localAddress:  rfc4380IPAddress,
			remoteAddress: rfc4380IPAddress,
			valid:         true,
			reach:         Teredo,
		},
		{
			name:          "unroutable ipv4 to rfc4380",
			localAddress:  unroutableIpv4Address,
			remoteAddress: rfc4380IPAddress,
			valid:         false,
			reach:         Default,
		},
		{
			name:          "routable ipv4 to rfc4380",
			localAddress:  routableIpv4Address,
			remoteAddress: rfc4380IPAddress,
			valid:         true,
			reach:         Ipv4,
		},
		{
			name:          "routable ipv6 to rfc4380",
			localAddress:  routableIpv6Address,
			remoteAddress: rfc4380IPAddress,
			valid:         true,
			reach:         Ipv6Weak,
		},
		{
			name:          "routable ipv4 to routable ipv4",
			localAddress:  routableIpv4Address,
			remoteAddress: routableIpv4Address,
			valid:         true,
			reach:         Ipv4,
		},
		{
			name:          "routable ipv6 to routable ipv4",
			localAddress:  routableIpv6Address,
			remoteAddress: routableIpv4Address,
			valid:         false,
			reach:         Unreachable,
		},
		{
			name:          "unroutable ipv4 to routable ipv6",
			localAddress:  unroutableIpv4Address,
			remoteAddress: routableIpv6Address,
			valid:         false,
			reach:         Default,
		},
		{
			name:          "unroutable ipv6 to routable ipv6",
			localAddress:  unroutableIpv6Address,
			remoteAddress: routableIpv6Address,
			valid:         false,
			reach:         Default,
		},
		{
			name:          "unroutable ipv4 to routable ipv6",
			localAddress:  unroutableIpv4Address,
			remoteAddress: routableIpv6Address,
			valid:         false,
			reach:         Default,
		},
		{
			name:          "routable ipv4 to unroutable ipv6",
			localAddress:  routableIpv4Address,
			remoteAddress: unroutableIpv6Address,
			valid:         false,
			reach:         Unreachable,
		},
		{
			name:          "routable ivp6 rfc4380 to routable ipv6",
			localAddress:  rfc4380IPAddress,
			remoteAddress: routableIpv6Address,
			valid:         true,
			reach:         Teredo,
		},
		{
			name:          "routable ipv4 to routable ipv6",
			localAddress:  routableIpv4Address,
			remoteAddress: routableIpv6Address,
			valid:         true,
			reach:         Ipv4,
		},
		{
			name:          "tunnelled ipv6 rfc3964 to routable ipv6",
			localAddress:  rfc3964IPAddress,
			remoteAddress: routableIpv6Address,
			valid:         true,
			reach:         Ipv6Weak,
		},
		{
			name:          "tunnelled ipv6 rfc6052 to routable ipv6",
			localAddress:  rfc6052IPAddress,
			remoteAddress: routableIpv6Address,
			valid:         true,
			reach:         Ipv6Weak,
		},
		{
			name:          "tunnelled ipv6 rfc6145 to routable ipv6",
			localAddress:  rfc6145IPAddress,
			remoteAddress: routableIpv6Address,
			valid:         true,
			reach:         Ipv6Weak,
		},
	}

	addressManager := New("testValidatePeerNa")
	for _, test := range tests {
		localIP := net.ParseIP(test.localAddress)
		remoteIP := net.ParseIP(test.remoteAddress)
		localNa := NewNetAddress(localIP, 8333, sfNodeNetwork)
		remoteNa := NewNetAddress(remoteIP, 8333, sfNodeNetwork)

		valid, reach := addressManager.ValidatePeerNa(localNa, remoteNa)
		if valid != test.valid {
			t.Errorf("%q: unexpected return value for valid - want '%v', "+
				"got '%v'", test.name, test.valid, valid)
			continue
		}
		if reach != test.reach {
			t.Errorf("%q: unexpected return value for reach - want '%v', "+
				"got '%v'", test.name, test.reach, reach)
		}
	}
}

// TestSetServices ensures that a known address' services are updated as
// expected and that the services field is not mutated when new services are
// added.
func TestSetServices(t *testing.T) {
	addressManager := New("testSetServices")
	const services = sfNodeNetwork

	// Attempt to set services for an address not known to the address manager.
	notKnownAddr := NewNetAddress(net.ParseIP("1.2.3.4"), 8333, services)
	err := addressManager.SetServices(notKnownAddr, services)
	if err == nil {
		t.Fatal("setting services for unknown address should return error")
	}

	// Add a new address to the address manager.
	netAddr := NewNetAddress(net.ParseIP("1.2.3.4"), 8333, services)
	srcAddr := NewNetAddress(net.ParseIP("5.6.7.8"), 8333, services)
	addressManager.addOrUpdateAddress(netAddr, srcAddr)

	// Ensure that the services field for a network address returned from the
	// address manager is not mutated by a call to SetServices.
	knownAddress := addressManager.GetAddress()
	if knownAddress == nil {
		t.Fatal("expected known address, got nil")
	}
	netAddrA := knownAddress.na
	if netAddrA.Services != services {
		t.Fatalf("unexpected network address services -- got %x, want %x",
			netAddrA.Services, services)
	}

	// Set the new services for the network address and verify that the
	// previously seen network address netAddrA's services are not modified.
	const newServiceFlags = services << 1
	addressManager.SetServices(netAddr, newServiceFlags)
	netAddrB := knownAddress.na
	if netAddrA == netAddrB {
		t.Fatal("expected known address to have new network address reference")
	}
	if netAddrA.Services != services {
		t.Fatal("netAddrA services flag was mutated")
	}
	if netAddrB.Services != newServiceFlags {
		t.Fatalf("netAddrB has invalid services -- got %x, want %x",
			netAddrB.Services, newServiceFlags)
	}
}
