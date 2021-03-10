// Copyright (c) 2013-2014 The btcsuite developers
// Copyright (c) 2015-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package addrmgr

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/decred/dcrd/wire"
)

// naTest is used to describe a test to be performed against the NetAddressKey
// method.
type naTest struct {
	in   wire.NetAddress
	want string
}

// naTests houses all of the tests to be performed against the NetAddressKey
// method.
var naTests = make([]naTest, 0)

// Put some IP in here for convenience. Points to google.
var someIP = "173.194.115.66"

// addNaTests
func addNaTests() {
	// IPv4
	// Localhost
	addNaTest("127.0.0.1", 8333, "127.0.0.1:8333")
	addNaTest("127.0.0.1", 8334, "127.0.0.1:8334")

	// Class A
	addNaTest("1.0.0.1", 8333, "1.0.0.1:8333")
	addNaTest("2.2.2.2", 8334, "2.2.2.2:8334")
	addNaTest("27.253.252.251", 8335, "27.253.252.251:8335")
	addNaTest("123.3.2.1", 8336, "123.3.2.1:8336")

	// Private Class A
	addNaTest("10.0.0.1", 8333, "10.0.0.1:8333")
	addNaTest("10.1.1.1", 8334, "10.1.1.1:8334")
	addNaTest("10.2.2.2", 8335, "10.2.2.2:8335")
	addNaTest("10.10.10.10", 8336, "10.10.10.10:8336")

	// Class B
	addNaTest("128.0.0.1", 8333, "128.0.0.1:8333")
	addNaTest("129.1.1.1", 8334, "129.1.1.1:8334")
	addNaTest("180.2.2.2", 8335, "180.2.2.2:8335")
	addNaTest("191.10.10.10", 8336, "191.10.10.10:8336")

	// Private Class B
	addNaTest("172.16.0.1", 8333, "172.16.0.1:8333")
	addNaTest("172.16.1.1", 8334, "172.16.1.1:8334")
	addNaTest("172.16.2.2", 8335, "172.16.2.2:8335")
	addNaTest("172.16.172.172", 8336, "172.16.172.172:8336")

	// Class C
	addNaTest("193.0.0.1", 8333, "193.0.0.1:8333")
	addNaTest("200.1.1.1", 8334, "200.1.1.1:8334")
	addNaTest("205.2.2.2", 8335, "205.2.2.2:8335")
	addNaTest("223.10.10.10", 8336, "223.10.10.10:8336")

	// Private Class C
	addNaTest("192.168.0.1", 8333, "192.168.0.1:8333")
	addNaTest("192.168.1.1", 8334, "192.168.1.1:8334")
	addNaTest("192.168.2.2", 8335, "192.168.2.2:8335")
	addNaTest("192.168.192.192", 8336, "192.168.192.192:8336")

	// IPv6
	// Localhost
	addNaTest("::1", 8333, "[::1]:8333")
	addNaTest("fe80::1", 8334, "[fe80::1]:8334")

	// Link-local
	addNaTest("fe80::1:1", 8333, "[fe80::1:1]:8333")
	addNaTest("fe91::2:2", 8334, "[fe91::2:2]:8334")
	addNaTest("fea2::3:3", 8335, "[fea2::3:3]:8335")
	addNaTest("feb3::4:4", 8336, "[feb3::4:4]:8336")

	// Site-local
	addNaTest("fec0::1:1", 8333, "[fec0::1:1]:8333")
	addNaTest("fed1::2:2", 8334, "[fed1::2:2]:8334")
	addNaTest("fee2::3:3", 8335, "[fee2::3:3]:8335")
	addNaTest("fef3::4:4", 8336, "[fef3::4:4]:8336")

	// Tor
	addNaTest("fd87:d87e:eb43::", 8333, "aaaaaaaaaaaaaaaa.onion:8333")
}

func addNaTest(ip string, port uint16, want string) {
	nip := net.ParseIP(ip)
	na := *wire.NewNetAddressIPPort(nip, port, wire.SFNodeNetwork)
	test := naTest{na, want}
	naTests = append(naTests, test)
}

func lookupFunc(host string) ([]net.IP, error) {
	return nil, errors.New("not implemented")
}

// addAddressByIP is a convenience function that adds an address from an ip
// address string and port, rather than a wire.NetAddress.
func (a *AddrManager) addAddressByIP(addr string, port uint16) {
	ip := net.ParseIP(addr)
	na := wire.NewNetAddressIPPort(ip, port, 0)
	a.AddAddress(na, na)
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

	amgr := New(dir, nil)
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
	amgr = New(dir, nil)
	amgr.Start()

	knownAddress := amgr.GetAddress()
	if knownAddress == nil {
		t.Fatal("address manager should contain known address")
	}

	// Verify that the known address matches what was added to the address
	// manager previously.
	wantNetAddrKey := someIP + ":8333"
	gotNetAddrKey := NetAddressKey(knownAddress.na)
	if gotNetAddrKey != wantNetAddrKey {
		t.Fatal("address manager does not contain expected address -- "+
			"got %v, want %v", gotNetAddrKey, wantNetAddrKey)
	}

	if err := amgr.Stop(); err != nil {
		t.Fatalf("address manager failed to stop: %v", err)
	}
}

func TestAddAddressUpdate(t *testing.T) {
	amgr := New("testaddaddressupdate", nil)
	amgr.Start()
	if ka := amgr.GetAddress(); ka != nil {
		t.Fatal("Address Manager should contain no addresses")
	}
	ip := net.ParseIP(someIP)
	if ip == nil {
		t.Fatalf("Invalid IP address %s", someIP)
	}
	na := wire.NewNetAddressIPPort(ip, 8333, 0)
	amgr.AddAddress(na, na)
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
	amgr.AddAddress(na, na)
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
		address  wire.NetAddress
		priority AddressPriority
		valid    bool
	}{
		{
			name:     "unroutable local IPv4 address",
			address:  wire.NetAddress{IP: net.ParseIP("192.168.0.100")},
			priority: InterfacePrio,
			valid:    false,
		},
		{
			name:     "routable IPv4 address",
			address:  wire.NetAddress{IP: net.ParseIP("204.124.1.1")},
			priority: InterfacePrio,
			valid:    true,
		},
		{
			name:     "routable IPv4 address with bound priority",
			address:  wire.NetAddress{IP: net.ParseIP("204.124.1.1")},
			priority: BoundPrio,
			valid:    true,
		},
		{
			name:     "unroutable local IPv6 address",
			address:  wire.NetAddress{IP: net.ParseIP("::1")},
			priority: InterfacePrio,
			valid:    false,
		},
		{
			name:     "unroutable local IPv6 address 2",
			address:  wire.NetAddress{IP: net.ParseIP("fe80::1")},
			priority: InterfacePrio,
			valid:    false,
		},
		{
			name:     "routable IPv6 address",
			address:  wire.NetAddress{IP: net.ParseIP("2620:100::1")},
			priority: InterfacePrio,
			valid:    true,
		},
	}
	amgr := New("testaddlocaladdress", nil)
	validLocalAddresses := make(map[string]struct{})
	for _, test := range tests {
		netAddr := &test.address
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
			validLocalAddresses[NetAddressKey(netAddr)] = struct{}{}
		}
	}

	// Ensure that all of the addresses that were expected to be added to the
	// address manager are also returned from a call to LocalAddresses.
	for _, localAddr := range amgr.LocalAddresses() {
		localAddrIP := net.ParseIP(localAddr.Address)
		netAddr := &wire.NetAddress{IP: localAddrIP}
		netAddrKey := NetAddressKey(netAddr)
		if _, ok := validLocalAddresses[netAddrKey]; !ok {
			t.Errorf("expected to find local address with key %v", netAddrKey)
		}
	}
}

func TestAttempt(t *testing.T) {
	n := New("testattempt", lookupFunc)

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
	unknownNetAddress := wire.NewNetAddressIPPort(unknownIP, 1234,
		wire.SFNodeNetwork)
	err = n.Attempt(unknownNetAddress)
	if err == nil {
		t.Fatal("Attempting unknown address should have returned an error")
	}
}

func TestConnected(t *testing.T) {
	n := New("testconnected", lookupFunc)

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
	unknownNetAddress := wire.NewNetAddressIPPort(unknownIP, 1234,
		wire.SFNodeNetwork)
	err = n.Connected(unknownNetAddress)
	if err == nil {
		t.Fatal("Marking unknown address as connected should have errored")
	}
}

func TestNeedMoreAddresses(t *testing.T) {
	n := New("testneedmoreaddresses", lookupFunc)
	addrsToAdd := 1500
	b := n.NeedMoreAddresses()
	if !b {
		t.Error("Expected that we need more addresses")
	}
	addrs := make([]*wire.NetAddress, addrsToAdd)

	var err error
	for i := 0; i < addrsToAdd; i++ {
		s := fmt.Sprintf("%d.%d.173.147:8333", i/128+60, i%128+60)
		addrs[i], err = n.DeserializeNetAddress(s)
		if err != nil {
			t.Errorf("Failed to turn %s into an address: %v", s, err)
		}
	}

	srcAddr := wire.NewNetAddressIPPort(net.IPv4(173, 144, 173, 111), 8333, 0)

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
	n := New("testgood", lookupFunc)
	addrsToAdd := 64 * 64
	addrs := make([]*wire.NetAddress, addrsToAdd)

	var err error
	for i := 0; i < addrsToAdd; i++ {
		s := fmt.Sprintf("%d.173.147.%d:8333", i/64+60, i%64+60)
		addrs[i], err = n.DeserializeNetAddress(s)
		if err != nil {
			t.Errorf("Failed to turn %s into an address: %v", s, err)
		}
	}

	srcAddr := wire.NewNetAddressIPPort(net.IPv4(173, 144, 173, 111), 8333, 0)

	n.AddAddresses(addrs, srcAddr)
	for _, addr := range addrs {
		n.Good(addr)
	}

	numAddrs := n.numAddresses()
	if numAddrs >= addrsToAdd {
		t.Errorf("Number of addresses is too many: %d vs %d", numAddrs, addrsToAdd)
	}

	numCache := len(n.AddressCache())
	if numCache >= numAddrs/4 {
		t.Errorf("Number of addresses in cache: got %d, want %d", numCache, numAddrs/4)
	}

	// Test internal behavior of how addresses are managed between the new and
	// tried address buckets. When an address is initially added it should enter
	// the new bucket, and when marked good it should move to the tried bucket.
	// If the tried bucket is full then it should make room for the newly tried
	// address by moving the old one back to the new bucket.
	n = New("testgood_tried_overflow", lookupFunc)
	n.triedBucketSize = 1
	n.getNewBucket = func(netAddr, srcAddr *wire.NetAddress) int {
		return 0
	}
	n.getTriedBucket = func(netAddr *wire.NetAddress) int {
		return 0
	}

	addrA := wire.NewNetAddressIPPort(net.ParseIP("173.144.173.1"), 8333, 0)
	addrB := wire.NewNetAddressIPPort(net.ParseIP("173.144.173.2"), 8333, 0)
	addrAKey := NetAddressKey(addrA)
	addrBKey := NetAddressKey(addrB)

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

	n.AddAddress(addrA, srcAddr)
	n.AddAddress(addrB, srcAddr)

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
	if NetAddressKey(n.addrTried[0][0].na) != addrAKey {
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
	if NetAddressKey(n.addrTried[0][0].na) != addrBKey {
		t.Error("Expected addrB to exist in tried bucket")
	}
	if _, exists := n.addrNew[0][addrAKey]; !exists {
		t.Error("Expected addrA to exist in the new bucket after being " +
			"evicted from the tried bucket")
	}
}

func TestGetAddress(t *testing.T) {
	n := New("testgetaddress", lookupFunc)

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

	ipStringA := ka.NetAddress().IP.String()
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

	ipStringB := ka.NetAddress().IP.String()
	if ipStringB != someIP {
		t.Errorf("Wrong IP -- got %v, want %v", ipStringB, someIP)
	}

	numAddrs := n.numAddresses()
	if numAddrs != 1 {
		t.Errorf("Wrong number of addresses -- got %d, want %d", numAddrs, 1)
	}

	// Marking an address not known to the address manager as good should return
	// an error.
	unknownIP := net.ParseIP("1.2.3.4")
	unknownNetAddress := wire.NewNetAddressIPPort(unknownIP, 1234,
		wire.SFNodeNetwork)
	err = n.Good(unknownNetAddress)
	if err == nil {
		t.Fatal("Attempting unknown address should have returned an error")
	}
}

func TestGetBestLocalAddress(t *testing.T) {
	localAddrs := []wire.NetAddress{
		{IP: net.ParseIP("192.168.0.100")},
		{IP: net.ParseIP("::1")},
		{IP: net.ParseIP("fe80::1")},
		{IP: net.ParseIP("2001:470::1")},
	}

	var tests = []struct {
		remoteAddr wire.NetAddress
		want0      wire.NetAddress
		want1      wire.NetAddress
		want2      wire.NetAddress
		want3      wire.NetAddress
	}{
		{
			// Remote connection from public IPv4
			wire.NetAddress{IP: net.ParseIP("204.124.8.1")},
			wire.NetAddress{IP: net.IPv4zero},
			wire.NetAddress{IP: net.IPv4zero},
			wire.NetAddress{IP: net.ParseIP("204.124.8.100")},
			wire.NetAddress{IP: net.ParseIP("fd87:d87e:eb43:25::1")},
		},
		{
			// Remote connection from private IPv4
			wire.NetAddress{IP: net.ParseIP("172.16.0.254")},
			wire.NetAddress{IP: net.IPv4zero},
			wire.NetAddress{IP: net.IPv4zero},
			wire.NetAddress{IP: net.IPv4zero},
			wire.NetAddress{IP: net.IPv4zero},
		},
		{
			// Remote connection from public IPv6
			wire.NetAddress{IP: net.ParseIP("2602:100:abcd::102")},
			wire.NetAddress{IP: net.IPv6zero},
			wire.NetAddress{IP: net.ParseIP("2001:470::1")},
			wire.NetAddress{IP: net.ParseIP("2001:470::1")},
			wire.NetAddress{IP: net.ParseIP("2001:470::1")},
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

	amgr := New("testgetbestlocaladdress", nil)

	// Test against default when there's no address
	for x, test := range tests {
		got := amgr.GetBestLocalAddress(&test.remoteAddr)
		if !test.want0.IP.Equal(got.IP) {
			t.Errorf("TestGetBestLocalAddress test1 #%d failed for remote address %s: want %s got %s",
				x, test.remoteAddr.IP, test.want1.IP, got.IP)
			continue
		}
	}

	for _, localAddr := range localAddrs {
		amgr.AddLocalAddress(&localAddr, InterfacePrio)
	}

	// Test against want1
	for x, test := range tests {
		got := amgr.GetBestLocalAddress(&test.remoteAddr)
		if !test.want1.IP.Equal(got.IP) {
			t.Errorf("TestGetBestLocalAddress test1 #%d failed for remote address %s: want %s got %s",
				x, test.remoteAddr.IP, test.want1.IP, got.IP)
			continue
		}
	}

	// Add a public IP to the list of local addresses.
	localAddr := wire.NetAddress{IP: net.ParseIP("204.124.8.100")}
	amgr.AddLocalAddress(&localAddr, InterfacePrio)

	// Test against want2
	for x, test := range tests {
		got := amgr.GetBestLocalAddress(&test.remoteAddr)
		if !test.want2.IP.Equal(got.IP) {
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

func TestNetAddressKey(t *testing.T) {
	addNaTests()

	t.Logf("Running %d tests", len(naTests))
	for i, test := range naTests {
		key := NetAddressKey(&test.in)
		if key != test.want {
			t.Errorf("NetAddressKey #%d\n got: %s want: %s", i, key, test.want)
			continue
		}
	}
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
	amgr := New(dir, nil)
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
		reach         int
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

	addressManager := New("testValidatePeerNa", nil)
	for _, test := range tests {
		localIP := net.ParseIP(test.localAddress)
		remoteIP := net.ParseIP(test.remoteAddress)
		localNa := wire.NewNetAddressIPPort(localIP, 8333, wire.SFNodeNetwork)
		remoteNa := wire.NewNetAddressIPPort(remoteIP, 8333, wire.SFNodeNetwork)

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

// TestHostToNetAddress ensures that HostToNetAddress behaves as expected
// given valid and invalid host name arguments.
func TestHostToNetAddress(t *testing.T) {
	// Define a hostname that will cause a lookup to be performed using the
	// lookupFunc provided to the address manager instance for each test.
	const hostnameForLookup = "hostname.test"
	const services = wire.SFNodeNetwork

	tests := []struct {
		name       string
		host       string
		port       uint16
		lookupFunc func(host string) ([]net.IP, error)
		wantErr    bool
		want       *wire.NetAddress
	}{
		{
			name:       "valid onion address",
			host:       "a5ccbdkubbr2jlcp.onion",
			port:       8333,
			lookupFunc: nil,
			wantErr:    false,
			want: wire.NewNetAddressIPPort(
				net.ParseIP("fd87:d87e:eb43:744:208d:5408:63a4:ac4f"), 8333,
				services),
		},
		{
			name:       "invalid onion address",
			host:       "0000000000000000.onion",
			port:       8333,
			lookupFunc: nil,
			wantErr:    true,
			want:       nil,
		},
		{
			name: "unresolvable host name",
			host: hostnameForLookup,
			port: 8333,
			lookupFunc: func(host string) ([]net.IP, error) {
				return nil, fmt.Errorf("unresolvable host %v", host)
			},
			wantErr: true,
			want:    nil,
		},
		{
			name: "not resolved host name",
			host: hostnameForLookup,
			port: 8333,
			lookupFunc: func(host string) ([]net.IP, error) {
				return nil, nil
			},
			wantErr: true,
			want:    nil,
		},
		{
			name: "resolved host name",
			host: hostnameForLookup,
			port: 8333,
			lookupFunc: func(host string) ([]net.IP, error) {
				return []net.IP{net.ParseIP("127.0.0.1")}, nil
			},
			wantErr: false,
			want: wire.NewNetAddressIPPort(net.ParseIP("127.0.0.1"), 8333,
				services),
		},
		{
			name:       "valid ip address",
			host:       "12.1.2.3",
			port:       8333,
			lookupFunc: nil,
			wantErr:    false,
			want: wire.NewNetAddressIPPort(net.ParseIP("12.1.2.3"), 8333,
				services),
		},
	}

	for _, test := range tests {
		addrManager := New("testHostToNetAddress", test.lookupFunc)
		result, err := addrManager.HostToNetAddress(test.host, test.port,
			services)
		if test.wantErr == true && err == nil {
			t.Errorf("%q: expected error but one was not returned", test.name)
		}
		if !reflect.DeepEqual(result, test.want) {
			t.Errorf("%q: unexpected result -- got %v, want %v", test.name,
				result, test.want)
		}
	}
}

// TestSetServices ensures that a known address' services are updated as
// expected and that the services field is not mutated when new services are
// added.
func TestSetServices(t *testing.T) {
	addressManager := New("testSetServices", nil)
	const services = wire.SFNodeNetwork

	// Attempt to set services for an address not known to the address manager.
	// This should have no effect and exercises paths that avoid a panic.
	notKnownAddr := wire.NewNetAddressIPPort(net.ParseIP("0.0.0.0"), 8333,
		services)
	err := addressManager.SetServices(notKnownAddr, services)
	if err == nil {
		t.Fatal("setting services for unknown address should return error")
	}

	// Add a new address to the address manager.
	netAddr := wire.NewNetAddressIPPort(net.ParseIP("1.2.3.4"), 8333, services)
	srcAddr := wire.NewNetAddressIPPort(net.ParseIP("5.6.7.8"), 8333, services)
	addressManager.AddAddress(netAddr, srcAddr)

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
