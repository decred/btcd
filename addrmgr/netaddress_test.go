// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package addrmgr

import (
	"net"
	"testing"
)

// TestKey verifies that Key converts a network address to an expected string
// value.
func TestKey(t *testing.T) {
	tests := []struct {
		ip   string
		port uint16
		want string
	}{
		// IPv4
		// Localhost
		{ip: "127.0.0.1", port: 8333, want: "127.0.0.1:8333"},
		{ip: "127.0.0.1", port: 8334, want: "127.0.0.1:8334"},

		// Class A
		{ip: "1.0.0.1", port: 8333, want: "1.0.0.1:8333"},
		{ip: "2.2.2.2", port: 8334, want: "2.2.2.2:8334"},
		{ip: "27.253.252.251", port: 8335, want: "27.253.252.251:8335"},
		{ip: "123.3.2.1", port: 8336, want: "123.3.2.1:8336"},

		// Private Class A
		{ip: "10.0.0.1", port: 8333, want: "10.0.0.1:8333"},
		{ip: "10.1.1.1", port: 8334, want: "10.1.1.1:8334"},
		{ip: "10.2.2.2", port: 8335, want: "10.2.2.2:8335"},
		{ip: "10.10.10.10", port: 8336, want: "10.10.10.10:8336"},

		// Class B
		{ip: "128.0.0.1", port: 8333, want: "128.0.0.1:8333"},
		{ip: "129.1.1.1", port: 8334, want: "129.1.1.1:8334"},
		{ip: "180.2.2.2", port: 8335, want: "180.2.2.2:8335"},
		{ip: "191.10.10.10", port: 8336, want: "191.10.10.10:8336"},

		// Private Class B
		{ip: "172.16.0.1", port: 8333, want: "172.16.0.1:8333"},
		{ip: "172.16.1.1", port: 8334, want: "172.16.1.1:8334"},
		{ip: "172.16.2.2", port: 8335, want: "172.16.2.2:8335"},
		{ip: "172.16.172.172", port: 8336, want: "172.16.172.172:8336"},

		// Class C
		{ip: "193.0.0.1", port: 8333, want: "193.0.0.1:8333"},
		{ip: "200.1.1.1", port: 8334, want: "200.1.1.1:8334"},
		{ip: "205.2.2.2", port: 8335, want: "205.2.2.2:8335"},
		{ip: "223.10.10.10", port: 8336, want: "223.10.10.10:8336"},

		// Private Class C
		{ip: "192.168.0.1", port: 8333, want: "192.168.0.1:8333"},
		{ip: "192.168.1.1", port: 8334, want: "192.168.1.1:8334"},
		{ip: "192.168.2.2", port: 8335, want: "192.168.2.2:8335"},
		{ip: "192.168.192.192", port: 8336, want: "192.168.192.192:8336"},

		// IPv6
		// Localhost
		{ip: "::1", port: 8333, want: "[::1]:8333"},
		{ip: "fe80::1", port: 8334, want: "[fe80::1]:8334"},

		// Link-local
		{ip: "fe80::1:1", port: 8333, want: "[fe80::1:1]:8333"},
		{ip: "fe91::2:2", port: 8334, want: "[fe91::2:2]:8334"},
		{ip: "fea2::3:3", port: 8335, want: "[fea2::3:3]:8335"},
		{ip: "feb3::4:4", port: 8336, want: "[feb3::4:4]:8336"},

		// Site-local
		{ip: "fec0::1:1", port: 8333, want: "[fec0::1:1]:8333"},
		{ip: "fed1::2:2", port: 8334, want: "[fed1::2:2]:8334"},
		{ip: "fee2::3:3", port: 8335, want: "[fee2::3:3]:8335"},
		{ip: "fef3::4:4", port: 8336, want: "[fef3::4:4]:8336"},

		// TORv2
		{ip: "fd87:d87e:eb43::", port: 8333, want: "aaaaaaaaaaaaaaaa.onion:8333"},
	}

	for _, test := range tests {
		netAddr := NewNetAddress(net.ParseIP(test.ip), test.port, sfNodeNetwork)
		key := netAddr.Key()
		if key != test.want {
			t.Errorf("unexpected network address key -- got %s, want %s",
				key, test.want)
			continue
		}
	}
}

// TestClone verifies that a copy of the network address is made.
func TestClone(t *testing.T) {
	const port = 0
	netAddr := NewNetAddress(net.ParseIP("1.2.3.4"), port, sfNodeNetwork)
	netAddrClone := netAddr.Clone()

	if netAddr == netAddrClone {
		t.Error("expected new network address reference")
	}
}

// TestAddService verifies that the service flag is set as expected on a
// network address instance.
func TestAddService(t *testing.T) {
	const port = 0
	netAddr := NewNetAddress(net.ParseIP("1.2.3.4"), port, ServiceFlag(0))
	netAddr.AddService(sfNodeNetwork)

	if netAddr.Services != sfNodeNetwork {
		t.Errorf("expected service flag to be set -- got %x, want %x",
			netAddr.Services, sfNodeNetwork)
	}
}
