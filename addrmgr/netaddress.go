// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package addrmgr

import (
	"encoding/base32"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// ServiceFlag identifies services supported by a Decred peer.
type ServiceFlag uint64

const (
	// sfNodeNetwork is a flag used to indicate a peer is a full node.
	sfNodeNetwork ServiceFlag = 1 << iota
)

// NetAddress defines information about a peer on the network.
type NetAddress struct {
	// Type represents the type of network that the network address belongs to.
	Type NetAddressType

	// IP address of the peer. It is defined as a byte array to support various
	// address types that are not standard to the net module and therefore not
	// entirely appropriate to store as a net.IP.
	IP []byte

	// Port is the port of the remote peer.
	Port uint16

	// Timestamp is the last time the address was seen.
	Timestamp time.Time

	// Services represents the service flags supported by this network address.
	Services ServiceFlag
}

// IsRoutable returns a boolean indicating whether the network address is
// routable.
func (netAddr *NetAddress) IsRoutable() bool {
	return isRoutable(netAddr.IP)
}

// ipString returns a string for the ip from the provided NetAddress. If the
// ip is in the range used for TORv2 addresses then it will be transformed into
// the respective .onion address.
func (netAddr *NetAddress) ipString() string {
	netIP := netAddr.IP
	switch netAddr.Type {
	case TORv2Address:
		base32 := base32.StdEncoding.EncodeToString(netIP[6:])
		return strings.ToLower(base32) + ".onion"
	}
	return net.IP(netIP).String()
}

// Key returns a string that can be used to uniquely represent the network
// address and includes the port.
func (netAddr *NetAddress) Key() string {
	portString := strconv.FormatUint(uint64(netAddr.Port), 10)
	return net.JoinHostPort(netAddr.ipString(), portString)
}

// Clone creates a shallow copy of the NetAddress instance. The IP reference
// is shared since it is not mutated.
func (netAddr *NetAddress) Clone() *NetAddress {
	netAddrCopy := *netAddr
	return &netAddrCopy
}

// AddService adds the provided service to the set of services that the
// network address supports.
func (netAddr *NetAddress) AddService(service ServiceFlag) {
	netAddr.Services |= service
}

// HostToBytes deconstructs a given host to its respective []byte representation
// and also returns the network address type.  If an error occurs while decoding
// an onion address, the error is returned.  If the host cannot be converted
// then an unknown address type is returned without error.
func HostToBytes(host string) (NetAddressType, []byte, error) {
	if strings.HasSuffix(host, ".onion") {
		// Check if this is a TorV2 address.
		if len(host) == 22 {
			data, err := base32.StdEncoding.DecodeString(
				strings.ToUpper(host[:16]))
			if err != nil {
				return UnknownAddressType, nil, err
			}
			prefix := []byte{0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43}
			addrBytes := append(prefix, data...)
			return TORv2Address, addrBytes, nil
		}
	}

	if ip := net.ParseIP(host); ip != nil {
		if isIPv4(ip) {
			return IPv4Address, ip.To4(), nil
		}
		if isOnionCatTor(ip) {
			return TORv2Address, ip, nil
		}
		return IPv6Address, ip, nil
	}

	return UnknownAddressType, nil, nil
}

// canonicalizeIP converts the provided address' bytes into a standard structure
// based on the type of the network address, if applicable.
func canonicalizeIP(addrType NetAddressType, addrBytes []byte) []byte {
	len := len(addrBytes)
	switch {
	case len == 16 && addrType == IPv4Address:
		return net.IP(addrBytes).To4()
	case len == 10 && addrType == TORv2Address:
		prefix := []byte{0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43}
		return append(prefix, addrBytes...)
	case addrType == IPv6Address:
		return net.IP(addrBytes).To16()
	}
	return addrBytes
}

// deriveNetAddressType attempts to determine the network address type from
// the address' raw bytes.  If the type cannot be determined, an error is
// returned.
func deriveNetAddressType(addrBytes []byte) (NetAddressType, error) {
	len := len(addrBytes)
	switch {
	case isIPv4(addrBytes):
		return IPv4Address, nil
	case len == 10:
		return TORv2Address, nil
	case len == 16 && isOnionCatTor(addrBytes):
		return TORv2Address, nil
	case len == 16:
		return IPv6Address, nil
	}
	return UnknownAddressType, makeError(ErrUnknownAddressType,
		"unable to determine address type from raw network address bytes")
}

// assertNetAddressTypeValid returns an error if the suggested address type does
// not appear to match the provided address.
func assertNetAddressTypeValid(netAddressType NetAddressType, addrBytes []byte) error {
	derivedAddressType, err := deriveNetAddressType(addrBytes)
	if err != nil {
		return err
	}

	if netAddressType != derivedAddressType {
		str := fmt.Sprintf("derived address type does not match expected value"+
			" (got %v, expected %v)", derivedAddressType, netAddressType)
		return makeError(ErrMismatchedAddressType, str)
	}

	return nil
}

// NewNetAddressByType creates a new network address using the provided
// parameters.  If the provided network id does not appear to match the address,
// an error is returned.
func NewNetAddressByType(netAddressType NetAddressType, addrBytes []byte, port uint16, timestamp time.Time, services ServiceFlag) (*NetAddress, error) {
	canonicalizedIP := canonicalizeIP(netAddressType, addrBytes)
	err := assertNetAddressTypeValid(netAddressType, canonicalizedIP)
	if err != nil {
		return nil, err
	}
	return &NetAddress{
		Type:      netAddressType,
		IP:        canonicalizedIP,
		Port:      port,
		Services:  services,
		Timestamp: timestamp,
	}, nil
}

// newAddressFromString creates a new address manager network address from
// the provided string.  The address is expected to be provided in the format
// host:port.
func (a *AddrManager) newAddressFromString(addr string) (*NetAddress, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}

	networkID, addrBytes, err := HostToBytes(host)
	if err != nil {
		return nil, err
	}
	if networkID == UnknownAddressType {
		str := fmt.Sprintf("failed to deserialize address %s", addr)
		return nil, makeError(ErrUnknownAddressType, str)
	}
	// Return error here if the network id is not known.
	timestamp := time.Unix(time.Now().Unix(), 0)
	return NewNetAddressByType(networkID, addrBytes, uint16(port), timestamp,
		sfNodeNetwork)
}

// NewNetAddress creates a new address manager network address given an ip,
// port, and the supported service flags for the address.  IP must be an IPv4 or
// IPv6 address or a 10-byte TORv2 public key.
func NewNetAddress(ip net.IP, port uint16, services ServiceFlag) *NetAddress {
	netAddressType, _ := deriveNetAddressType(ip)
	timestamp := time.Unix(time.Now().Unix(), 0)
	canonicalizedIP := canonicalizeIP(netAddressType, ip)
	return &NetAddress{
		Type:      netAddressType,
		IP:        canonicalizedIP,
		Port:      port,
		Services:  services,
		Timestamp: timestamp,
	}
}
