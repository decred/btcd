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

// ipString returns a string representation of the network address' IP field.
// If the ip is in the range used for TORv2 addresses then it will be
// transformed into the respective .onion address.  It does not include the
// port.
func (netAddr *NetAddress) ipString() string {
	netIP := netAddr.IP
	switch netAddr.Type {
	case TORv2Address:
		base32 := base32.StdEncoding.EncodeToString(netIP[6:])
		return strings.ToLower(base32) + ".onion"
	case TORv3Address:
		addrBytes := netIP
		checksum := calcTORv3Checksum(addrBytes)
		addrBytes = append(addrBytes, checksum[:]...)
		addrBytes = append(addrBytes, torV3VersionByte)
		base32 := base32.StdEncoding.EncodeToString(addrBytes)
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

// String returns a human-readable string for the network address.  This is
// equivalent to calling Key, but is provided so the type can be used as a
// fmt.Stringer.
func (netAddr *NetAddress) String() string {
	return netAddr.Key()
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
func deriveNetAddressType(claimedType NetAddressType, addrBytes []byte) (NetAddressType, error) {
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
	case len == 32 && claimedType == TORv3Address:
		return TORv3Address, nil
	}
	return UnknownAddressType, makeError(ErrUnknownAddressType,
		"unable to determine address type from raw network address bytes")
}

// assertNetAddressTypeValid returns an error if the suggested address type does
// not appear to match the provided address.
func assertNetAddressTypeValid(netAddressType NetAddressType, addrBytes []byte) error {
	derivedAddressType, err := deriveNetAddressType(netAddressType, addrBytes)
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

	networkID, addrBytes, err := ParseHost(host)
	if err != nil {
		return nil, err
	}
	if networkID == UnknownAddressType {
		str := fmt.Sprintf("failed to deserialize address %s", addr)
		return nil, makeError(ErrUnknownAddressType, str)
	}
	timestamp := time.Unix(time.Now().Unix(), 0)
	return NewNetAddressByType(networkID, addrBytes, uint16(port), timestamp,
		sfNodeNetwork)
}

// NewNetAddressIPPort creates a new address manager network address given an
// ip, port, and the supported service flags for the address.  The provided ip
/// MUST be a valid IPv4, IPv6, or TORv2 address.
func NewNetAddressIPPort(ip net.IP, port uint16, services ServiceFlag) *NetAddress {
	netAddressType, _ := deriveNetAddressType(UnknownAddressType, ip)
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
