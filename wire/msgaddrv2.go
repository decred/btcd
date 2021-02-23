// Copyright (c) 2013-2015 The btcsuite developers
// Copyright (c) 2015-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/decred/dcrd/addrmgr/v2"
)

// MaxAddrPerV2Msg is the maximum number of addresses that can be in a single
// Decred addrv2 protocol message.
const MaxAddrPerV2Msg = 1000

// MsgAddrV2 implements the Message interface and represents a wire
// addrv2 message.  It is used to provide a list of known active peers on the
// network.  An active peer is considered one that has transmitted a message
// within the last 3 hours.  Nodes which have not transmitted in that time
// frame should be forgotten.  Each message is limited to a maximum number of
// addresses.
type MsgAddrV2 struct {
	// AddrList contains the addresses that will be sent to or have been
	// received from a peer.  Instead of manually appending addresses to this
	// field directly, consumers should use the convenience functions on an
	// instance of this message to add addresses.
	AddrList []*addrmgr.NetAddress
}

// AddAddress adds a known address to the message.  If the maximum number of
// addresses has been reached, then an error is returned.
func (msg *MsgAddrV2) AddAddress(na *addrmgr.NetAddress) error {
	const op = "MsgAddrV2.AddAddress"
	if len(msg.AddrList)+1 > MaxAddrPerV2Msg {
		msg := fmt.Sprintf("too many addresses in message [max %v]",
			MaxAddrPerV2Msg)
		return messageError(op, ErrTooManyAddrs, msg)
	}

	msg.AddrList = append(msg.AddrList, na)
	return nil
}

// AddAddresses adds multiple known addresses to the message.  If the number of
// addresses exceeds the maximum allowed then an error is returned.
func (msg *MsgAddrV2) AddAddresses(netAddrs ...*addrmgr.NetAddress) error {
	for _, na := range netAddrs {
		err := msg.AddAddress(na)
		if err != nil {
			return err
		}
	}
	return nil
}

// ClearAddresses removes all addresses from the message.
func (msg *MsgAddrV2) ClearAddresses() {
	msg.AddrList = []*addrmgr.NetAddress{}
}

// readAddrmgrNetAddress reads an encoded addrmgr.NetAddress from the provided
// reader.
func readAddrmgrNetAddress(op string, r io.Reader, pver uint32) (*addrmgr.NetAddress, error) {
	type netAddress struct {
		Timestamp time.Time
		Services  ServiceFlag
		Port      uint16
		Type      addrmgr.NetAddressType
	}
	na := &netAddress{}

	err := readElement(r, (*int64Time)(&na.Timestamp))
	if err != nil {
		return nil, err
	}

	// Read the service flags.
	err = readElement(r, &na.Services)
	if err != nil {
		return nil, err
	}

	// Read the network id to determine the expected length of the ip field.
	err = readElement(r, &na.Type)
	if err != nil {
		return nil, err
	}

	// Read the ip bytes with a length varying by the network id type.
	var ipBytes []byte
	switch na.Type {
	case addrmgr.IPv4Address:
		var ip [4]byte
		err := readElement(r, &ip)
		if err != nil {
			return nil, err
		}
		ipBytes = ip[:]
	case addrmgr.TORv2Address:
		var ip [10]byte
		err := readElement(r, &ip)
		if err != nil {
			return nil, err
		}
		ipBytes = ip[:]
	case addrmgr.IPv6Address:
		var ip [16]byte
		err := readElement(r, &ip)
		if err != nil {
			return nil, err
		}
		ipBytes = ip[:]
	default:
		msg := fmt.Sprintf("unsupported network address type %v", na.Type)
		return nil, messageError(op, ErrInvalidMsg, msg)
	}

	err = readElement(r, &na.Port)
	if err != nil {
		return nil, err
	}

	return addrmgr.NewNetAddressByType(na.Type, ipBytes, na.Port,
		na.Timestamp, addrmgr.ServiceFlag(na.Services))
}

// writeAddrmgrNetAddress serializes an address manager network address to the
// provided writer.
func writeAddrmgrNetAddress(op string, w io.Writer, pver uint32, na *addrmgr.NetAddress) error {
	err := writeElement(w, na.Timestamp.Unix())
	if err != nil {
		return err
	}

	err = writeElements(w, na.Services, na.Type)
	if err != nil {
		return err
	}

	netAddrIP := na.IP
	switch na.Type {
	case addrmgr.IPv4Address:
		var ip [4]byte
		if netAddrIP != nil {
			copy(ip[:], netAddrIP)
		}
		err = writeElement(w, ip)
		if err != nil {
			return err
		}
	case addrmgr.TORv2Address:
		var ip [10]byte
		if netAddrIP != nil {
			pubkey := netAddrIP[6:]
			copy(ip[:], pubkey)
		}
		err = writeElement(w, ip)
		if err != nil {
			return err
		}
	case addrmgr.IPv6Address:
		var ip [16]byte
		if netAddrIP != nil {
			copy(ip[:], net.IP(netAddrIP).To16())
		}
		err = writeElement(w, ip)
		if err != nil {
			return err
		}
	default:
		msg := fmt.Sprintf("unrecognized network address type %v", na.Type)
		return messageError(op, ErrInvalidMsg, msg)
	}

	return writeElement(w, na.Port)
}

// maxNetAddressPayloadV2 returns the max payload size for an address manager
// network address based on the protocol version.
func maxNetAddressPayloadV2(pver uint32) uint32 {
	const timestampSize = 8
	const servicesSize = 8
	const addressTypeSize = 1
	const maxAddressSize = 16
	const portSize = 2
	return timestampSize + servicesSize + addressTypeSize + maxAddressSize +
		portSize
}

// BtcDecode decodes r using the wire protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgAddrV2) BtcDecode(r io.Reader, pver uint32) error {
	const op = "MsgAddrV2.BtcDecode"

	// Ensure peers sending msgaddrv2 are on the expected minimum version.
	if pver < AddrV2Version {
		msg := fmt.Sprintf("%s message invalid for protocol version %d",
			msg.Command(), pver)
		return messageError(op, ErrMsgInvalidForPVer, msg)
	}

	// Read the total number of addresses in this message.
	count, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	if count == 0 {
		return messageError(op, ErrTooFewAddrs,
			"no addresses for message [count 0, min 1]")
	}

	// Limit to max addresses per message.
	if count > MaxAddrPerV2Msg {
		msg := fmt.Sprintf("too many addresses for message [count %v, max %v]",
			count, MaxAddrPerV2Msg)
		return messageError(op, ErrTooManyAddrs, msg)
	}

	msg.AddrList = make([]*addrmgr.NetAddress, 0, count)

	for i := uint64(0); i < count; i++ {
		netAddr, err := readAddrmgrNetAddress(op, r, pver)
		if err != nil {
			return err
		}
		msg.AddAddress(netAddr)
	}
	return nil
}

// BtcEncode encodes the receiver to w using the wire protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgAddrV2) BtcEncode(w io.Writer, pver uint32) error {
	const op = "MsgAddrV2.BtcEncode"
	if pver < AddrV2Version {
		msg := fmt.Sprintf("%s message invalid for protocol version %d",
			msg.Command(), pver)
		return messageError(op, ErrMsgInvalidForPVer, msg)
	}

	count := len(msg.AddrList)
	if count > MaxAddrPerV2Msg {
		msg := fmt.Sprintf("too many addresses for message [count %v, max %v]",
			count, MaxAddrPerV2Msg)
		return messageError(op, ErrTooManyAddrs, msg)
	}

	if count == 0 {
		return messageError(op, ErrTooFewAddrs,
			"no addresses for message [count 0, min 1]")
	}

	err := WriteVarInt(w, pver, uint64(count))
	if err != nil {
		return err
	}

	for _, na := range msg.AddrList {
		err = writeAddrmgrNetAddress(op, w, pver, na)
		if err != nil {
			return err
		}
	}

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgAddrV2) Command() string {
	return CmdAddrV2
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgAddrV2) MaxPayloadLength(pver uint32) uint32 {
	if pver < AddrV2Version {
		return 0
	}

	// Num addresses (size of varInt for max address per message) + max allowed
	// addresses * max address size.
	return uint32(VarIntSerializeSize(MaxAddrPerV2Msg)) +
		(MaxAddrPerV2Msg * maxNetAddressPayloadV2(pver))
}

// NewMsgAddrV2 returns a new wire addrv2 message that conforms to the
// Message interface.  See MsgAddr for details.
func NewMsgAddrV2() *MsgAddrV2 {
	return &MsgAddrV2{
		AddrList: make([]*addrmgr.NetAddress, 0, MaxAddrPerV2Msg),
	}
}
