// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2015-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"errors"
	"io"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/addrmgr/v2"
)

// TestAddrV2 tests the MsgAddrV2 API.
func TestAddrV2(t *testing.T) {
	pver := ProtocolVersion

	// Ensure the command is expected value.
	wantCmd := "addrv2"
	msg := NewMsgAddrV2()
	if cmd := msg.Command(); cmd != wantCmd {
		t.Errorf("NewMsgAddrV2: wrong command - got %v want %v",
			cmd, wantCmd)
	}

	// Ensure max payload is expected value for latest protocol version.
	wantPayload := uint32(35003)
	maxPayload := msg.MaxPayloadLength(pver)
	if maxPayload != wantPayload {
		t.Errorf("MaxPayloadLength: wrong max payload length for "+
			"protocol version %d - got %v, want %v", pver,
			maxPayload, wantPayload)
	}

	// Ensure max payload length is not more than MaxMessagePayload.
	if maxPayload > MaxMessagePayload {
		t.Fatalf("MaxPayloadLength: payload length (%v) for protocol "+
			"version %d exceeds MaxMessagePayload (%v).", maxPayload, pver,
			MaxMessagePayload)
	}

	// Ensure NetAddresses are added properly.
	na := addrmgr.NewNetAddress(net.ParseIP("127.0.0.1"), 8333,
		addrmgr.ServiceFlag(SFNodeNetwork))
	err := msg.AddAddress(na)
	if err != nil {
		t.Errorf("AddAddress: %v", err)
	}
	if msg.AddrList[0] != na {
		t.Errorf("AddAddress: wrong address added - got %v, want %v",
			spew.Sprint(msg.AddrList[0]), spew.Sprint(na))
	}

	// Ensure the address list is cleared properly.
	msg.ClearAddresses()
	if len(msg.AddrList) != 0 {
		t.Errorf("ClearAddresses: address list is not empty - "+
			"got %v [%v], want %v", len(msg.AddrList),
			spew.Sprint(msg.AddrList[0]), 0)
	}

	// Ensure adding more than the max allowed addresses per message returns
	// error.
	for i := 0; i < MaxAddrPerMsg+1; i++ {
		err = msg.AddAddress(na)
	}
	if err == nil {
		t.Errorf("AddAddress: expected error on too many addresses " +
			"not received")
	}
	err = msg.AddAddresses(na)
	if err == nil {
		t.Errorf("AddAddresses: expected error on too many addresses " +
			"not received")
	}
}

// newNetAddress is a convenience function for constructing a new network
// address.
func newNetAddress(host string, port uint16) *addrmgr.NetAddress {
	timestamp := time.Unix(0x495fab29, 0) // 2009-01-03 12:15:05 -0600 CST
	addrType, addrBytes, _ := addrmgr.HostToBytes(host)
	netAddr, _ := addrmgr.NewNetAddressByType(addrType, addrBytes, port,
		timestamp, addrmgr.ServiceFlag(SFNodeNetwork))
	return netAddr
}

// TestAddrWire tests the MsgAddrV2 wire encode and decode for various numbers
// of addresses at the latest protocol version.
func TestAddrV2Wire(t *testing.T) {
	pver := ProtocolVersion
	ipv4Address := newNetAddress("127.0.0.1", 8333)
	ipv6Address := newNetAddress("2620:100::1", 8334)
	torv2Address := newNetAddress("aaaaaaaaaaaaaaaa.onion", 8335)

	tests := []struct {
		name      string
		addrs     []*addrmgr.NetAddress
		wantBytes []byte
	}{
		{
			name: "latest protocol version with one address",
			addrs: []*addrmgr.NetAddress{
				ipv4Address,
			},
			wantBytes: []byte{
				0x01,
				0x29, 0xab, 0x5f, 0x49, 0x00, 0x00, 0x00, 0x00, // Timestamp
				0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Services
				0x01,                   // Address type
				0x7f, 0x00, 0x00, 0x01, // Address bytes
				0x8d, 0x20, // Port
			},
		},
		{
			name: "latest protocol version with multiple addresses",
			addrs: []*addrmgr.NetAddress{
				ipv4Address,
				ipv6Address,
				torv2Address,
			},
			wantBytes: []byte{
				0x03,
				// IPv4 address
				0x29, 0xab, 0x5f, 0x49, 0x00, 0x00, 0x00, 0x00, // Timestamp
				0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Services
				0x01,                   // Address type
				0x7f, 0x00, 0x00, 0x01, // Address bytes
				0x8d, 0x20, // Port
				// IPv6 address
				0x29, 0xab, 0x5f, 0x49, 0x00, 0x00, 0x00, 0x00,
				0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x02,
				0x26, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				0x8e, 0x20,
				// TORv2 address
				0x29, 0xab, 0x5f, 0x49, 0x00, 0x00, 0x00, 0x00,
				0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x03,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x8f, 0x20,
			},
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		subject := NewMsgAddrV2()
		subject.AddAddresses(test.addrs...)

		// Encode the message to the wire format and ensure it serializes
		// correctly.
		var buf bytes.Buffer
		err := subject.BtcEncode(&buf, pver)
		if err != nil {
			t.Errorf("%q: error encoding message - %v", test.name, err)
			continue
		}
		if !reflect.DeepEqual(buf.Bytes(), test.wantBytes) {
			t.Errorf("%q: mismatched bytes -- got: %s want: %s", test.name,
				spew.Sdump(buf.Bytes()), spew.Sdump(test.wantBytes))
			continue
		}

		// Decode the message from wire format and ensure it deserializes
		// correctly.
		var msg MsgAddrV2
		rbuf := bytes.NewReader(test.wantBytes)
		err = msg.BtcDecode(rbuf, pver)
		if err != nil {
			t.Errorf("%q: error decoding message - %v", test.name, err)
			continue
		}
		if !reflect.DeepEqual(&msg, subject) {
			t.Errorf("%q: mismatched message - got: %s want: %s", i,
				spew.Sdump(msg), spew.Sdump(subject))
			continue
		}
	}
}

// TestAddrWireErrors performs negative tests against wire encode and decode
// of MsgAddrV2 to confirm error paths work correctly.
func TestAddrV2WireErrors(t *testing.T) {
	pver := ProtocolVersion
	na := newNetAddress("127.0.0.1", 8333)
	addrs := []*addrmgr.NetAddress{na}

	tests := []struct {
		name     string
		addrs    []*addrmgr.NetAddress // Value to encode
		bytes    []byte                // Wire encoding
		pver     uint32                // Protocol version for wire encoding
		ioLimit  int                   // Max size of fixed buffer to induce errors
		writeErr error                 // Expected write error
		readErr  error                 // Expected read error
	}{
		{
			name:     "unsupported protocol version",
			pver:     AddrV2Version - 1,
			addrs:    addrs,
			bytes:    []byte{0x01},
			ioLimit:  1,
			writeErr: ErrMsgInvalidForPVer,
			readErr:  ErrMsgInvalidForPVer,
		},
		{
			name:     "zero byte i/o limit",
			pver:     pver,
			addrs:    addrs,
			bytes:    []byte{0x00},
			ioLimit:  0,
			writeErr: io.ErrShortWrite,
			readErr:  io.EOF,
		},
		{
			name:     "one byte i/o limit",
			pver:     pver,
			addrs:    addrs,
			bytes:    []byte{0x01},
			ioLimit:  1,
			writeErr: io.ErrShortWrite,
			readErr:  io.EOF,
		},
		{
			name:     "message with no addresses",
			pver:     pver,
			addrs:    nil,
			bytes:    []byte{0x00},
			ioLimit:  1,
			writeErr: ErrTooFewAddrs,
			readErr:  ErrTooFewAddrs,
		},

		{
			name: "message with too many addresses",
			pver: pver,
			addrs: func() []*addrmgr.NetAddress {
				var addrs []*addrmgr.NetAddress
				for i := 0; i < MaxAddrPerMsg+1; i++ {
					addrs = append(addrs, na)
				}
				return addrs
			}(),
			bytes:    []byte{0xfd, 0xe9, 0x03},
			ioLimit:  3,
			writeErr: ErrTooManyAddrs,
			readErr:  ErrTooManyAddrs,
		},
	}

	t.Logf("Running %d tests", len(tests))
	for _, test := range tests {
		subject := NewMsgAddrV2()
		subject.AddrList = test.addrs

		// Encode to wire format.
		w := newFixedWriter(test.ioLimit)
		err := subject.BtcEncode(w, test.pver)
		if !errors.Is(err, test.writeErr) {
			t.Errorf("%q: wrong error - got: %v, want: %v", test.name, err,
				test.writeErr)
			continue
		}

		// Decode from wire format.
		var msg MsgAddrV2
		r := newFixedReader(test.ioLimit, test.bytes)
		err = msg.BtcDecode(r, test.pver)
		if !errors.Is(err, test.readErr) {
			t.Errorf("%q: wrong error - got: %v, want: %v", test.name, err,
				test.readErr)
			continue
		}
	}
}
