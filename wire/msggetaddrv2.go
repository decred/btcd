// Copyright (c) 2013-2015 The btcsuite developers
// Copyright (c) 2015-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"
)

// MsgGetAddrV2 implements the Message interface and represents a decred
// getaddr message.  It is used to request a list of known active peers on the
// network from a peer to help identify potential nodes.  The list is returned
// via one or more addrv2 messages (MsgAddrV2).
//
// This message has no payload.
type MsgGetAddrV2 struct{}

// BtcDecode decodes r using the wire protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgGetAddrV2) BtcDecode(r io.Reader, pver uint32) error {
	const op = "MsgGetAddrV2.BtcDecode"
	if pver < AddrV2Version {
		msg := fmt.Sprintf("%s message invalid for protocol version %d",
			msg.Command(), pver)
		return messageError(op, ErrMsgInvalidForPVer, msg)
	}

	return nil
}

// BtcEncode encodes the receiver to w using the wire protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgGetAddrV2) BtcEncode(w io.Writer, pver uint32) error {
	const op = "MsgGetAddrV2.BtcEncode"
	if pver < AddrV2Version {
		msg := fmt.Sprintf("%s message invalid for protocol version %d",
			msg.Command(), pver)
		return messageError(op, ErrMsgInvalidForPVer, msg)
	}

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgGetAddrV2) Command() string {
	return CmdGetAddrV2
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgGetAddrV2) MaxPayloadLength(pver uint32) uint32 {
	return 0
}

// NewMsgGetAddrV2 returns a new Decred getaddr message that conforms to the
// Message interface.  See MsgGetAddr for details.
func NewMsgGetAddrV2() *MsgGetAddrV2 {
	return &MsgGetAddrV2{}
}
