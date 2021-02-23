// Copyright (c) 2013-2015 The btcsuite developers
// Copyright (c) 2015-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
)

// ErrorCode describes a kind of message error.
type ErrorCode int

// These constants are used to identify a specific Error.
const (
	// ErrNonCanonicalVarInt is returned when a variable length integer is
	// not canonically encoded.
	ErrNonCanonicalVarInt ErrorCode = iota

	// ErrVarStringTooLong is returned when a variable string exceeds the
	// maximum message size allowed.
	ErrVarStringTooLong

	// ErrVarBytesTooLong is returned when a variable-length byte slice
	// exceeds the maximum message size allowed.
	ErrVarBytesTooLong

	// ErrCmdTooLong is returned when a command exceeds the maximum command
	// size allowed.
	ErrCmdTooLong

	// ErrPayloadTooLarge is returned when a payload exceeds the maximum
	// payload size allowed.
	ErrPayloadTooLarge

	// ErrWrongNetwork is returned when a message intended for a different
	// network is received.
	ErrWrongNetwork

	// ErrMalformedCmd is returned when a malformed command is received.
	ErrMalformedCmd

	// ErrUnknownCmd is returned when an unknown command is received.
	ErrUnknownCmd

	// ErrPayloadChecksum is returned when a message with an invalid checksum
	// is received.
	ErrPayloadChecksum

	// ErrTooFewAddrs is returned when an address list has zero addresses.
	ErrTooFewAddrs

	// ErrTooManyAddrs is returned when an address list exceeds the maximum
	// allowed.
	ErrTooManyAddrs

	// ErrTooManyTxs is returned when a the number of transactions exceed the
	// maximum allowed.
	ErrTooManyTxs

	// ErrMsgInvalidForPVer is returned when a message is invalid for
	// the expected protocol version.
	ErrMsgInvalidForPVer

	// ErrFilterTooLarge is returned when a committed filter exceeds
	// the maximum size allowed.
	ErrFilterTooLarge

	// ErrTooManyProofs is returned when the numeber of proof hashes
	// exceeds the maximum allowed.
	ErrTooManyProofs

	// ErrTooManyFilterTypes is returned when the number of filter types
	// exceeds the maximum allowed.
	ErrTooManyFilterTypes

	// ErrTooManyLocators is returned when the number of block locators exceed
	// the maximum allowed.
	ErrTooManyLocators

	// ErrTooManyVectors is returned when the number of inventory vectors
	// exceed the maximum allowed.
	ErrTooManyVectors

	// ErrTooManyHeaders is returned when the number of block headers exceed
	// the maximum allowed.
	ErrTooManyHeaders

	// ErrHeaderContainsTxs is returned when a header's transactions
	// count is greater than zero.
	ErrHeaderContainsTxs

	// ErrTooManyVotes is returned when the number of vote hashes exceed the
	// maximum allowed.
	ErrTooManyVotes

	// ErrTooManyBlocks is returned when the number of block hashes exceed the
	// maximum allowed.
	ErrTooManyBlocks

	// ErrMismatchedWitnessCount returned when a transaction has unequal witness
	// and prefix txin quantities.
	ErrMismatchedWitnessCount

	// ErrUnknownTxType is returned when a transaction type is unknown.
	ErrUnknownTxType

	// ErrReadInPrefixFromWitnessOnlyTx is returned when attempting to read a
	// transaction input prefix from a witness only transaction.
	ErrReadInPrefixFromWitnessOnlyTx

	// ErrInvalidMsg is returned for an invalid message structure.
	ErrInvalidMsg

	// ErrUserAgentTooLong is returned when the provided user agent exceeds
	// the maximum allowed.
	ErrUserAgentTooLong

	// ErrTooManyFilterHeaders is returned when the number of committed filter
	// headers exceed the maximum allowed.
	ErrTooManyFilterHeaders

	// ErrMalformedStrictString is returned when a string that has strict
	// formatting requirements does not conform to the requirements.
	ErrMalformedStrictString

	// ErrTooManyInitialStateTypes is returned when the number of initial
	// state types is larger than the maximum allowed by the protocol.
	ErrTooManyInitStateTypes

	// ErrInitialStateTypeTooLong is returned when an individual initial
	// state type is longer than allowed by the protocol.
	ErrInitStateTypeTooLong

	// ErrTooManyTSpends is returned when the number of tspend hashes
	// exceeds the maximum allowed.
	ErrTooManyTSpends
)

// Map of ErrorCode values back to their constant names for pretty printing.
var errorCodeStrings = map[ErrorCode]string{
	ErrNonCanonicalVarInt:            "ErrNonCanonicalVarInt",
	ErrVarStringTooLong:              "ErrVarStringTooLong",
	ErrVarBytesTooLong:               "ErrVarBytesTooLong",
	ErrCmdTooLong:                    "ErrCmdTooLong",
	ErrPayloadTooLarge:               "ErrPayloadTooLarge",
	ErrWrongNetwork:                  "ErrWrongNetwork",
	ErrMalformedCmd:                  "ErrMalformedCmd",
	ErrUnknownCmd:                    "ErrUnknownCmd",
	ErrPayloadChecksum:               "ErrPayloadChecksum",
	ErrTooManyAddrs:                  "ErrTooManyAddrs",
	ErrTooManyTxs:                    "ErrTooManyTxs",
	ErrMsgInvalidForPVer:             "ErrMsgInvalidForPVer",
	ErrFilterTooLarge:                "ErrFilterTooLarge",
	ErrTooManyProofs:                 "ErrTooManyProofs",
	ErrTooManyFilterTypes:            "ErrTooManyFilterTypes",
	ErrTooManyLocators:               "ErrTooManyLocators",
	ErrTooManyVectors:                "ErrTooManyVectors",
	ErrTooManyHeaders:                "ErrTooManyHeaders",
	ErrHeaderContainsTxs:             "ErrHeaderContainsTxs",
	ErrTooManyVotes:                  "ErrTooManyVotes",
	ErrTooManyBlocks:                 "ErrTooManyBlocks",
	ErrMismatchedWitnessCount:        "ErrMismatchedWitnessCount",
	ErrUnknownTxType:                 "ErrUnknownTxType",
	ErrReadInPrefixFromWitnessOnlyTx: "ErrReadInPrefixFromWitnessOnlyTx",
	ErrInvalidMsg:                    "ErrInvalidMsg",
	ErrUserAgentTooLong:              "ErrUserAgentTooLong",
	ErrTooManyFilterHeaders:          "ErrTooManyFilterHeaders",
	ErrMalformedStrictString:         "ErrMalformedStrictString",
	ErrTooManyInitStateTypes:         "ErrTooManyInitStateTypes",
	ErrInitStateTypeTooLong:          "ErrInitStateTypeTooLong",
	ErrTooManyTSpends:                "ErrTooManyTSpends",
}

// String returns the ErrorCode as a human-readable name.
func (e ErrorCode) String() string {
	if s := errorCodeStrings[e]; s != "" {
		return s
	}
	return fmt.Sprintf("Unknown ErrorCode (%d)", int(e))
}

// Error implements the error interface.
func (e ErrorCode) Error() string {
	return e.String()
}

// Is implements the interface to work with the standard library's errors.Is.
//
// It returns true in the following cases:
// - The target is a *MessageError and the error codes match
// - The target is an ErrorCode and it the error codes match
func (e ErrorCode) Is(target error) bool {
	switch target := target.(type) {
	case *MessageError:
		return e == target.ErrorCode

	case ErrorCode:
		return e == target
	}

	return false
}

// MessageError describes an issue with a message.
// An example of some potential issues are messages from the wrong decred
// network, invalid commands, mismatched checksums, and exceeding max payloads.
//
// This provides a mechanism for the caller to type assert the error to
// differentiate between general io errors such as io.EOF and issues that
// resulted from malformed messages.
type MessageError struct {
	Func        string    // Function name
	ErrorCode   ErrorCode // Describes the kind of error
	Description string    // Human readable description of the issue
}

// Error satisfies the error interface and prints human-readable errors.
func (m MessageError) Error() string {
	if m.Func != "" {
		return fmt.Sprintf("%v: %v", m.Func, m.Description)
	}
	return m.Description
}

// messageError creates an Error given a set of arguments.
func messageError(Func string, c ErrorCode, desc string) *MessageError {
	return &MessageError{Func: Func, ErrorCode: c, Description: desc}
}

// Is implements the interface to work with the standard library's errors.Is.
//
// It returns true in the following cases:
// - The target is a *MessageError and the error codes match
// - The target is an ErrorCode and it the error codes match
func (m *MessageError) Is(target error) bool {
	switch target := target.(type) {
	case *MessageError:
		return m.ErrorCode == target.ErrorCode

	case ErrorCode:
		return target == m.ErrorCode
	}

	return false
}

// Unwrap returns the underlying wrapped error if it is not ErrOther.
// Unwrap returns the ErrorCode. Else, it returns nil.
func (m *MessageError) Unwrap() error {
	return m.ErrorCode
}
