// Copyright (c) 2013-2015 The btcsuite developers
// Copyright (c) 2015-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

// ErrorKind identifies a kind of error.  It has full support for errors.Is and
// errors.As, so the caller can directly check against an error kind when
// determining the reason for an error.
type ErrorKind string

// These constants are used to identify a specific Error.
const (
	// ErrNonCanonicalVarInt is returned when a variable length integer is
	// not canonically encoded.
	ErrNonCanonicalVarInt = ErrorKind("ErrNonCanonicalVarInt")

	// ErrVarStringTooLong is returned when a variable string exceeds the
	// maximum message size allowed.
	ErrVarStringTooLong = ErrorKind("ErrVarStringTooLong")

	// ErrVarBytesTooLong is returned when a variable-length byte slice
	// exceeds the maximum message size allowed.
	ErrVarBytesTooLong = ErrorKind("ErrVarBytesTooLong")

	// ErrCmdTooLong is returned when a command exceeds the maximum command
	// size allowed.
	ErrCmdTooLong = ErrorKind("ErrCmdTooLong")

	// ErrPayloadTooLarge is returned when a payload exceeds the maximum
	// payload size allowed.
	ErrPayloadTooLarge = ErrorKind("ErrPayloadTooLarge")

	// ErrWrongNetwork is returned when a message intended for a different
	// network is received.
	ErrWrongNetwork = ErrorKind("ErrWrongNetwork")

	// ErrMalformedCmd is returned when a malformed command is received.
	ErrMalformedCmd = ErrorKind("ErrMalformedCmd")

	// ErrUnknownCmd is returned when an unknown command is received.
	ErrUnknownCmd = ErrorKind("ErrUnknownCmd")

	// ErrPayloadChecksum is returned when a message with an invalid checksum
	// is received.
	ErrPayloadChecksum = ErrorKind("ErrPayloadChecksum")

	// ErrTooManyAddrs is returned when an address list exceeds the maximum
	// allowed.
	ErrTooManyAddrs = ErrorKind("ErrTooManyAddrs")

	// ErrTooManyTxs is returned when a the number of transactions exceed the
	// maximum allowed.
	ErrTooManyTxs = ErrorKind("ErrTooManyTxs")

	// ErrMsgInvalidForPVer is returned when a message is invalid for
	// the expected protocol version.
	ErrMsgInvalidForPVer = ErrorKind("ErrMsgInvalidForPVer")

	// ErrFilterTooLarge is returned when a committed filter exceeds
	// the maximum size allowed.
	ErrFilterTooLarge = ErrorKind("ErrFilterTooLarge")

	// ErrTooManyProofs is returned when the numeber of proof hashes
	// exceeds the maximum allowed.
	ErrTooManyProofs = ErrorKind("ErrTooManyProofs")

	// ErrTooManyFilterTypes is returned when the number of filter types
	// exceeds the maximum allowed.
	ErrTooManyFilterTypes = ErrorKind("ErrTooManyFilterTypes")

	// ErrTooManyLocators is returned when the number of block locators exceed
	// the maximum allowed.
	ErrTooManyLocators = ErrorKind("ErrTooManyLocators")

	// ErrTooManyVectors is returned when the number of inventory vectors
	// exceed the maximum allowed.
	ErrTooManyVectors = ErrorKind("ErrTooManyVectors")

	// ErrTooManyHeaders is returned when the number of block headers exceed
	// the maximum allowed.
	ErrTooManyHeaders = ErrorKind("ErrTooManyHeaders")

	// ErrHeaderContainsTxs is returned when a header's transactions
	// count is greater than zero.
	ErrHeaderContainsTxs = ErrorKind("ErrHeaderContainsTxs")

	// ErrTooManyVotes is returned when the number of vote hashes exceed the
	// maximum allowed.
	ErrTooManyVotes = ErrorKind("ErrTooManyVotes")

	// ErrTooManyBlocks is returned when the number of block hashes exceed the
	// maximum allowed.
	ErrTooManyBlocks = ErrorKind("ErrTooManyBlocks")

	// ErrMismatchedWitnessCount returned when a transaction has unequal witness
	// and prefix txin quantities.
	ErrMismatchedWitnessCount = ErrorKind("ErrMismatchedWitnessCount")

	// ErrUnknownTxType is returned when a transaction type is unknown.
	ErrUnknownTxType = ErrorKind("ErrUnknownTxType")

	// ErrReadInPrefixFromWitnessOnlyTx is returned when attempting to read a
	// transaction input prefix from a witness only transaction.
	ErrReadInPrefixFromWitnessOnlyTx = ErrorKind("ErrReadInPrefixFromWitnessOnlyTx")

	// ErrInvalidMsg is returned for an invalid message structure.
	ErrInvalidMsg = ErrorKind("ErrInvalidMsg")

	// ErrUserAgentTooLong is returned when the provided user agent exceeds
	// the maximum allowed.
	ErrUserAgentTooLong = ErrorKind("ErrUserAgentTooLong")

	// ErrTooManyFilterHeaders is returned when the number of committed filter
	// headers exceed the maximum allowed.
	ErrTooManyFilterHeaders = ErrorKind("ErrTooManyFilterHeaders")

	// ErrMalformedStrictString is returned when a string that has strict
	// formatting requirements does not conform to the requirements.
	ErrMalformedStrictString = ErrorKind("ErrMalformedStrictString")

	// ErrTooManyInitialStateTypes is returned when the number of initial
	// state types is larger than the maximum allowed by the protocol.
	ErrTooManyInitStateTypes = ErrorKind("ErrTooManyInitStateTypes")

	// ErrInitialStateTypeTooLong is returned when an individual initial
	// state type is longer than allowed by the protocol.
	ErrInitStateTypeTooLong = ErrorKind("ErrInitStateTypeTooLong")

	// ErrTooManyTSpends is returned when the number of tspend hashes
	// exceeds the maximum allowed.
	ErrTooManyTSpends = ErrorKind("ErrTooManyTSpends")
)

// Error satisfies the error interface and prints human-readable errors.
func (e ErrorKind) Error() string {
	return string(e)
}

// MessageError identifies an error related to wire messages. It has
// full support for errors.Is and errors.As, so the caller can
// ascertain the specific reason for the error by checking the
// underlying error.
type MessageError struct {
	Func        string
	Err         error
	Description string
}

// Error satisfies the error interface and prints human-readable errors.
func (e MessageError) Error() string {
	return e.Description
}

// Unwrap returns the underlying wrapped error.
func (e MessageError) Unwrap() error {
	return e.Err
}

// messageError creates a MessageError given a set of arguments.
func messageError(fn string, kind ErrorKind, desc string) MessageError {
	return MessageError{Func: fn, Err: kind, Description: desc}
}
