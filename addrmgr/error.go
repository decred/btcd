// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package addrmgr

// ErrorKind identifies a kind of error.  It has full support for errors.Is
// and errors.As, so the caller can directly check against an error kind
// when determining the reason for an error.
type ErrorKind string

// These constants are used to identify a specific RuleError.
const (
	// ErrAddressNotFound indicates that an attempt to perform an action on
	// was performed for an address not known to the address manager.
	ErrAddressNotFound = ErrorKind("ErrAddressNotFound")

	// ErrUnknownAddressType indicates that the network type could not be
	// determined from a network address' bytes.
	ErrUnknownAddressType = ErrorKind("ErrUnknownAddressType")

	// ErrMismatchedAddressType indicates that the network type could not be
	// determined from a network address' bytes.
	ErrMismatchedAddressType = ErrorKind("ErrMismatchedAddressType")
)

// Error satisfies the error interface and prints human-readable errors.
func (e ErrorKind) Error() string {
	return string(e)
}

// Error identifies a mining rule rule violation. It has full support for
// errors.Is and errors.As, so the caller can ascertain the specific reason
// for the error by checking the underlying error. It is used to indicate
// that processing of a block or transaction failed due to one of the many
// validation rules.
type Error struct {
	Err         error
	Description string
}

// Error satisfies the error interface and prints human-readable errors.
func (e Error) Error() string {
	return e.Description
}

// Unwrap returns the underlying wrapped error.
func (e Error) Unwrap() error {
	return e.Err
}

// makeError creates an Error given a set of arguments.
func makeError(kind ErrorKind, desc string) Error {
	return Error{Err: kind, Description: desc}
}
