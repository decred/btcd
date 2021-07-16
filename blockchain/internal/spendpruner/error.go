// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package spendpruner

// ErrorKind identifies a kind of error.  It has full support for errors.Is and
// errors.As, so the caller can directly check against an error kind when
// determining the reason for an error.
type ErrorKind string

// These constants are used to identify a specific PruneError.
const (
	// ErrNoConsumer indicates a spend journal consumer hash does not exist.
	ErrNoConsumer = ErrorKind("ErrNoConsumer")

	// ErrLoadSpendDeps indicates an error loading consumer
	// spend dependencies.
	ErrLoadSpendDeps = ErrorKind("ErrLoadSpendDeps")

	// ErrNeedSpendData indicates an error asserting a spend data dependency.
	ErrNeedSpendData = ErrorKind("ErrNeedSpendData")

	// ErrNeedSpendData indicates an error updating consumer spend dependencies.
	ErrUpdateConsumerDeps = ErrorKind("ErrUpdateConsumerDeps")
)

// Error satisfies the error interface and prints human-readable errors.
func (e ErrorKind) Error() string {
	return string(e)
}

// PruneError identifies a spend journal pruner error. It has full support
// for errors.Is and errors.As, so the caller can ascertain the specific
// reason for the error by checking the underlying error.
type PruneError struct {
	Description string
	Err         error
}

// Error satisfies the error interface and prints human-readable errors.
func (e PruneError) Error() string {
	return e.Description
}

// Unwrap returns the underlying wrapped error.
func (e PruneError) Unwrap() error {
	return e.Err
}

// pruneError creates a PruneError given a set of arguments.
func pruneError(kind ErrorKind, desc string) PruneError {
	return PruneError{Err: kind, Description: desc}
}
