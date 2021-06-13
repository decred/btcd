// Copyright (c) 2015-2016 The btcsuite developers
// Copyright (c) 2016-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package database

// ErrorKind identifies a kind of error.  It has full support for errors.Is and
// errors.As, so the caller can directly check against an error kind when
// determining the reason for an error.
type ErrorKind string

// These constants are used to identify a specific database Error.
const (
	// ------------------------------------------
	// Errors related to driver registration.
	// ------------------------------------------

	// ErrDbTypeRegistered indicates two different database drivers
	// attempt to register with the name database type.
	ErrDbTypeRegistered = ErrorKind("ErrDbTypeRegistered")

	// ------------------------------------------
	// Errors related to database functions.
	// ------------------------------------------

	// ErrDbUnknownType indicates there is no driver registered for
	// the specified database type.
	ErrDbUnknownType = ErrorKind("ErrDbUnknownType")

	// ErrDbDoesNotExist indicates open is called for a database that
	// does not exist.
	ErrDbDoesNotExist = ErrorKind("ErrDbDoesNotExist")

	// ErrDbExists indicates create is called for a database that
	// already exists.
	ErrDbExists = ErrorKind("ErrDbExists")

	// ErrDbNotOpen indicates a database instance is accessed before
	// it is opened or after it is closed.
	ErrDbNotOpen = ErrorKind("ErrDbNotOpen")

	// ErrDbAlreadyOpen indicates open was called on a database that
	// is already open.
	ErrDbAlreadyOpen = ErrorKind("ErrDbAlreadyOpen")

	// ErrInvalid indicates the specified database is not valid.
	ErrInvalid = ErrorKind("ErrInvalid")

	// ErrCorruption indicates a checksum failure occurred which invariably
	// means the database is corrupt.
	ErrCorruption = ErrorKind("ErrCorruption")

	// ------------------------------------------
	// Errors related to database transactions.
	// ------------------------------------------

	// ErrTxClosed indicates an attempt was made to commit or rollback a
	// transaction that has already had one of those operations performed.
	ErrTxClosed = ErrorKind("ErrTxClosed")

	// ErrTxNotWritable indicates an operation that requires write access to
	// the database was attempted against a read-only transaction.
	ErrTxNotWritable = ErrorKind("ErrTxNotWritable")

	// ------------------------------------------
	// Errors related to metadata operations.
	// ------------------------------------------

	// ErrBucketNotFound indicates an attempt to access a bucket that has
	// not been created yet.
	ErrBucketNotFound = ErrorKind("ErrBucketNotFound")

	// ErrBucketExists indicates an attempt to create a bucket that already
	// exists.
	ErrBucketExists = ErrorKind("ErrBucketExists")

	// ErrBucketNameRequired indicates an attempt to create a bucket with a
	// blank name.
	ErrBucketNameRequired = ErrorKind("ErrBucketNameRequired")

	// ErrKeyRequired indicates at attempt to insert a zero-length key.
	ErrKeyRequired = ErrorKind("ErrKeyRequired")

	// ErrKeyTooLarge indicates an attempt to insert a key that is larger
	// than the max allowed key size.  The max key size depends on the
	// specific backend driver being used.  As a general rule, key sizes
	// should be relatively, so this should rarely be an issue.
	ErrKeyTooLarge = ErrorKind("ErrKeyTooLarge")

	// ErrValueTooLarge indicates an attempt to insert a value that is
	// larger than max allowed value size.  The max key size depends on the
	// specific backend driver being used.
	ErrValueTooLarge = ErrorKind("ErrValueTooLarge")

	// ErrIncompatibleValue indicates the value in question is invalid for
	// the specific requested operation.  For example, trying create or
	// delete a bucket with an existing non-bucket key, attempting to create
	// or delete a non-bucket key with an existing bucket key, or trying to
	// delete a value via a cursor when it points to a nested bucket.
	ErrIncompatibleValue = ErrorKind("ErrIncompatibleValue")

	// ErrValueNotFound indicates no value found for the provided key.
	ErrValueNotFound = ErrorKind("ErrValueNotFound")

	// ------------------------------------------
	// Errors related to block I/O operations.
	// ------------------------------------------

	// ErrBlockNotFound indicates a block with the provided hash does not
	// exist in the database.
	ErrBlockNotFound = ErrorKind("ErrBlockNotFound")

	// ErrBlockExists indicates a block with the provided hash already
	// exists in the database.
	ErrBlockExists = ErrorKind("ErrBlockExists")

	// ErrBlockRegionInvalid indicates a region that exceeds the bounds of
	// the specified block was requested.  When the hash provided by the
	// region does not correspond to an existing block, the error will be
	// ErrBlockNotFound instead.
	ErrBlockRegionInvalid = ErrorKind("ErrBlockRegionInvalid")

	// ------------------------------------------
	// Support for driver-specific errors.
	// ------------------------------------------

	// ErrDriverSpecific indicates the Err field is a driver-specific error.
	// This provides a mechanism for drivers to plug-in their own custom
	// errors for any situations which aren't already covered by the error
	// codes provided by this package.
	ErrDriverSpecific = ErrorKind("ErrDriverSpecific")
)

// Error satisfies the error interface and prints human-readable errors.
func (e ErrorKind) Error() string {
	return string(e)
}

// Error identifies an error related to database operation. It has
// full support for errors.Is and errors.As, so the caller can ascertain the
// specific reason for the error by checking the underlying error.
type Error struct {
	Err         error
	RawErr      error
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
