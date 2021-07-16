// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

// UtxoBackendIterator represents an iterator over the key/value pairs in a
// UtxoBackend in key order.
//
// When an error is encountered, any iteration method will return false and will
// yield no key/value pair.  The error can be queried by calling the Error
// method.
//
// Release must always be called on the iterator after use whether an error
// occurred or not.
//
// The interface contract does NOT require that these methods are safe for
// concurrent access.
type UtxoBackendIterator interface {
	// First moves the iterator to the first key/value pair.  If the iterator only
	// contains one key/value pair then First and Last would move to the same
	// key/value pair.  It returns whether the pair that is moved to exists.
	First() bool

	// Last moves the iterator to the last key/value pair.  If the iterator only
	// contains one key/value pair then First and Last would move to the same
	// key/value pair.  It returns whether the pair that is moved to exists.
	Last() bool

	// Seek moves the iterator to the first key/value pair whose key is greater
	// than or equal to the given key.  It returns whether the pair that is moved
	// to exists.
	//
	// It is safe to modify the contents of the argument after Seek returns.
	Seek(key []byte) bool

	// Next moves the iterator to the next key/value pair.  It returns false if
	// the iterator is exhausted.
	Next() bool

	// Prev moves the iterator to the previous key/value pair.  It returns false
	// if the iterator is exhausted.
	Prev() bool

	// Error returns any accumulated error.  Exhausting all of the key/value pairs
	// is not considered to be an error.
	Error() error

	// Key returns the key of the current key/value pair, or nil if done.  The
	// caller should not modify the contents of the returned slice, and its
	// contents may change on the next call to any iteration method.
	Key() []byte

	// Value returns the value of the current key/value pair, or nil if done.  The
	// caller should not modify the contents of the returned slice, and its
	// contents may change on the next call to any iteration method.
	Value() []byte

	// Release releases the iterator.  An iterator must always be released after
	// use, but it is not necessary to read an iterator until exhaustion before
	// releasing it.
	Release()
}
