// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"errors"
	"fmt"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

// UtxoBackendTx represents a UtxoBackend transaction.
//
// As would be expected with a transaction, no changes will be saved to the
// underlying UtxoBackend until it has been committed.  The transaction will
// only provide a view of the database at the time it was created.  Transactions
// should not be long running operations.
//
// The interface contract requires that these methods are safe for concurrent
// access.
type UtxoBackendTx interface {
	// Get returns the value for the given key.  It returns nil if the key does
	// not exist.  An empty slice is returned for keys that exist but have no
	// value assigned.
	//
	// The returned slice is safe to modify.  Additionally, it is safe to modify
	// the slice passed as an argument after Get returns.
	Get(key []byte) ([]byte, error)

	// Has returns true if the key exists.
	//
	// It is safe to modify the slice passed as an argument after Has returns.
	Has(key []byte) (bool, error)

	// Put sets the value for the given key.  It overwrites any previous value for
	// that key.
	//
	// It is safe to modify the slice passed as an argument after Put returns.
	Put(key, value []byte) error

	// Delete removes the given key.
	//
	// It is safe to modify the slice passed as an argument after Delete returns.
	Delete(key []byte) error

	// NewIterator returns an iterator for the latest snapshot of the transaction.
	// The returned iterator is NOT safe for concurrent use, but it is safe to use
	// multiple iterators concurrently, with each in a dedicated goroutine.
	//
	// The prefix parameter allows for slicing the iterator to only contain keys
	// with the given prefix.  A nil prefix is treated as a key BEFORE all keys.
	//
	// NOTE: The contents of any slice returned by the iterator should NOT be
	// modified unless noted otherwise.
	//
	// The iterator must be released after use, by calling Release method.
	NewIterator(prefix []byte) UtxoBackendIterator

	// Commit commits the transaction.  If the returned error is not nil, then the
	// transaction is not committed and can either be retried or discarded.
	//
	// Other methods should not be called after the transaction has been
	// committed.
	Commit() error

	// Discard discards the transaction.  This method is a noop if the
	// transaction is already closed (either committed or discarded).
	//
	// Other methods should not be called after the transaction has been
	// discarded.
	Discard()
}

// levelDbUtxoBackendTx represents a UtxoBackend transaction.  It wraps an
// underlying leveldb transaction and implements the UtxoBackendTx interface.
type levelDbUtxoBackendTx struct {
	*leveldb.Transaction
}

// Get returns the value for the given key.  It returns nil if the key does not
// exist.  An empty slice is returned for keys that exist but have no value
// assigned.
//
// The returned slice is safe to modify.  Additionally, it is safe to modify the
// slice passed as an argument after Get returns.
func (tx *levelDbUtxoBackendTx) Get(key []byte) ([]byte, error) {
	serialized, err := tx.Transaction.Get(key, nil)
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get key %x from leveldb transaction: %v",
			key, err)
	}
	return serialized, nil
}

// Has returns true if the key exists.
//
// It is safe to modify the slice passed as an argument after Has returns.
func (tx *levelDbUtxoBackendTx) Has(key []byte) (bool, error) {
	has, err := tx.Transaction.Has(key, nil)
	if err != nil {
		return false, fmt.Errorf("failed to get existence of key %x from leveldb "+
			"transaction: %v", key, err)
	}
	return has, nil
}

// Put sets the value for the given key.  It overwrites any previous value for
// that key.
//
// It is safe to modify the slice passed as an argument after Put returns.
func (tx *levelDbUtxoBackendTx) Put(key, value []byte) error {
	err := tx.Transaction.Put(key, value, nil)
	if err != nil {
		return fmt.Errorf("failed to put key %x (value %x) to leveldb "+
			"transaction: %v", key, value, err)
	}
	return nil
}

// Delete removes the given key.
//
// It is safe to modify the slice passed as an argument after Delete returns.
func (tx *levelDbUtxoBackendTx) Delete(key []byte) error {
	err := tx.Transaction.Delete(key, nil)
	if err != nil {
		return fmt.Errorf("failed to delete key %x from leveldb transaction: %v",
			key, err)
	}
	return nil
}

// NewIterator returns an iterator for the latest snapshot of the transaction.
// The returned iterator is NOT safe for concurrent use, but it is safe to use
// multiple iterators concurrently, with each in a dedicated goroutine.
//
// The prefix parameter allows for slicing the iterator to only contain keys
// with the given prefix.  A nil prefix is treated as a key BEFORE all keys.
//
// NOTE: The contents of any slice returned by the iterator should NOT be
// modified unless noted otherwise.
//
// The iterator must be released after use, by calling Release method.
func (tx *levelDbUtxoBackendTx) NewIterator(prefix []byte) UtxoBackendIterator {
	var slice *util.Range
	if prefix != nil {
		slice = util.BytesPrefix(prefix)
	}
	return tx.Transaction.NewIterator(slice, nil)
}

// Ensure levelDbUtxoBackendTx implements the UtxoBackendTx interface.
var _ UtxoBackendTx = (*levelDbUtxoBackendTx)(nil)
