// Copyright (c) 2016 The btcsuite developers
// Copyright (c) 2016-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

/*
Package indexers implements optional block chain indexes.
*/
package indexers

import (
	"context"
	"encoding/binary"
	"errors"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/database/v2"
	"github.com/decred/dcrd/dcrutil/v4"
	"github.com/decred/dcrd/wire"
)

var (
	// byteOrder is the preferred byte order used for serializing numeric
	// fields for storage in the database.
	byteOrder = binary.LittleEndian

	// errInterruptRequested indicates that an operation was cancelled due
	// to a user-requested interrupt.
	errInterruptRequested = errors.New("interrupt requested")
)

// NeedsInputser provides a generic interface for an indexer to specify the it
// requires the ability to look up inputs for a transaction.
type NeedsInputser interface {
	NeedsInputs() bool
}

// PrevScripter defines an interface that provides access to scripts and their
// associated version keyed by an outpoint.  It is used within this package as a
// generic means to provide the scripts referenced by the inputs to transactions
// within a block that are needed to index it.  The boolean return indicates
// whether or not the script and version for the provided outpoint was found.
type PrevScripter interface {
	PrevScript(*wire.OutPoint) (uint16, []byte, bool)
}

// Indexer provides a generic interface for an indexer that is managed by an
// index manager such as the Manager type provided by this package.
type Indexer interface {
	// Key returns the key of the index as a byte slice.
	Key() []byte

	// Name returns the human-readable name of the index.
	Name() string

	// Return the current version of the index.
	Version() uint32

	// Create is invoked when the indexer manager determines the index needs
	// to be created for the first time.
	Create(dbTx database.Tx) error

	// Init is invoked when the index manager is first initializing the
	// index.  This differs from the Create method in that it is called on
	// every load, including the case the index was just created.
	Init() error

	// ConnectBlock is invoked when the index manager is notified that a new
	// block has been connected to the main chain.
	ConnectBlock(dbTx database.Tx, block, parent *dcrutil.Block, prevScripts PrevScripter, isTreasuryEnabled bool) error

	// DisconnectBlock is invoked when the index manager is notified that a
	// block has been disconnected from the main chain.
	DisconnectBlock(dbTx database.Tx, block, parent *dcrutil.Block, prevScripts PrevScripter, isTreasuryEnabled bool) error
}

// ChainQueryer provides a generic interface that is used to provide access to
// the chain details required to by the index manager to initialize and sync
// the various indexes.
//
// All function MUST be safe for concurrent access.
type ChainQueryer interface {
	// MainChainHasBlock returns whether or not the block with the given hash is
	// in the main chain.
	MainChainHasBlock(*chainhash.Hash) bool

	// BestHeight returns the height of the current best block.
	BestHeight() int64

	// BlockHashByHeight returns the hash of the block at the given height in
	// the main chain.
	BlockHashByHeight(int64) (*chainhash.Hash, error)

	// PrevScripts returns a source of previous transaction scripts and their
	// associated versions spent by the given block.
	PrevScripts(database.Tx, *dcrutil.Block) (PrevScripter, error)

	// IsTreasuryEnabled returns true if the treasury agenda is active at
	// the provided block.
	IsTreasuryEnabled(*chainhash.Hash) (bool, error)
}

// IndexManager provides a generic interface that is called when blocks are
// connected and disconnected to and from the tip of the main chain for the
// purpose of supporting optional indexes.
type IndexManager interface {
	// Init is invoked during chain initialize in order to allow the index
	// manager to initialize itself and any indexes it is managing.  The channel
	// parameter specifies a channel the caller can close to signal that the
	// process should be interrupted.  It can be nil if that behavior is not
	// desired.
	Init(context.Context, ChainQueryer) error

	// ConnectBlock is invoked when a new block has been connected to the main
	// chain.
	ConnectBlock(database.Tx, *dcrutil.Block, *dcrutil.Block, PrevScripter, bool) error

	// DisconnectBlock is invoked when a block has been disconnected from the
	// main chain.
	DisconnectBlock(database.Tx, *dcrutil.Block, *dcrutil.Block, PrevScripter, bool) error
}

// IndexDropper provides a method to remove an index from the database. Indexers
// may implement this for a more efficient way of deleting themselves from the
// database rather than simply dropping a bucket.
type IndexDropper interface {
	DropIndex(context.Context, database.DB) error
}

// AssertError identifies an error that indicates an internal code consistency
// issue and should be treated as a critical and unrecoverable error.
type AssertError string

// Error returns the assertion error as a huma-readable string and satisfies
// the error interface.
func (e AssertError) Error() string {
	return "assertion failed: " + string(e)
}

// errDeserialize signifies that a problem was encountered when deserializing
// data.
type errDeserialize string

// Error implements the error interface.
func (e errDeserialize) Error() string {
	return string(e)
}

// isDeserializeErr returns whether or not the passed error is an errDeserialize
// error.
func isDeserializeErr(err error) bool {
	var derr errDeserialize
	return errors.As(err, &derr)
}

// internalBucket is an abstraction over a database bucket.  It is used to make
// the code easier to test since it allows mock objects in the tests to only
// implement these functions instead of everything a database.Bucket supports.
type internalBucket interface {
	Get(key []byte) []byte
	Put(key []byte, value []byte) error
	Delete(key []byte) error
}

// interruptRequested returns true when the provided channel has been closed.
// This simplifies early shutdown slightly since the caller can just use an if
// statement instead of a select.
func interruptRequested(ctx context.Context) bool {
	return ctx.Err() != nil
}

// makeDbErr creates a database.Error given a set of arguments.
func makeDbErr(kind database.ErrorKind, desc string) database.Error {
	return database.Error{Err: kind, Description: desc}
}


// dbPutIndexerTip uses an existing database transaction to update or add the
// current tip for the given index to the provided values.
func dbPutIndexerTip(dbTx database.Tx, idxKey []byte, hash *chainhash.Hash, height int32) error {
	serialized := make([]byte, chainhash.HashSize+4)
	copy(serialized, hash[:])
	byteOrder.PutUint32(serialized[chainhash.HashSize:], uint32(height))

	indexesBucket := dbTx.Metadata().Bucket(indexTipsBucketName)
	return indexesBucket.Put(idxKey, serialized)
}

// dbFetchIndexerTip uses an existing database transaction to retrieve the
// hash and height of the current tip for the provided index.
func dbFetchIndexerTip(dbTx database.Tx, idxKey []byte) (*chainhash.Hash, int32, error) {
	indexesBucket := dbTx.Metadata().Bucket(indexTipsBucketName)
	if indexesBucket == nil {
		str := fmt.Sprintf("%s bucket not found", string(indexTipsBucketName))
		return nil, 0, makeDbErr(database.ErrBucketNotFound, str)
	}
	serialized := indexesBucket.Get(idxKey)
	if len(serialized) == 0 {
		str := fmt.Sprintf("no index tip value found for %s ", string(idxKey))
		return nil, 0, makeDbErr(database.ErrValueNotFound, str)
	}
	if len(serialized) < chainhash.HashSize+4 {
		str := fmt.Sprintf("unexpected end of data for "+
			"index %q tip", string(idxKey))
		return nil, 0, makeDbErr(database.ErrCorruption, str)
	}

	var hash chainhash.Hash
	copy(hash[:], serialized[:chainhash.HashSize])
	height := int32(byteOrder.Uint32(serialized[chainhash.HashSize:]))
	return &hash, height, nil
}

// indexVersionKey returns the key for an index which houses the current version
// of the index.
func indexVersionKey(idxKey []byte) []byte {
	verKey := make([]byte, len(idxKey)+1)
	verKey[0] = 'v'
	copy(verKey[1:], idxKey)
	return verKey
}

// dbPutIndexerVersion uses an existing database transaction to update the
// version for the given index to the provided value.
func dbPutIndexerVersion(dbTx database.Tx, idxKey []byte, version uint32) error {
	serialized := make([]byte, 4)
	byteOrder.PutUint32(serialized[0:4], version)

	indexesBucket := dbTx.Metadata().Bucket(indexTipsBucketName)
	return indexesBucket.Put(indexVersionKey(idxKey), serialized)
}

// existsIndex returns whether the index keyed by idxKey exists in the database.
func existsIndex(db database.DB, idxKey []byte, idxName string) (bool, error) {
	var exists bool
	err := db.View(func(dbTx database.Tx) error {
		indexesBucket := dbTx.Metadata().Bucket(indexTipsBucketName)
		if indexesBucket != nil && indexesBucket.Get(idxKey) != nil {
			exists = true
		}
		return nil
	})
	return exists, err
}

// incrementalFlatDrop uses multiple database updates to remove key/value pairs
// saved to a flat index.
func incrementalFlatDrop(ctx context.Context, db database.DB, idxKey []byte, idxName string) error {
	const maxDeletions = 2000000
	var totalDeleted uint64
	for numDeleted := maxDeletions; numDeleted == maxDeletions; {
		numDeleted = 0
		err := db.Update(func(dbTx database.Tx) error {
			bucket := dbTx.Metadata().Bucket(idxKey)
			cursor := bucket.Cursor()
			for ok := cursor.First(); ok; ok = cursor.Next() &&
				numDeleted < maxDeletions {

				if err := cursor.Delete(); err != nil {
					return err
				}
				numDeleted++
			}
			return nil
		})
		if err != nil {
			return err
		}

		if numDeleted > 0 {
			totalDeleted += uint64(numDeleted)
			log.Infof("Deleted %d keys (%d total) from %s",
				numDeleted, totalDeleted, idxName)
		}

		if interruptRequested(ctx) {
			return errInterruptRequested
		}
	}
	return nil
}

// indexDropKey returns the key for an index which indicates it is in the
// process of being dropped.
func indexDropKey(idxKey []byte) []byte {
	dropKey := make([]byte, len(idxKey)+1)
	dropKey[0] = 'd'
	copy(dropKey[1:], idxKey)
	return dropKey
}

// dropIndexMetadata drops the passed index from the database by removing the
// top level bucket for the index, the index tip, and any in-progress drop flag.
func dropIndexMetadata(db database.DB, idxKey []byte, idxName string) error {
	return db.Update(func(dbTx database.Tx) error {
		meta := dbTx.Metadata()
		indexesBucket := meta.Bucket(indexTipsBucketName)
		err := indexesBucket.Delete(idxKey)
		if err != nil {
			return err
		}

		err = meta.DeleteBucket(idxKey)
		if err != nil && !errors.Is(err, database.ErrBucketNotFound) {
			return err
		}

		err = indexesBucket.Delete(indexVersionKey(idxKey))
		if err != nil {
			return err
		}

		return indexesBucket.Delete(indexDropKey(idxKey))
	})
}

// dropFlatIndex incrementally drops the passed index from the database.  Since
// indexes can be massive, it deletes the index in multiple database
// transactions in order to keep memory usage to reasonable levels.  For this
// algorithm to work, the index must be "flat" (have no nested buckets).  It
// also marks the drop in progress so the drop can be resumed if it is stopped
// before it is done before the index can be used again.
func dropFlatIndex(ctx context.Context, db database.DB, idxKey []byte, idxName string) error {
	// Nothing to do if the index doesn't already exist.
	exists, err := existsIndex(db, idxKey, idxName)
	if err != nil {
		return err
	}
	if !exists {
		log.Infof("Not dropping %s because it does not exist", idxName)
		return nil
	}

	log.Infof("Dropping all %s entries.  This might take a while...",
		idxName)

	// Mark that the index is in the process of being dropped so that it
	// can be resumed on the next start if interrupted before the process is
	// complete.
	err = markIndexDeletion(db, idxKey)
	if err != nil {
		return err
	}

	// Since the indexes can be so large, attempting to simply delete
	// the bucket in a single database transaction would result in massive
	// memory usage and likely crash many systems due to ulimits.  In order
	// to avoid this, use a cursor to delete a maximum number of entries out
	// of the bucket at a time.
	err = incrementalFlatDrop(ctx, db, idxKey, idxName)
	if err != nil {
		return err
	}

	// Remove the index tip, version, bucket, and in-progress drop flag now that
	// all index entries have been removed.
	err = dropIndexMetadata(db, idxKey, idxName)
	if err != nil {
		return err
	}

	log.Infof("Dropped %s", idxName)
	return nil
}

// dropIndex drops the passed index from the database without using incremental
// deletion.  This should be used to drop indexes containing nested buckets,
// which can not be deleted with dropFlatIndex.
func dropIndex(db database.DB, idxKey []byte, idxName string) error {
	// Nothing to do if the index doesn't already exist.
	exists, err := existsIndex(db, idxKey, idxName)
	if err != nil {
		return err
	}
	if !exists {
		log.Infof("Not dropping %s because it does not exist", idxName)
		return nil
	}

	log.Infof("Dropping all %s entries.  This might take a while...",
		idxName)

	// Mark that the index is in the process of being dropped so that it
	// can be resumed on the next start if interrupted before the process is
	// complete.
	err = markIndexDeletion(db, idxKey)
	if err != nil {
		return err
	}

	// Remove the index tip, version, bucket, and in-progress drop flag.
	// Removing the index bucket also recursively removes all values saved to
	// the index.
	err = dropIndexMetadata(db, idxKey, idxName)
	if err != nil {
		return err
	}

	log.Infof("Dropped %s", idxName)
	return nil
}

// markIndexDeletion marks the index identified by idxKey for deletion.  Marking
// an index for deletion allows deletion to resume next startup if an
// incremental deletion was interrupted.
func markIndexDeletion(db database.DB, idxKey []byte) error {
	return db.Update(func(dbTx database.Tx) error {
		indexesBucket := dbTx.Metadata().Bucket(indexTipsBucketName)
		return indexesBucket.Put(indexDropKey(idxKey), idxKey)
	})
}
