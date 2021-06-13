// Copyright (c) 2016 The btcsuite developers
// Copyright (c) 2016-2021 The Decred developers
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
	"fmt"

	"github.com/decred/dcrd/blockchain/v4/internal/progresslog"
	"github.com/decred/dcrd/blockchain/v4/internal/spendpruner"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
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

	// indexTipsBucketName is the name of the db bucket used to house the
	// current tip of each index.
	indexTipsBucketName = []byte("idxtips")
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

// ChainQueryer provides a generic interface that is used to provide access to
// the chain details required by indexes.
//
// All functions MUST be safe for concurrent access.
type ChainQueryer interface {
	// MainChainHasBlock returns whether or not the block with the given hash is
	// in the main chain.
	MainChainHasBlock(*chainhash.Hash) bool

	// ChainParams returns the network parameters of the chain.
	ChainParams() *chaincfg.Params

	// Best returns the height and hash of the current best block.
	Best() (int64, *chainhash.Hash)

	// BlockHashByHeight returns the hash of the block at the given height in
	// the main chain.
	BlockHashByHeight(int64) (*chainhash.Hash, error)

	// BlockHeightByHash returns the height of the block with the given hash
	// in the main chain.
	BlockHeightByHash(hash *chainhash.Hash) (int64, error)

	// BlockByHash returns the block of the provided hash.
	BlockByHash(*chainhash.Hash) (*dcrutil.Block, error)

	// Ancestor returns the ancestor of the provided block at the
	// provided height.
	Ancestor(block *chainhash.Hash, height int64) *chainhash.Hash

	// AddSpendConsumer adds the provided spend consumer.
	AddSpendConsumer(consumer spendpruner.SpendConsumer)
	// PrevScripts returns a source of previous transaction scripts and their
	// associated versions spent by the given block.
	PrevScripts(database.Tx, *dcrutil.Block) (PrevScripter, error)

	// IsTreasuryAgendaActive returns true if the treasury agenda is active at
	// the provided block.
	IsTreasuryAgendaActive(*chainhash.Hash) (bool, error)
}

// Indexer defines a generic interface for an indexer.
type Indexer interface {
	// Key returns the key of the index as a byte slice.
	Key() []byte

	// Name returns the human-readable name of the index.
	Name() string

	// Version returns the current version of the index.
	Version() uint32

	// DB returns the database of the index.
	DB() database.DB

	// Queryer returns the chain queryer.
	Queryer() ChainQueryer

	// Tip returns the current index tip.
	Tip() (int64, *chainhash.Hash, error)

	// Create is invoked when the indexer is being created.
	Create(dbTx database.Tx) error

	// Init is invoked when the index is being initialized.
	// This differs from the Create method in that it is called on
	// every load, including the case the index was just created.
	Init(ctx context.Context, chainParams *chaincfg.Params) error

	// ProcessNotification indexes the provided notification based on its
	// notification type.
	ProcessNotification(dbTx database.Tx, ntfn *IndexNtfn) error

	// IndexSubsciption returns the subscription for index updates.
	IndexSubscription() *IndexSubscription

	// WaitForSync subscribes clients for the next index sync update.
	WaitForSync() chan bool

	// Subscribers returns all client channels waiting for the next index update.
	Subscribers() map[chan bool]struct{}
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

// indexNeedsInputs returns whether or not the index needs access to
// the txouts referenced by the transaction inputs being indexed.
func indexNeedsInputs(index Indexer) bool {
	if idx, ok := index.(NeedsInputser); ok {
		return idx.NeedsInputs()
	}

	return false
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

// tip returns the current tip hash and height of the provided index.
func tip(db database.DB, key []byte) (int64, *chainhash.Hash, error) {
	var hash *chainhash.Hash
	var height int32
	err := db.View(func(dbTx database.Tx) error {
		var err error
		hash, height, err = dbFetchIndexerTip(dbTx, key)
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	return int64(height), hash, err
}

// recover reverts the index to a block on the main chain by repeatedly
// disconnecting the index tip if it is not on the main chain.
func recover(ctx context.Context, idx Indexer) error {
	// Fetch the current tip for the index.
	height, hash, err := idx.Tip()
	if err != nil {
		return err
	}

	// Nothing to do if the index does not have any entries yet.
	if height == 0 {
		return nil
	}

	// Nothing to do if the index tip is on the main chain.
	if idx.Queryer().MainChainHasBlock(hash) {
		return nil
	}

	log.Infof("%s: recovering from tip %d (%s)", idx.Name(), height, hash)

	// Create a progress logger for the recovery process below.
	progressLogger := progresslog.NewBlockProgressLogger("Recovered", log)

	queryer := idx.Queryer()
	var cachedBlock *dcrutil.Block
	for !queryer.MainChainHasBlock(hash) {
		if interruptRequested(ctx) {
			return errInterruptRequested
		}

		// Get the block, unless it's already cached.
		var block *dcrutil.Block
		if cachedBlock == nil && height > 0 {
			block, err = queryer.BlockByHash(hash)
			if err != nil {
				return err
			}
		} else {
			block = cachedBlock
		}

		parentHash := &block.MsgBlock().Header.PrevBlock
		parent, err := queryer.BlockByHash(parentHash)
		if err != nil {
			return err
		}
		cachedBlock = parent

		var prevScripts PrevScripter
		err = idx.DB().Update(func(dbTx database.Tx) error {
			if interruptRequested(ctx) {
				return errInterruptRequested
			}

			// Fetch the associated script information for previous outputs
			// of the block if the index requires them.
			if indexNeedsInputs(idx) {
				var err error
				prevScripts, err = queryer.PrevScripts(dbTx, block)
				if err != nil {
					return err
				}
			}

			return nil
		})
		if err != nil {
			return err
		}

		ntfn := &IndexNtfn{
			NtfnType:    DisconnectNtfn,
			Block:       block,
			Parent:      parent,
			PrevScripts: prevScripts,
			Done:        make(chan bool),
		}

		err = updateIndex(ctx, idx, ntfn)
		if err != nil {
			return err
		}

		// Update the tip to the previous block.
		hash = &block.MsgBlock().Header.PrevBlock
		height--

		progressLogger.LogBlockHeight(block.MsgBlock(), parent.MsgBlock())
	}

	log.Infof("%s: index recovered to tip %d (%s)", idx.Name(),
		height, hash)

	return nil
}

// finishDrop determines if the provided index is in the middle
// of being dropped and finishes dropping it when it is.  This is necessary
// because dropping an index has to be done in several atomic steps rather
// than one big atomic step due to the massive number of entries.
func finishDrop(ctx context.Context, indexer Indexer) error {
	var drop bool
	err := indexer.DB().View(func(dbTx database.Tx) error {
		// The index does not need to be dropped if the index tips
		// bucket hasn't been created yet.
		indexesBucket := dbTx.Metadata().Bucket(indexTipsBucketName)
		if indexesBucket == nil {
			return nil
		}

		// Mark the indexer as requiring a drop if one is already in
		// progress.
		dropKey := indexDropKey(indexer.Key())
		if indexesBucket.Get(dropKey) != nil {
			drop = true
		}

		return nil
	})
	if err != nil {
		return err
	}

	// Nothing to do if the index does not need dropping.
	if !drop {
		return nil
	}

	if interruptRequested(ctx) {
		return errInterruptRequested
	}

	log.Infof("Resuming %s drop", indexer.Name())

	switch d := indexer.(type) {
	case IndexDropper:
		err := d.DropIndex(ctx, indexer.DB())
		if err != nil {
			return err
		}
	default:
		err := dropIndex(indexer.DB(), indexer.Key(), indexer.Name())
		if err != nil {
			return err
		}
	}

	return nil
}

// createIndex determines if each of the provided index has already
// been created and creates it if not.
func createIndex(indexer Indexer, genesisHash *chainhash.Hash) error {
	return indexer.DB().Update(func(dbTx database.Tx) error {
		// Create the bucket for the current tips as needed.
		meta := dbTx.Metadata()
		indexesBucket, err := meta.CreateBucketIfNotExists(indexTipsBucketName)
		if err != nil {
			return err
		}

		// Nothing to do if the index tip already exists.
		idxKey := indexer.Key()
		if indexesBucket.Get(idxKey) != nil {
			return nil
		}

		// Store the index version.
		err = dbPutIndexerVersion(dbTx, idxKey, indexer.Version())
		if err != nil {
			return err
		}

		// The tip for the index does not exist, so create it and
		// invoke the create callback for the index so it can perform
		// any one-time initialization it requires.
		if err := indexer.Create(dbTx); err != nil {
			return err
		}

		// Set the tip for the index to values which represent an
		// uninitialized index (the genesis block hash and height).
		err = dbPutIndexerTip(dbTx, idxKey, genesisHash, 0)
		if err != nil {
			return err
		}

		return nil
	})
}

// upgradeIndex determines if the provided index needs to be upgraded.
// If it does it is dropped and recreeated.
func upgradeIndex(ctx context.Context, indexer Indexer, genesisHash *chainhash.Hash) error {
	if err := finishDrop(ctx, indexer); err != nil {
		return err
	}
	return createIndex(indexer, genesisHash)
}

// maybeNotifySubscribers updates subscribers the index is synced when
// the tip is identical to the chain tip.
func maybeNotifySubscribers(ctx context.Context, indexer Indexer) error {
	if interruptRequested(ctx) {
		return errInterruptRequested
	}

	bestHeight, bestHash := indexer.Queryer().Best()
	tipHeight, tipHash, err := indexer.Tip()
	if err != nil {
		return fmt.Errorf("%s: unable to fetch index tip: %v",
			indexer.Name(), err)
	}

	if tipHeight == bestHeight && *bestHash == *tipHash {
		subs := indexer.Subscribers()
		for sub := range subs {
			close(sub)
			delete(subs, sub)
		}
	}

	return nil
}

// notifyDependent relays the provided index notification to the dependent of
// the provided index if there is one set.
func notifyDependent(ctx context.Context, indexer Indexer, ntfn *IndexNtfn) error {
	if interruptRequested(ctx) {
		return errInterruptRequested
	}

	sub := indexer.IndexSubscription()
	if sub == nil {
		return fmt.Errorf("%s: no index update subscription found",
			indexer.Name())
	}

	// Notify the dependent subscription if set.
	sub.mtx.Lock()
	defer sub.mtx.Unlock()
	if sub.dependent != nil {
		err := updateIndex(ctx, sub.dependent.idx, ntfn)
		if err != nil {
			return err
		}
	}

	return nil
}

// updateIndex processes the notification for the provided index.
func updateIndex(ctx context.Context, indexer Indexer, ntfn *IndexNtfn) error {
	// Ensure the incoming index notification is of the next block
	// extending the chain.
	tip, _, err := indexer.Tip()
	if err != nil {
		return fmt.Errorf("%s: unable to fetch index tip: %v",
			indexer.Name(), err)
	}

	var expectedHeight int64
	switch ntfn.NtfnType {
	case ConnectNtfn:
		expectedHeight = tip + 1
	case DisconnectNtfn:
		expectedHeight = tip
	default:
		return fmt.Errorf("%s: unknown notification type received: %v",
			indexer.Name(), ntfn.NtfnType)
	}

	// Relay the notification to the dependent if its height is less than that
	// of the expected notification since its possible for a dependent to have
	// a lower tip height than its prerequisite.
	if ntfn.Block.Height() < expectedHeight {
		log.Tracef("%s: relaying notification for height %d to dependent",
			indexer.Name(), ntfn.Block.Height())
		return notifyDependent(ctx, indexer, ntfn)
	}

	// Receiving a notification with a height higher than the expected implies
	// a missed index update.
	if ntfn.Block.Height() > expectedHeight {
		return fmt.Errorf("%s: missing index notification, expected "+
			"notification for height %d, got %d", indexer.Name(),
			expectedHeight, ntfn.Block.Height())
	}

	err = indexer.DB().Update(func(dbTx database.Tx) error {
		return indexer.ProcessNotification(dbTx, ntfn)
	})
	if err != nil {
		return err
	}

	err = notifyDependent(ctx, indexer, ntfn)
	if err != nil {
		return err
	}

	err = maybeNotifySubscribers(ctx, indexer)
	if err != nil {
		return err
	}

	return nil
}
