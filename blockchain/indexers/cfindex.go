// Copyright (c) 2017 The btcsuite developers
// Copyright (c) 2018-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/database/v2"
	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/dcrd/gcs/v2"
	"github.com/decred/dcrd/gcs/v2/blockcf"
	"github.com/decred/dcrd/wire"
)

const (
	// cfIndexName is the human-readable name for the index.
	cfIndexName = "committed filter index"

	// cfIndexVersion is the current version of the committed filter index.
	cfIndexVersion = 2
)

// Committed filters come in two flavors: basic and extended. They are
// generated and dropped in pairs, and both are indexed by a block's hash.
// Besides holding different content, they also live in different buckets.
var (
	// cfIndexParentBucketKey is the name of the parent bucket used to house
	// the index. The rest of the buckets live below this bucket.
	cfIndexParentBucketKey = []byte("cfindexparentbucket")

	// cfIndexKeys is an array of db bucket names used to house indexes of
	// block hashes to cfilters.
	cfIndexKeys = [][]byte{
		[]byte("cf0byhashidx"),
		[]byte("cf1byhashidx"),
	}

	// cfHeaderKeys is an array of db bucket names used to house indexes of
	// block hashes to cf headers.
	cfHeaderKeys = [][]byte{
		[]byte("cf0headerbyhashidx"),
		[]byte("cf1headerbyhashidx"),
	}

	maxFilterType = uint8(len(cfHeaderKeys) - 1)
)

// dbFetchFilter retrieves a block's basic or extended filter. A filter's
// absence is not considered an error.
func dbFetchFilter(dbTx database.Tx, key []byte, h *chainhash.Hash) []byte {
	idx := dbTx.Metadata().Bucket(cfIndexParentBucketKey).Bucket(key)
	return idx.Get(h[:])
}

// dbFetchFilterHeader retrieves a block's basic or extended filter header.
// A filter's absence is not considered an error.
func dbFetchFilterHeader(dbTx database.Tx, key []byte, h *chainhash.Hash) ([]byte, error) {
	idx := dbTx.Metadata().Bucket(cfIndexParentBucketKey).Bucket(key)

	fh := idx.Get(h[:])
	if fh == nil {
		return make([]byte, chainhash.HashSize), nil
	}
	if len(fh) != chainhash.HashSize {
		return nil, fmt.Errorf("invalid filter header length %v", len(fh))
	}

	return fh, nil
}

// dbStoreFilter stores a block's basic or extended filter.
func dbStoreFilter(dbTx database.Tx, key []byte, h *chainhash.Hash, f []byte) error {
	idx := dbTx.Metadata().Bucket(cfIndexParentBucketKey).Bucket(key)
	return idx.Put(h[:], f)
}

// dbStoreFilterHeader stores a block's basic or extended filter header.
func dbStoreFilterHeader(dbTx database.Tx, key []byte, h *chainhash.Hash, fh []byte) error {
	if len(fh) != chainhash.HashSize {
		return fmt.Errorf("invalid filter header length %v", len(fh))
	}
	idx := dbTx.Metadata().Bucket(cfIndexParentBucketKey).Bucket(key)
	return idx.Put(h[:], fh)
}

// dbDeleteFilter deletes a filter's basic or extended filter.
func dbDeleteFilter(dbTx database.Tx, key []byte, h *chainhash.Hash) error {
	idx := dbTx.Metadata().Bucket(cfIndexParentBucketKey).Bucket(key)
	return idx.Delete(h[:])
}

// dbDeleteFilterHeader deletes a filter's basic or extended filter header.
func dbDeleteFilterHeader(dbTx database.Tx, key []byte, h *chainhash.Hash) error {
	idx := dbTx.Metadata().Bucket(cfIndexParentBucketKey).Bucket(key)
	return idx.Delete(h[:])
}

// CFIndex implements a committed filter (cf) by hash index.
type CFIndex struct {
	db          database.DB
	chain       ChainQueryer
	chainParams *chaincfg.Params
	sub         *IndexSubscription
	subscribers map[chan bool]struct{}
	mtx         sync.Mutex
}

// Ensure the CFIndex type implements the Indexer interface.
var _ Indexer = (*CFIndex)(nil)

// Init initializes the hash-based cf index.
//
// This is part of the Indexer interface.
func (idx *CFIndex) Init(ctx context.Context, chainParams *chaincfg.Params) error {
	if interruptRequested(ctx) {
		return errInterruptRequested
	}

	// Finish any drops that were previously interrupted.
	if err := finishDrop(ctx, idx.db, idx); err != nil {
		return err
	}

	// Create the initial state for the index as needed.
	if err := createIndex(idx.db, &chainParams.GenesisHash, idx); err != nil {
		return err
	}

	// Upgrade the index as needed.
	if err := upgradeIndex(ctx, idx.db, &chainParams.GenesisHash, idx); err != nil {
		return err
	}

	// Recover the index to the main chain if needed.
	if err := recover(ctx, idx.db, idx, idx.chain); err != nil {
		return err
	}

	// Sync the index to the main chain tip.
	if err := catchUp(ctx, idx.db, idx, idx.chain); err != nil {
		return err
	}

	return nil
}

// Key returns the database key to use for the index as a byte slice. This is
// part of the Indexer interface.
func (idx *CFIndex) Key() []byte {
	return cfIndexParentBucketKey
}

// Name returns the human-readable name of the index. This is part of the
// Indexer interface.
func (idx *CFIndex) Name() string {
	return cfIndexName
}

// Version returns the current version of the index.
//
// This is part of the Indexer interface.
func (idx *CFIndex) Version() uint32 {
	return cfIndexVersion
}

// DB returns the database of the index.
//
// This is part of the Indexer interface.
func (idx *CFIndex) DB() database.DB {
	return idx.db
}

// Tip returns the current tip of the index.
//
// This is part of the Indexer interface.
func (idx *CFIndex) Tip() (int64, *chainhash.Hash, error) {
	return tip(idx.db, idx.Key())
}

// Create is invoked when the indexer manager determines the index needs to
// be created for the first time. It creates buckets for the two hash-based cf
// indexes (simple, extended).
func (idx *CFIndex) Create(dbTx database.Tx) error {
	meta := dbTx.Metadata()

	cfIndexParentBucket, err := meta.CreateBucket(cfIndexParentBucketKey)
	if err != nil {
		return err
	}

	for _, bucketName := range cfIndexKeys {
		_, err = cfIndexParentBucket.CreateBucket(bucketName)
		if err != nil {
			return err
		}
	}

	for _, bucketName := range cfHeaderKeys {
		_, err = cfIndexParentBucket.CreateBucket(bucketName)
		if err != nil {
			return err
		}
	}

	firstHeader := make([]byte, chainhash.HashSize)
	err = dbStoreFilterHeader(dbTx, cfHeaderKeys[wire.GCSFilterRegular],
		&idx.chainParams.GenesisBlock.Header.PrevBlock, firstHeader)
	if err != nil {
		return err
	}

	return dbStoreFilterHeader(dbTx, cfHeaderKeys[wire.GCSFilterExtended],
		&idx.chainParams.GenesisBlock.Header.PrevBlock, firstHeader)
}

// storeFilter stores a given filter, and performs the steps needed to
// generate the filter's header.
func storeFilter(dbTx database.Tx, block *dcrutil.Block, f *gcs.FilterV1, filterType wire.FilterType) error {
	if uint8(filterType) > maxFilterType {
		return errors.New("unsupported filter type")
	}

	// Figure out which buckets to use.
	fkey := cfIndexKeys[filterType]
	hkey := cfHeaderKeys[filterType]

	// Start by storing the filter.
	h := block.Hash()
	var basicFilterBytes []byte
	if f != nil {
		basicFilterBytes = f.Bytes()
	}
	err := dbStoreFilter(dbTx, fkey, h, basicFilterBytes)
	if err != nil {
		return err
	}

	// Then fetch the previous block's filter header.
	ph := &block.MsgBlock().Header.PrevBlock
	pfh, err := dbFetchFilterHeader(dbTx, hkey, ph)
	if err != nil {
		return err
	}

	// Construct the new block's filter header, and store it.
	prevHeader, err := chainhash.NewHash(pfh)
	if err != nil {
		return err
	}
	fh := gcs.MakeHeaderForFilter(f, prevHeader)
	return dbStoreFilterHeader(dbTx, hkey, h, fh[:])
}

// connectBlock adds a hash-to-cf mapping for the passed block.
func (idx *CFIndex) connectBlock(dbTx database.Tx, block, parent *dcrutil.Block, _ PrevScripter) error {
	f, err := blockcf.Regular(block.MsgBlock())
	if err != nil {
		return err
	}

	err = storeFilter(dbTx, block, f, wire.GCSFilterRegular)
	if err != nil {
		return err
	}

	f, err = blockcf.Extended(block.MsgBlock())
	if err != nil {
		return err
	}

	err = storeFilter(dbTx, block, f, wire.GCSFilterExtended)
	if err != nil {
		return err
	}

	// Update the current index tip.
	return dbPutIndexerTip(dbTx, idx.Key(), block.Hash(), int32(block.Height()))
}

// disconnectBlock removes the hash-to-cf mapping for the passed block.
func (idx *CFIndex) disconnectBlock(dbTx database.Tx, block, parent *dcrutil.Block, _ PrevScripter) error {
	for _, key := range cfIndexKeys {
		err := dbDeleteFilter(dbTx, key, block.Hash())
		if err != nil {
			return err
		}
	}

	for _, key := range cfHeaderKeys {
		err := dbDeleteFilterHeader(dbTx, key, block.Hash())
		if err != nil {
			return err
		}
	}

	// Update the current index tip.
	return dbPutIndexerTip(dbTx, idx.Key(), &block.MsgBlock().Header.PrevBlock,
		int32(block.Height()-1))
}

// FilterByBlockHash returns the serialized contents of a block's basic or
// extended committed filter.
func (idx *CFIndex) FilterByBlockHash(h *chainhash.Hash, filterType wire.FilterType) ([]byte, error) {
	if uint8(filterType) > maxFilterType {
		return nil, errors.New("unsupported filter type")
	}

	var f []byte
	err := idx.db.View(func(dbTx database.Tx) error {
		f = dbFetchFilter(dbTx, cfIndexKeys[filterType], h)
		return nil
	})
	return f, err
}

// FilterHeaderByBlockHash returns the serialized contents of a block's basic
// or extended committed filter header.
func (idx *CFIndex) FilterHeaderByBlockHash(h *chainhash.Hash, filterType wire.FilterType) ([]byte, error) {
	if uint8(filterType) > maxFilterType {
		return nil, errors.New("unsupported filter type")
	}

	var fh []byte
	err := idx.db.View(func(dbTx database.Tx) error {
		var err error
		fh, err = dbFetchFilterHeader(dbTx,
			cfHeaderKeys[filterType], h)
		return err
	})
	return fh, err
}

// NewCfIndex returns a new instance of an indexer that is used to create a
// mapping of the hashes of all blocks in the blockchain to their respective
// committed filters.
//
// It implements the Indexer interface which plugs into the IndexManager that
// in turn is used by the blockchain package. This allows the index to be
// seamlessly maintained along with the chain.
func NewCfIndex(ctx context.Context, db database.DB, chain ChainQueryer, chainParams *chaincfg.Params, subscriber *IndexSubscriber) (*CFIndex, error) {
	idx := &CFIndex{
		db:          db,
		chain:       chain,
		chainParams: chainParams,
		subscribers: make(map[chan bool]struct{}),
	}
	err := idx.Init(ctx, chainParams)
	if err != nil {
		return nil, err
	}

	// The committed filter index is an optional index. It has no dependencies and
	// is updated asynchronously.
	idx.sub, err = subscriber.Subscribe(idx, "")
	if err != nil {
		return nil, err
	}

	go idx.run(ctx)

	return idx, nil
}

// DropCfIndex drops the CF index from the provided database if exists.
func DropCfIndex(ctx context.Context, db database.DB) error {
	return dropIndexMetadata(db, cfIndexParentBucketKey, cfIndexName)
}

// DropIndex drops the cf index from the provided database if it
// exists.
func (*CFIndex) DropIndex(ctx context.Context, db database.DB) error {
	return DropTxIndex(ctx, db)
}

// ProcessNotification indexes the provided notification based on its
// notification type.
//
// This is part of the Indexer interface.
func (idx *CFIndex) ProcessNotification(dbTx database.Tx, ntfn *IndexNtfn) error {
	switch ntfn.NtfnType {
	case ConnectNtfn:
		err := idx.connectBlock(dbTx, ntfn.Block, ntfn.Parent, ntfn.PrevScripts)
		if err != nil {
			return fmt.Errorf("%s: unable to connect block: %v", idx.Name(), err)
		}

	case DisconnectNtfn:
		err := idx.disconnectBlock(dbTx, ntfn.Block, ntfn.Parent, ntfn.PrevScripts)
		if err != nil {
			log.Errorf("%s: unable to disconnect block: %v", idx.Name(), err)
		}

	default:
		return fmt.Errorf("unknown notification type provided: %d", ntfn.NtfnType)
	}

	return nil
}

// run processes incoming notifications from the index subscriber.
//
// This should be run as a goroutine.
func (idx *CFIndex) run(ctx context.Context) {
	c := idx.sub.C()

	for {
		select {
		case ntfn := <-c:
			err := idx.db.Update(func(dbTx database.Tx) error {
				return idx.ProcessNotification(dbTx, ntfn)
			})
			if err != nil {
				log.Error(err)
			}

			// Notify the dependent subscription if set.
			idx.sub.mtx.Lock()
			if idx.sub.dependency != nil {
				idx.sub.dependency.publishIndexNtfn(ntfn)
			}
			idx.sub.mtx.Unlock()

			bestHeight, bestHash := idx.chain.Best()
			tipHeight, tipHash, err := idx.Tip()
			if err != nil {
				log.Error(err)
				continue
			}

			if tipHeight == bestHeight && bestHash.IsEqual(tipHash) {
				// Notify subscribers the index is synced by
				// closing the channel.
				idx.mtx.Lock()
				for c := range idx.subscribers {
					close(c)
					delete(idx.subscribers, c)
				}
				idx.mtx.Unlock()
			}

		case <-ctx.Done():
			return
		}
	}
}

// WaitForSync subscribes clients for the next index sync update.
func (idx *CFIndex) WaitForSync() chan bool {
	c := make(chan bool)

	idx.mtx.Lock()
	idx.subscribers[c] = struct{}{}
	idx.mtx.Unlock()

	return c
}
