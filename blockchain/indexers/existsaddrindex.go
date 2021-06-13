// Copyright (c) 2016-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"context"
	"fmt"
	"sync"

	"github.com/decred/dcrd/blockchain/stake/v4"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/database/v2"
	"github.com/decred/dcrd/dcrutil/v4"
	"github.com/decred/dcrd/txscript/v4"
	"github.com/decred/dcrd/txscript/v4/stdaddr"
	"github.com/decred/dcrd/wire"
)

const (
	// existsAddressIndexName is the human-readable name for the index.
	existsAddressIndexName = "exists address index"

	// existsAddrIndexVersion is the current version of the exists address
	// index.
	existsAddrIndexVersion = 2
)

var (
	// existsAddrIndexKey is the key of the ever seen address index and
	// the db bucket used to house it.
	existsAddrIndexKey = []byte("existsaddridx")
)

// ExistsAddrIndex implements an "ever seen" address index.  Any address that
// is ever seen in a block or in the mempool is stored here as a key. Values
// are empty.  Once an address is seen, it is never removed from this store.
// This results in a local version of this database that is consistent only
// for this peer, but at minimum contains all the addresses seen on the
// blockchain itself.
//
// In addition, support is provided for a memory-only index of unconfirmed
// transactions such as those which are kept in the memory pool before inclusion
// in a block.
type ExistsAddrIndex struct {
	// The following fields are set when the instance is created and can't
	// be changed afterwards, so there is no need to protect them with a
	// separate mutex.
	db    database.DB
	chain ChainQueryer
	sub   *IndexSubscription

	// The following fields are used to quickly link transactions and
	// addresses that have not been included into a block yet when an
	// address index is being maintained.  The are protected by the
	// unconfirmedLock field.
	//
	// The txnsByAddr field is used to keep an index of all transactions
	// which either create an output to a given address or spend from a
	// previous output to it keyed by the address.
	//
	// The addrsByTx field is essentially the reverse and is used to
	// keep an index of all addresses which a given transaction involves.
	// This allows fairly efficient updates when transactions are removed
	// once they are included into a block.
	unconfirmedLock sync.RWMutex
	mpExistsAddr    map[[addrKeySize]byte]struct{}

	subscribers map[chan bool]struct{}
	mtx         sync.Mutex
	cancel      context.CancelFunc
}

// NewExistsAddrIndex returns a new instance of an indexer that is used to
// create a mapping of all addresses ever seen.
func NewExistsAddrIndex(subscriber *IndexSubscriber, db database.DB, chain ChainQueryer) (*ExistsAddrIndex, error) {
	idx := &ExistsAddrIndex{
		db:           db,
		chain:        chain,
		mpExistsAddr: make(map[[addrKeySize]byte]struct{}),
		subscribers:  make(map[chan bool]struct{}),
		cancel:       subscriber.cancel,
	}

	// The exists address index is an optional index. It has no
	// prerequisite and is updated asynchronously.
	sub, err := subscriber.Subscribe(idx, noPrereqs)
	if err != nil {
		return nil, err
	}

	idx.sub = sub

	err = idx.Init(subscriber.ctx, chain.ChainParams())
	if err != nil {
		return nil, err
	}

	return idx, nil
}

// Ensure the ExistsAddrIndex type implements the Indexer interface.
var _ Indexer = (*ExistsAddrIndex)(nil)

// Init initializes the exists address transaction index.
//
// This is part of the Indexer interface.
func (idx *ExistsAddrIndex) Init(ctx context.Context, chainParams *chaincfg.Params) error {
	if interruptRequested(ctx) {
		return errInterruptRequested
	}

	// Finish any drops that were previously interrupted.
	if err := finishDrop(ctx, idx); err != nil {
		return err
	}

	// Create the initial state for the index as needed.
	if err := createIndex(idx, &chainParams.GenesisHash); err != nil {
		return err
	}

	// Upgrade the index as needed.
	if err := upgradeIndex(ctx, idx, &chainParams.GenesisHash); err != nil {
		return err
	}

	// Recover the exists address index and its dependents to the main
	// chain if needed.
	if err := recover(ctx, idx); err != nil {
		return err
	}

	return nil
}

// Key returns the database key to use for the index as a byte slice.
//
// This is part of the Indexer interface.
func (idx *ExistsAddrIndex) Key() []byte {
	return existsAddrIndexKey
}

// Name returns the human-readable name of the index.
//
// This is part of the Indexer interface.
func (idx *ExistsAddrIndex) Name() string {
	return existsAddressIndexName
}

// Version returns the current version of the index.
//
// This is part of the Indexer interface.
func (idx *ExistsAddrIndex) Version() uint32 {
	return existsAddrIndexVersion
}

// DB returns the database of the index.
//
// This is part of the Indexer interface.
func (idx *ExistsAddrIndex) DB() database.DB {
	return idx.db
}

// Queryer returns the chain queryer.
//
// This is part of the Indexer interface.
func (idx *ExistsAddrIndex) Queryer() ChainQueryer {
	return idx.chain
}

// Tip returns the current tip of the index.
//
// This is part of the Indexer interface.
func (idx *ExistsAddrIndex) Tip() (int64, *chainhash.Hash, error) {
	return tip(idx.db, idx.Key())
}

// Create is invoked when the index is created for the first time.
// It creates the bucket for the address index.
//
// This is part of the Indexer interface.
func (idx *ExistsAddrIndex) Create(dbTx database.Tx) error {
	_, err := dbTx.Metadata().CreateBucket(existsAddrIndexKey)
	return err
}

// IndexSubscription returns the subscription for index updates.
//
// This is part of the Indexer interface.
func (idx *ExistsAddrIndex) IndexSubscription() *IndexSubscription {
	return idx.sub
}

// Subscribers returns all client channels waiting for the next index update.
//
// This is part of the Indexer interface.
func (idx *ExistsAddrIndex) Subscribers() map[chan bool]struct{} {
	idx.mtx.Lock()
	defer idx.mtx.Unlock()
	return idx.subscribers
}

// WaitForSync subscribes clients for the next index sync update.
//
// This is part of the Indexer interface.
func (idx *ExistsAddrIndex) WaitForSync() chan bool {
	c := make(chan bool)

	idx.mtx.Lock()
	idx.subscribers[c] = struct{}{}
	idx.mtx.Unlock()

	return c
}

// dbPutExistsAddr uses an existing database transaction to update or add a
// used address index to the database.
func dbPutExistsAddr(bucket internalBucket, addrKey [addrKeySize]byte) error {
	return bucket.Put(addrKey[:], nil)
}

// existsAddress takes a bucket and key for an address and responds with
// whether or not the key exists in the database.
func (idx *ExistsAddrIndex) existsAddress(bucket internalBucket, k [addrKeySize]byte) bool {
	if bucket.Get(k[:]) != nil {
		return true
	}

	idx.unconfirmedLock.RLock()
	_, exists := idx.mpExistsAddr[k]
	idx.unconfirmedLock.RUnlock()

	return exists
}

// ExistsAddress is the concurrency safe, exported function that returns
// whether or not an address has been seen before.
func (idx *ExistsAddrIndex) ExistsAddress(addr stdaddr.Address) (bool, error) {
	k, err := addrToKey(addr)
	if err != nil {
		return false, err
	}

	var exists bool
	err = idx.db.View(func(dbTx database.Tx) error {
		meta := dbTx.Metadata()
		existsAddrIndex := meta.Bucket(existsAddrIndexKey)
		exists = existsAddrIndex.Get(k[:]) != nil

		return nil
	})
	if err != nil {
		return false, err
	}

	// Only check the in memory map if needed.
	if !exists {
		idx.unconfirmedLock.RLock()
		_, exists = idx.mpExistsAddr[k]
		idx.unconfirmedLock.RUnlock()
	}

	return exists, nil
}

// ExistsAddresses is the concurrency safe, exported function that returns
// whether or not each address in a slice of addresses has been seen before.
func (idx *ExistsAddrIndex) ExistsAddresses(addrs []stdaddr.Address) ([]bool, error) {
	exists := make([]bool, len(addrs))
	addrKeys := make([][addrKeySize]byte, len(addrs))
	for i := range addrKeys {
		var err error
		addrKeys[i], err = addrToKey(addrs[i])
		if err != nil {
			return nil, err
		}
	}

	err := idx.db.View(func(dbTx database.Tx) error {
		for i := range addrKeys {
			meta := dbTx.Metadata()
			existsAddrIndex := meta.Bucket(existsAddrIndexKey)

			exists[i] = existsAddrIndex.Get(addrKeys[i][:]) != nil
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	idx.unconfirmedLock.RLock()
	for i := range addrKeys {
		if !exists[i] {
			_, exists[i] = idx.mpExistsAddr[addrKeys[i]]
		}
	}
	idx.unconfirmedLock.RUnlock()

	return exists, nil
}

// connectBlock adds all addresses associated with transactions in the
// provided block.
//
// This is part of the Indexer interface.
func (idx *ExistsAddrIndex) connectBlock(dbTx database.Tx, block, parent *dcrutil.Block, _ PrevScripter, isTreasuryEnabled bool) error {
	// NOTE: The fact that the block can disapprove the regular tree of the
	// previous block is ignored for this index because even though technically
	// the address might become unused again if its only use was in a
	// transaction that was disapproved, the chances of that are extremely low
	// since disapproved transactions are nearly always mined again in another
	// block.
	//
	// More importantly, the primary purpose of this index is to track whether
	// or not addresses have ever been seen, so even if they technically end up
	// becoming unused, they were still seen.

	usedAddrs := make(map[[addrKeySize]byte]struct{})
	blockTxns := make([]*dcrutil.Tx, 0, len(block.Transactions())+
		len(block.STransactions()))
	blockTxns = append(blockTxns, block.Transactions()...)
	blockTxns = append(blockTxns, block.STransactions()...)
	for _, tx := range blockTxns {
		msgTx := tx.MsgTx()
		isSStx := stake.IsSStx(msgTx)
		for _, txIn := range msgTx.TxIn {
			// Note that the functions used here require v0 scripts.  Hence it
			// is used for the script version.  This will ultimately need to
			// updated to support new script versions.
			const scriptVersion = 0
			if txscript.IsMultisigSigScript(txIn.SignatureScript) {
				rs := txscript.MultisigRedeemScriptFromScriptSig(
					txIn.SignatureScript)
				class, addrs, _, err := txscript.ExtractPkScriptAddrs(
					scriptVersion, rs, idx.chain.ChainParams(),
					isTreasuryEnabled)
				if err != nil {
					// Non-standard outputs are skipped.
					continue
				}
				if class != txscript.MultiSigTy {
					// This should never happen, but be paranoid.
					continue
				}

				for _, addr := range addrs {
					k, err := addrToKey(addr)
					if err != nil {
						continue
					}

					usedAddrs[k] = struct{}{}
				}
			}
		}

		for _, txOut := range tx.MsgTx().TxOut {
			class, addrs, _, err := txscript.ExtractPkScriptAddrs(
				txOut.Version, txOut.PkScript, idx.chain.ChainParams(),
				isTreasuryEnabled)
			if err != nil {
				// Non-standard outputs are skipped.
				continue
			}

			if isSStx && class == txscript.NullDataTy {
				addr, err := stake.AddrFromSStxPkScrCommitment(txOut.PkScript,
					idx.chain.ChainParams())
				if err != nil {
					// Ignore unsupported address types.
					continue
				}

				addrs = append(addrs, addr)
			}

			for _, addr := range addrs {
				k, err := addrToKey(addr)
				if err != nil {
					// Ignore unsupported address types.
					continue
				}

				usedAddrs[k] = struct{}{}
			}
		}
	}

	// Write all the newly used addresses to the database,
	// skipping any keys that already exist. Write any
	// addresses we see in mempool at this time, too,
	// then remove them from the unconfirmed map drop
	// dropping the old map and reassigning a new map.
	idx.unconfirmedLock.Lock()
	for addrKey := range idx.mpExistsAddr {
		usedAddrs[addrKey] = struct{}{}
	}
	idx.mpExistsAddr = make(map[[addrKeySize]byte]struct{})
	idx.unconfirmedLock.Unlock()

	meta := dbTx.Metadata()
	existsAddrIdxBucket := meta.Bucket(existsAddrIndexKey)
	newUsedAddrs := make(map[[addrKeySize]byte]struct{})
	for addrKey := range usedAddrs {
		if !idx.existsAddress(existsAddrIdxBucket, addrKey) {
			newUsedAddrs[addrKey] = struct{}{}
		}
	}

	for addrKey := range newUsedAddrs {
		err := dbPutExistsAddr(existsAddrIdxBucket, addrKey)
		if err != nil {
			return err
		}
	}

	// Update the current index tip.
	return dbPutIndexerTip(dbTx, idx.Key(), block.Hash(), int32(block.Height()))
}

// disconnectBlock only updates the index tip because the index never removes
// addresses, even in the case of a reorg.
//
// This is part of the Indexer interface.
func (idx *ExistsAddrIndex) disconnectBlock(dbTx database.Tx, block, parent *dcrutil.Block, _ PrevScripter, _ bool) error {
	// The primary purpose of this index is to track whether or not addresses
	// have ever been seen, so even if they ultimately end up technically
	// becoming unused due to being in a block that was disconnected and the
	// associated transactions never make it into a new block for some reason,
	// it was still seen at some point.  Thus, don't bother removing entries.
	//
	// Note that this does mean different nodes may slightly disagree about
	// whether or not an address that only ever existed in an orphaned side
	// chain was seen, however, that is an acceptable tradeoff given the use
	// case and the huge performance gained from not having to constantly update
	// the index with usage counts that would be required to properly handle
	// disconnecting block and disapproved regular trees.

	// Update the current index tip.
	return dbPutIndexerTip(dbTx, idx.Key(), &block.MsgBlock().Header.PrevBlock,
		int32(block.Height()-1))
}

// addUnconfirmedTx adds all addresses related to the transaction to the
// unconfirmed (memory-only) exists address index.
//
// This function MUST be called with the unconfirmed lock held.
func (idx *ExistsAddrIndex) addUnconfirmedTx(tx *wire.MsgTx, isTreasuryEnabled bool) {
	isSStx := stake.IsSStx(tx)
	for _, txIn := range tx.TxIn {
		if txscript.IsMultisigSigScript(txIn.SignatureScript) {
			// Note that the functions used here require v0 scripts.  Hence it
			// is used for the script version.  This will ultimately need to
			// updated to support new script versions.
			const scriptVersion = 0
			rs := txscript.MultisigRedeemScriptFromScriptSig(
				txIn.SignatureScript)
			class, addrs, _, err := txscript.ExtractPkScriptAddrs(
				scriptVersion, rs, idx.chain.ChainParams(),
				isTreasuryEnabled)
			if err != nil {
				// Non-standard outputs are skipped.
				continue
			}
			if class != txscript.MultiSigTy {
				// This should never happen, but be paranoid.
				continue
			}

			for _, addr := range addrs {
				k, err := addrToKey(addr)
				if err != nil {
					continue
				}

				if _, exists := idx.mpExistsAddr[k]; !exists {
					idx.mpExistsAddr[k] = struct{}{}
				}
			}
		}
	}

	for _, txOut := range tx.TxOut {
		class, addrs, _, err := txscript.ExtractPkScriptAddrs(txOut.Version,
			txOut.PkScript, idx.chain.ChainParams(), isTreasuryEnabled)
		if err != nil {
			// Non-standard outputs are skipped.
			continue
		}

		if isSStx && class == txscript.NullDataTy {
			addr, err := stake.AddrFromSStxPkScrCommitment(txOut.PkScript,
				idx.chain.ChainParams())
			if err != nil {
				// Ignore unsupported address types.
				continue
			}

			addrs = append(addrs, addr)
		}

		for _, addr := range addrs {
			k, err := addrToKey(addr)
			if err != nil {
				// Ignore unsupported address types.
				continue
			}

			if _, exists := idx.mpExistsAddr[k]; !exists {
				idx.mpExistsAddr[k] = struct{}{}
			}
		}
	}
}

// AddUnconfirmedTx adds all addresses related to the transaction to the
// unconfirmed (memory-only) exists address index.
//
// This function is safe for concurrent access.
func (idx *ExistsAddrIndex) AddUnconfirmedTx(tx *wire.MsgTx, isTreasuryEnabled bool) {
	idx.unconfirmedLock.Lock()
	idx.addUnconfirmedTx(tx, isTreasuryEnabled)
	idx.unconfirmedLock.Unlock()
}

// DropExistsAddrIndex drops the exists address index from the provided database
// if it exists.
func DropExistsAddrIndex(ctx context.Context, db database.DB) error {
	return dropFlatIndex(ctx, db, existsAddrIndexKey, existsAddressIndexName)
}

// DropIndex drops the exists address index from the provided database if it
// exists.
func (*ExistsAddrIndex) DropIndex(ctx context.Context, db database.DB) error {
	return DropExistsAddrIndex(ctx, db)
}

// ProcessNotification indexes the provided notification based on its
// notification type.
//
// This is part of the Indexer interface.
func (idx *ExistsAddrIndex) ProcessNotification(dbTx database.Tx, ntfn *IndexNtfn) error {
	switch ntfn.NtfnType {
	case ConnectNtfn:
		err := idx.connectBlock(dbTx, ntfn.Block, ntfn.Parent,
			ntfn.PrevScripts, ntfn.IsTreasuryEnabled)
		if err != nil {
			return fmt.Errorf("%s: unable to connect block: %v", idx.Name(), err)
		}

	case DisconnectNtfn:
		err := idx.disconnectBlock(dbTx, ntfn.Block, ntfn.Parent,
			ntfn.PrevScripts, ntfn.IsTreasuryEnabled)
		if err != nil {
			log.Errorf("%s: unable to disconnect block: %v", idx.Name(), err)
		}

	default:
		return fmt.Errorf("%s: unknown notification type received: %d",
			idx.Name(), ntfn.NtfnType)
	}

	return nil
}
