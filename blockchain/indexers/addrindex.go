// Copyright (c) 2016 The btcsuite developers
// Copyright (c) 2016-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"context"
	"errors"
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
	// addrIndexName is the human-readable name for the index.
	addrIndexName = "address index"

	// addrIndexVersion is the current version of the address index.
	addrIndexVersion = 2

	// level0MaxEntries is the maximum number of transactions that are
	// stored in level 0 of an address index entry.  Subsequent levels store
	// 2^n * level0MaxEntries entries, or in words, double the maximum of
	// the previous level.
	level0MaxEntries = 8

	// addrKeySize is the number of bytes an address key consumes in the
	// index.  It consists of 1 byte address type + 20 bytes hash160.
	addrKeySize = 1 + 20

	// levelKeySize is the number of bytes a level key in the address index
	// consumes.  It consists of the address key + 1 byte for the level.
	levelKeySize = addrKeySize + 1

	// levelOffset is the offset in the level key which identifies the
	// level.
	levelOffset = levelKeySize - 1

	// addrKeyTypePubKeyHash is the address type in an address key which
	// represents both a pay-to-pubkey-hash and a pay-to-pubkey address.
	// This is done because both are identical for the purposes of the
	// address index.
	addrKeyTypePubKeyHash = 0

	// addrKeyTypePubKeyHashEdwards is the address type in an address key
	// which represents both a pay-to-pubkey-hash and a pay-to-pubkey-alt
	// address using Schnorr signatures over the Ed25519 curve.  This is
	// done because both are identical for the purposes of the address
	// index.
	addrKeyTypePubKeyHashEdwards = 1

	// addrKeyTypePubKeyHashSchnorr is the address type in an address key
	// which represents both a pay-to-pubkey-hash and a pay-to-pubkey-alt
	// address using Schnorr signatures over the secp256k1 curve.  This is
	// done because both are identical for the purposes of the address
	// index.
	addrKeyTypePubKeyHashSchnorr = 2

	// addrKeyTypeScriptHash is the address type in an address key which
	// represents a pay-to-script-hash address.  This is necessary because
	// the hash of a pubkey address might be the same as that of a script
	// hash.
	addrKeyTypeScriptHash = 3
)

var (
	// addrIndexKey is the key of the address index and the db bucket used
	// to house it.
	addrIndexKey = []byte("txbyaddridx")

	// errUnsupportedAddressType is an error that is used to signal an
	// unsupported address type has been used.
	errUnsupportedAddressType = errors.New("address type is not supported " +
		"by the address index")
)

// -----------------------------------------------------------------------------
// The address index maps addresses referenced in the blockchain to a list of
// all the transactions involving that address.  Transactions are stored
// according to their order of appearance in the blockchain.  That is to say
// first by block height and then by offset inside the block.  It is also
// important to note that this implementation requires the transaction index
// since it is needed in order to catch up old blocks due to the fact the spent
// outputs will already be pruned from the utxo set.
//
// The approach used to store the index is similar to a log-structured merge
// tree (LSM tree) and is thus similar to how leveldb works internally.
//
// Every address consists of one or more entries identified by a level starting
// from 0 where each level holds a maximum number of entries such that each
// subsequent level holds double the maximum of the previous one.  In equation
// form, the number of entries each level holds is 2^n * firstLevelMaxSize.
//
// New transactions are appended to level 0 until it becomes full at which point
// the entire level 0 entry is appended to the level 1 entry and level 0 is
// cleared.  This process continues until level 1 becomes full at which point it
// will be appended to level 2 and cleared and so on.
//
// The result of this is the lower levels contain newer transactions and the
// transactions within each level are ordered from oldest to newest.
//
// The intent of this approach is to provide a balance between space efficiency
// and indexing cost.  Storing one entry per transaction would have the lowest
// indexing cost, but would waste a lot of space because the same address hash
// would be duplicated for every transaction key.  On the other hand, storing a
// single entry with all transactions would be the most space efficient, but
// would cause indexing cost to grow quadratically with the number of
// transactions involving the same address.  The approach used here provides
// logarithmic insertion and retrieval.
//
// The serialized key format is:
//
//   <addr type><addr hash><level>
//
//   Field           Type      Size
//   addr type       uint8     1 byte
//   addr hash       hash160   20 bytes
//   level           uint8     1 byte
//   -----
//   Total: 22 bytes
//
// The serialized value format is:
//
//   [<block id><start offset><tx length><block index>,...]
//
//   Field           Type      Size
//   block id        uint32    4 bytes
//   start offset    uint32    4 bytes
//   tx length       uint32    4 bytes
//   block index     uint32    4 bytes
//   -----
//   Total: 16 bytes per indexed tx
// -----------------------------------------------------------------------------

// fetchBlockHashFunc defines a callback function to use in order to convert a
// serialized block ID to an associated block hash.
type fetchBlockHashFunc func(serializedID []byte) (*chainhash.Hash, error)

// serializeAddrIndexEntry serializes the provided block id and transaction
// location according to the format described in detail above.
func serializeAddrIndexEntry(blockID uint32, txLoc wire.TxLoc, blockIndex uint32) []byte {
	// Serialize the entry.
	serialized := make([]byte, txEntrySize)
	byteOrder.PutUint32(serialized, blockID)
	byteOrder.PutUint32(serialized[4:], uint32(txLoc.TxStart))
	byteOrder.PutUint32(serialized[8:], uint32(txLoc.TxLen))
	byteOrder.PutUint32(serialized[12:], blockIndex)
	return serialized
}

// deserializeAddrIndexEntry decodes the passed serialized byte slice into the
// provided region struct according to the format described in detail above and
// uses the passed block hash fetching function in order to convert the block ID
// to the associated block hash.
func deserializeAddrIndexEntry(serialized []byte, entry *TxIndexEntry, fetchBlockHash fetchBlockHashFunc) error {
	// Ensure there are enough bytes to decode.
	if len(serialized) < txEntrySize {
		return errDeserialize("unexpected end of data")
	}

	hash, err := fetchBlockHash(serialized[0:4])
	if err != nil {
		return err
	}
	region := &entry.BlockRegion
	region.Hash = hash
	region.Offset = byteOrder.Uint32(serialized[4:8])
	region.Len = byteOrder.Uint32(serialized[8:12])
	entry.BlockIndex = byteOrder.Uint32(serialized[12:16])
	return nil
}

// keyForLevel returns the key for a specific address and level in the address
// index entry.
func keyForLevel(addrKey [addrKeySize]byte, level uint8) [levelKeySize]byte {
	var key [levelKeySize]byte
	copy(key[:], addrKey[:])
	key[levelOffset] = level
	return key
}

// dbPutAddrIndexEntry updates the address index to include the provided entry
// according to the level-based scheme described in detail above.
func dbPutAddrIndexEntry(bucket internalBucket, addrKey [addrKeySize]byte, blockID uint32, txLoc wire.TxLoc, blockIndex uint32) error {
	// Start with level 0 and its initial max number of entries.
	curLevel := uint8(0)
	maxLevelBytes := level0MaxEntries * txEntrySize

	// Simply append the new entry to level 0 and return now when it will
	// fit.  This is the most common path.
	newData := serializeAddrIndexEntry(blockID, txLoc, blockIndex)
	level0Key := keyForLevel(addrKey, 0)
	level0Data := bucket.Get(level0Key[:])
	if len(level0Data)+len(newData) <= maxLevelBytes {
		mergedData := newData
		if len(level0Data) > 0 {
			mergedData = make([]byte, len(level0Data)+len(newData))
			copy(mergedData, level0Data)
			copy(mergedData[len(level0Data):], newData)
		}
		return bucket.Put(level0Key[:], mergedData)
	}

	// At this point, level 0 is full, so merge each level into higher
	// levels as many times as needed to free up level 0.
	prevLevelData := level0Data
	for {
		// Each new level holds twice as much as the previous one.
		curLevel++
		maxLevelBytes *= 2

		// Move to the next level as long as the current level is full.
		curLevelKey := keyForLevel(addrKey, curLevel)
		curLevelData := bucket.Get(curLevelKey[:])
		if len(curLevelData) == maxLevelBytes {
			prevLevelData = curLevelData
			continue
		}

		// The current level has room for the data in the previous one,
		// so merge the data from previous level into it.
		mergedData := prevLevelData
		if len(curLevelData) > 0 {
			mergedData = make([]byte, len(curLevelData)+
				len(prevLevelData))
			copy(mergedData, curLevelData)
			copy(mergedData[len(curLevelData):], prevLevelData)
		}
		err := bucket.Put(curLevelKey[:], mergedData)
		if err != nil {
			return err
		}

		// Move all of the levels before the previous one up a level.
		for mergeLevel := curLevel - 1; mergeLevel > 0; mergeLevel-- {
			mergeLevelKey := keyForLevel(addrKey, mergeLevel)
			prevLevelKey := keyForLevel(addrKey, mergeLevel-1)
			prevData := bucket.Get(prevLevelKey[:])
			err := bucket.Put(mergeLevelKey[:], prevData)
			if err != nil {
				return err
			}
		}
		break
	}

	// Finally, insert the new entry into level 0 now that it is empty.
	return bucket.Put(level0Key[:], newData)
}

// dbFetchAddrIndexEntries returns block regions for transactions referenced by
// the given address key and the number of entries skipped since it could have
// been less in the case where there are less total entries than the requested
// number of entries to skip.
func dbFetchAddrIndexEntries(bucket internalBucket, addrKey [addrKeySize]byte, numToSkip, numRequested uint32, reverse bool, fetchBlockHash fetchBlockHashFunc) ([]TxIndexEntry, uint32, error) {
	// When the reverse flag is not set, all levels need to be fetched
	// because numToSkip and numRequested are counted from the oldest
	// transactions (highest level) and thus the total count is needed.
	// However, when the reverse flag is set, only enough records to satisfy
	// the requested amount are needed.
	var level uint8
	var serialized []byte
	for !reverse || len(serialized) < int(numToSkip+numRequested)*txEntrySize {
		curLevelKey := keyForLevel(addrKey, level)
		levelData := bucket.Get(curLevelKey[:])
		if levelData == nil {
			// Stop when there are no more levels.
			break
		}

		// Higher levels contain older transactions, so prepend them.
		prepended := make([]byte, len(serialized)+len(levelData))
		copy(prepended, levelData)
		copy(prepended[len(levelData):], serialized)
		serialized = prepended
		level++
	}

	// When the requested number of entries to skip is larger than the
	// number available, skip them all and return now with the actual number
	// skipped.
	numEntries := uint32(len(serialized) / txEntrySize)
	if numToSkip >= numEntries {
		return nil, numEntries, nil
	}

	// Nothing more to do when there are no requested entries.
	if numRequested == 0 {
		return nil, numToSkip, nil
	}

	// Limit the number to load based on the number of available entries,
	// the number to skip, and the number requested.
	numToLoad := numEntries - numToSkip
	if numToLoad > numRequested {
		numToLoad = numRequested
	}

	// Start the offset after all skipped entries and load the calculated
	// number.
	results := make([]TxIndexEntry, numToLoad)
	for i := uint32(0); i < numToLoad; i++ {
		// Calculate the read offset according to the reverse flag.
		var offset uint32
		if reverse {
			offset = (numEntries - numToSkip - i - 1) * txEntrySize
		} else {
			offset = (numToSkip + i) * txEntrySize
		}

		// Deserialize and populate the result.
		err := deserializeAddrIndexEntry(serialized[offset:],
			&results[i], fetchBlockHash)
		if err != nil {
			// Ensure any deserialization errors are returned as
			// database corruption errors.
			if isDeserializeErr(err) {
				str := fmt.Sprintf("failed to deserialized address index "+
					"for key %x: %v", addrKey, err)
				err = makeDbErr(database.ErrCorruption, str)
			}

			return nil, 0, err
		}
	}

	return results, numToSkip, nil
}

// minEntriesToReachLevel returns the minimum number of entries that are
// required to reach the given address index level.
func minEntriesToReachLevel(level uint8) int {
	maxEntriesForLevel := level0MaxEntries
	minRequired := 1
	for l := uint8(1); l <= level; l++ {
		minRequired += maxEntriesForLevel
		maxEntriesForLevel *= 2
	}
	return minRequired
}

// maxEntriesForLevel returns the maximum number of entries allowed for the
// given address index level.
func maxEntriesForLevel(level uint8) int {
	numEntries := level0MaxEntries
	for l := level; l > 0; l-- {
		numEntries *= 2
	}
	return numEntries
}

// dbRemoveAddrIndexEntries removes the specified number of entries from
// the address index for the provided key.  An assertion error will be returned
// if the count exceeds the total number of entries in the index.
func dbRemoveAddrIndexEntries(bucket internalBucket, addrKey [addrKeySize]byte, count int) error {
	// Nothing to do if no entries are being deleted.
	if count <= 0 {
		return nil
	}

	// Make use of a local map to track pending updates and define a closure
	// to apply it to the database.  This is done in order to reduce the
	// number of database reads and because there is more than one exit
	// path that needs to apply the updates.
	pendingUpdates := make(map[uint8][]byte)
	applyPending := func() error {
		for level, data := range pendingUpdates {
			curLevelKey := keyForLevel(addrKey, level)
			if len(data) == 0 {
				err := bucket.Delete(curLevelKey[:])
				if err != nil {
					return err
				}
				continue
			}
			err := bucket.Put(curLevelKey[:], data)
			if err != nil {
				return err
			}
		}
		return nil
	}

	// Loop forwards through the levels while removing entries until the
	// specified number has been removed.  This will potentially result in
	// entirely empty lower levels which will be backfilled below.
	var highestLoadedLevel uint8
	numRemaining := count
	for level := uint8(0); numRemaining > 0; level++ {
		// Load the data for the level from the database.
		curLevelKey := keyForLevel(addrKey, level)
		curLevelData := bucket.Get(curLevelKey[:])
		if len(curLevelData) == 0 && numRemaining > 0 {
			return AssertError(fmt.Sprintf("dbRemoveAddrIndexEntries "+
				"not enough entries for address key %x to "+
				"delete %d entries", addrKey, count))
		}
		pendingUpdates[level] = curLevelData
		highestLoadedLevel = level

		// Delete the entire level as needed.
		numEntries := len(curLevelData) / txEntrySize
		if numRemaining >= numEntries {
			pendingUpdates[level] = nil
			numRemaining -= numEntries
			continue
		}

		// Remove remaining entries to delete from the level.
		offsetEnd := len(curLevelData) - (numRemaining * txEntrySize)
		pendingUpdates[level] = curLevelData[:offsetEnd]
		break
	}

	// When all elements in level 0 were not removed there is nothing left
	// to do other than updating the database.
	if len(pendingUpdates[0]) != 0 {
		return applyPending()
	}

	// At this point there are one or more empty levels before the current
	// level which need to be backfilled and the current level might have
	// had some entries deleted from it as well.  Since all levels after
	// level 0 are required to either be empty, half full, or completely
	// full, the current level must be adjusted accordingly by backfilling
	// each previous levels in a way which satisfies the requirements.  Any
	// entries that are left are assigned to level 0 after the loop as they
	// are guaranteed to fit by the logic in the loop.  In other words, this
	// effectively squashes all remaining entries in the current level into
	// the lowest possible levels while following the level rules.
	//
	// Note that the level after the current level might also have entries
	// and gaps are not allowed, so this also keeps track of the lowest
	// empty level so the code below knows how far to backfill in case it is
	// required.
	lowestEmptyLevel := uint8(255)
	curLevelData := pendingUpdates[highestLoadedLevel]
	curLevelMaxEntries := maxEntriesForLevel(highestLoadedLevel)
	for level := highestLoadedLevel; level > 0; level-- {
		// When there are not enough entries left in the current level
		// for the number that would be required to reach it, clear the
		// the current level which effectively moves them all up to the
		// previous level on the next iteration.  Otherwise, there are
		// are sufficient entries, so update the current level to
		// contain as many entries as possible while still leaving
		// enough remaining entries required to reach the level.
		numEntries := len(curLevelData) / txEntrySize
		prevLevelMaxEntries := curLevelMaxEntries / 2
		minPrevRequired := minEntriesToReachLevel(level - 1)
		if numEntries < prevLevelMaxEntries+minPrevRequired {
			lowestEmptyLevel = level
			pendingUpdates[level] = nil
		} else {
			// This level can only be completely full or half full,
			// so choose the appropriate offset to ensure enough
			// entries remain to reach the level.
			var offset int
			if numEntries-curLevelMaxEntries >= minPrevRequired {
				offset = curLevelMaxEntries * txEntrySize
			} else {
				offset = prevLevelMaxEntries * txEntrySize
			}
			pendingUpdates[level] = curLevelData[:offset]
			curLevelData = curLevelData[offset:]
		}

		curLevelMaxEntries = prevLevelMaxEntries
	}
	pendingUpdates[0] = curLevelData
	if len(curLevelData) == 0 {
		lowestEmptyLevel = 0
	}

	// When the highest loaded level is empty, it's possible the level after
	// it still has data and thus that data needs to be backfilled as well.
	for len(pendingUpdates[highestLoadedLevel]) == 0 {
		// When the next level is empty too, the is no data left to
		// continue backfilling, so there is nothing left to do.
		// Otherwise, populate the pending updates map with the newly
		// loaded data and update the highest loaded level accordingly.
		level := highestLoadedLevel + 1
		curLevelKey := keyForLevel(addrKey, level)
		levelData := bucket.Get(curLevelKey[:])
		if len(levelData) == 0 {
			break
		}
		pendingUpdates[level] = levelData
		highestLoadedLevel = level

		// At this point the highest level is not empty, but it might
		// be half full.  When that is the case, move it up a level to
		// simplify the code below which backfills all lower levels that
		// are still empty.  This also means the current level will be
		// empty, so the loop will perform another iteration to
		// potentially backfill this level with data from the next one.
		curLevelMaxEntries := maxEntriesForLevel(level)
		if len(levelData)/txEntrySize != curLevelMaxEntries {
			pendingUpdates[level] = nil
			pendingUpdates[level-1] = levelData
			level--
			curLevelMaxEntries /= 2
		}

		// Backfill all lower levels that are still empty by iteratively
		// halfing the data until the lowest empty level is filled.
		for level > lowestEmptyLevel {
			offset := (curLevelMaxEntries / 2) * txEntrySize
			pendingUpdates[level] = levelData[:offset]
			levelData = levelData[offset:]
			pendingUpdates[level-1] = levelData
			level--
			curLevelMaxEntries /= 2
		}

		// The lowest possible empty level is now the highest loaded
		// level.
		lowestEmptyLevel = highestLoadedLevel
	}

	// Apply the pending updates.
	return applyPending()
}

// addrToKey converts known address types to an addrindex key.  An error is
// returned for unsupported types.
func addrToKey(addr stdaddr.Address) ([addrKeySize]byte, error) {
	// Convert public key addresses to public key hash variants.
	if addrPKH, ok := addr.(stdaddr.AddressPubKeyHasher); ok {
		addr = addrPKH.AddressPubKeyHash()
	}

	switch addr := addr.(type) {
	case *stdaddr.AddressPubKeyHashEcdsaSecp256k1V0:
		var result [addrKeySize]byte
		result[0] = addrKeyTypePubKeyHash
		copy(result[1:], addr.Hash160()[:])
		return result, nil

	case *stdaddr.AddressPubKeyHashEd25519V0:
		var result [addrKeySize]byte
		result[0] = addrKeyTypePubKeyHashEdwards
		copy(result[1:], addr.Hash160()[:])
		return result, nil

	case *stdaddr.AddressPubKeyHashSchnorrSecp256k1V0:
		var result [addrKeySize]byte
		result[0] = addrKeyTypePubKeyHashSchnorr
		copy(result[1:], addr.Hash160()[:])
		return result, nil

	case *stdaddr.AddressScriptHashV0:
		var result [addrKeySize]byte
		result[0] = addrKeyTypeScriptHash
		copy(result[1:], addr.Hash160()[:])
		return result, nil
	}

	return [addrKeySize]byte{}, errUnsupportedAddressType
}

// AddrIndex implements a transaction by address index.  That is to say, it
// supports querying all transactions that reference a given address because
// they are either crediting or debiting the address.  The returned transactions
// are ordered according to their order of appearance in the blockchain.  In
// other words, first by block height and then by offset inside the block.
//
// In addition, support is provided for a memory-only index of unconfirmed
// transactions such as those which are kept in the memory pool before inclusion
// in a block.
type AddrIndex struct {
	// The following fields are set when the instance is created and can't
	// be changed afterwards, so there is no need to protect them with a
	// separate mutex.
	db          database.DB
	chain       ChainQueryer
	chainParams *chaincfg.Params
	sub         *IndexSubscription
	consumer    *SpendConsumer

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
	txnsByAddr      map[[addrKeySize]byte]map[chainhash.Hash]*dcrutil.Tx
	addrsByTx       map[chainhash.Hash]map[[addrKeySize]byte]struct{}

	subscribers map[chan bool]struct{}
	mtx         sync.Mutex
	cancel      context.CancelFunc
}

// Ensure the AddrIndex type implements the Indexer interface.
var _ Indexer = (*AddrIndex)(nil)

// Ensure the AddrIndex type implements the NeedsInputser interface.
var _ NeedsInputser = (*AddrIndex)(nil)

// NeedsInputs signals that the index requires the referenced inputs in order
// to properly create the index.
//
// This implements the NeedsInputser interface.
func (idx *AddrIndex) NeedsInputs() bool {
	return true
}

// Init creates a transaction by address index.  In particular, it maintains
// a map of transactions and their associated addresses via a stream of updates
// on connected and disconnected blocks.
//
// This is part of the Indexer interface.
func (idx *AddrIndex) Init(ctx context.Context, chainParams *chaincfg.Params) error {
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

	// Recover the address index and its dependents to the main chain if needed.
	if err := recover(ctx, idx); err != nil {
		return err
	}

	return nil
}

// Key returns the database key to use for the index as a byte slice.
//
// This is part of the Indexer interface.
func (idx *AddrIndex) Key() []byte {
	return addrIndexKey
}

// Name returns the human-readable name of the index.
//
// This is part of the Indexer interface.
func (idx *AddrIndex) Name() string {
	return addrIndexName
}

// Version returns the current version of the index.
//
// This is part of the Indexer interface.
func (idx *AddrIndex) Version() uint32 {
	return addrIndexVersion
}

// DB returns the database of the index.
//
// This is part of the Indexer interface.
func (idx *AddrIndex) DB() database.DB {
	return idx.db
}

// Queryer returns the chain queryer.
//
// This is part of the Indexer interface.
func (idx *AddrIndex) Queryer() ChainQueryer {
	return idx.chain
}

// Tip returns the current tip of the index.
//
// This is part of the Indexer interface.
func (idx *AddrIndex) Tip() (int64, *chainhash.Hash, error) {
	return tip(idx.db, idx.Key())
}

// IndexSubscription returns the subscription for index updates.
//
// This is part of the Indexer interface.
func (idx *AddrIndex) IndexSubscription() *IndexSubscription {
	return idx.sub
}

// Subscribers returns all client channels waiting for the next index update.
//
// This is part of the Indexer interface.
func (idx *AddrIndex) Subscribers() map[chan bool]struct{} {
	idx.mtx.Lock()
	defer idx.mtx.Unlock()
	return idx.subscribers
}

// WaitForSync subscribes clients for the next index sync update.
//
// This is part of the Indexer interface.
func (idx *AddrIndex) WaitForSync() chan bool {
	c := make(chan bool)

	idx.mtx.Lock()
	idx.subscribers[c] = struct{}{}
	idx.mtx.Unlock()

	return c
}

// Create is invoked when the index is created for the first time.  It creates
// the bucket for the address index.
//
// This is part of the Indexer interface.
func (idx *AddrIndex) Create(dbTx database.Tx) error {
	_, err := dbTx.Metadata().CreateBucket(addrIndexKey)
	return err
}

// writeIndexData represents the address index data to be written for one block.
// It consists of the address mapped to an ordered list of the transactions
// that involve the address in block.  It is ordered so the transactions can be
// stored in the order they appear in the block.
type writeIndexData map[[addrKeySize]byte][]int

// indexPkScript extracts all standard addresses from the passed public key
// script and maps each of them to the associated transaction using the passed
// map.
func (idx *AddrIndex) indexPkScript(data writeIndexData, scriptVersion uint16, pkScript []byte, txIdx int, isSStx bool, isTreasuryEnabled bool) {
	// Nothing to index if the script is non-standard or otherwise doesn't
	// contain any addresses.
	class, addrs, _, err := txscript.ExtractPkScriptAddrs(scriptVersion,
		pkScript, idx.chainParams, isTreasuryEnabled)
	if err != nil {
		return
	}

	if isSStx && class == txscript.NullDataTy {
		addr, err := stake.AddrFromSStxPkScrCommitment(pkScript, idx.chainParams)
		if err != nil {
			return
		}

		addrs = append(addrs, addr)
	}

	if len(addrs) == 0 {
		return
	}

	for _, addr := range addrs {
		addrKey, err := addrToKey(addr)
		if err != nil {
			// Ignore unsupported address types.
			continue
		}

		// Avoid inserting the transaction more than once.  Since the
		// transactions are indexed serially any duplicates will be
		// indexed in a row, so checking the most recent entry for the
		// address is enough to detect duplicates.
		indexedTxns := data[addrKey]
		numTxns := len(indexedTxns)
		if numTxns > 0 && indexedTxns[numTxns-1] == txIdx {
			continue
		}
		indexedTxns = append(indexedTxns, txIdx)
		data[addrKey] = indexedTxns
	}
}

// indexBlock extracts all of the standard addresses from all of the regular and
// stake transactions in the passed block and maps each of them to the
// associated transaction using the passed map.
func (idx *AddrIndex) indexBlock(data writeIndexData, block *dcrutil.Block, prevScripts PrevScripter, isTreasuryEnabled bool) {
	regularTxns := block.Transactions()
	for txIdx, tx := range regularTxns {
		// Coinbases do not reference any inputs.  Since the block is
		// required to have already gone through full validation, it has
		// already been proven that the first transaction in the block
		// is a coinbase.
		if txIdx != 0 {
			for _, txIn := range tx.MsgTx().TxIn {
				// The input should always be available since the index contract
				// requires it, however, be safe and simply ignore any missing
				// entries.
				origin := &txIn.PreviousOutPoint
				version, pkScript, ok := prevScripts.PrevScript(origin)
				if !ok {
					log.Warnf("Missing input %v:%d for tx %v while indexing "+
						"block %v (height %v)\n", origin, origin.Tree,
						tx.Hash(), block.Hash(), block.Height())
					continue
				}

				idx.indexPkScript(data, version, pkScript,
					txIdx, false, isTreasuryEnabled)
			}
		}

		for _, txOut := range tx.MsgTx().TxOut {
			idx.indexPkScript(data, txOut.Version, txOut.PkScript,
				txIdx, false, isTreasuryEnabled)
		}
	}

	for txIdx, tx := range block.STransactions() {
		msgTx := tx.MsgTx()
		thisTxOffset := txIdx + len(regularTxns)

		isSSGen := stake.IsSSGen(msgTx, isTreasuryEnabled)
		var (
			isTSpend, isTreasuryBase bool
		)
		if isTreasuryEnabled {
			// Short circuit expensive Is* calls.
			isTreasuryBase = !isSSGen && stake.IsTreasuryBase(msgTx)
			isTSpend = !isTreasuryBase && stake.IsTSpend(msgTx)
		}
		for i, txIn := range msgTx.TxIn {
			// Skip stakebases.
			if isSSGen && i == 0 {
				continue
			}

			// Skip treasury transactions that do not have inputs.
			if isTreasuryBase || isTSpend {
				continue
			}

			// The input should always be available since the index contract
			// requires it, however, be safe and simply ignore any missing
			// entries.
			origin := &txIn.PreviousOutPoint
			version, pkScript, ok := prevScripts.PrevScript(origin)
			if !ok {
				log.Warnf("Missing input %v:%d for tx %v while indexing "+
					"block %v (height %v)\n", origin, origin.Tree,
					tx.Hash(), block.Hash(), block.Height())
				continue
			}

			idx.indexPkScript(data, version, pkScript, thisTxOffset,
				false, isTreasuryEnabled)
		}

		isSStx := stake.IsSStx(msgTx)
		for _, txOut := range msgTx.TxOut {
			idx.indexPkScript(data, txOut.Version, txOut.PkScript,
				thisTxOffset, isSStx, isTreasuryEnabled)
		}
	}
}

// connectBlock adds a mapping for all addresses associated with transactions in
// the provided block.
func (idx *AddrIndex) connectBlock(dbTx database.Tx, block, parent *dcrutil.Block, prevScripts PrevScripter, isTreasuryEnabled bool) error {
	// NOTE: The fact that the block can disapprove the regular tree of the
	// previous block is ignored for this index because even though the
	// disapproved transactions no longer apply spend semantics, they still
	// exist within the block and thus have to be processed before the next
	// block disapproves them.

	// The offset and length of the transactions within the serialized block.
	txLocs, stakeTxLocs, err := block.TxLoc()
	if err != nil {
		return err
	}

	// Get the internal block ID associated with the block.
	blockID, err := dbFetchBlockIDByHash(dbTx, block.Hash())
	if err != nil {
		return err
	}

	// Build all of the address to transaction mappings in a local map.
	addrsToTxns := make(writeIndexData)
	idx.indexBlock(addrsToTxns, block, prevScripts, isTreasuryEnabled)

	// Add all of the index entries for each address.
	stakeIdxsStart := len(txLocs)
	addrIdxBucket := dbTx.Metadata().Bucket(addrIndexKey)
	for addrKey, txIdxs := range addrsToTxns {
		for _, txIdx := range txIdxs {
			// Adjust the block index and slice of transaction locations to use
			// based on the regular or stake tree.
			txLocations := txLocs
			blockIndex := txIdx
			if txIdx >= stakeIdxsStart {
				txLocations = stakeTxLocs
				blockIndex -= stakeIdxsStart
			}

			err := dbPutAddrIndexEntry(addrIdxBucket, addrKey, blockID,
				txLocations[blockIndex], uint32(blockIndex))
			if err != nil {
				return err
			}
		}
	}

	// Update the current index tip.
	return dbPutIndexerTip(dbTx, idx.Key(), block.Hash(), int32(block.Height()))
}

// disconnectBlock removes the mappings for addresses associated with
// transactions in the provided block.
func (idx *AddrIndex) disconnectBlock(dbTx database.Tx, block, parent *dcrutil.Block, prevScripts PrevScripter, isTreasuryEnabled bool) error {
	// NOTE: The fact that the block can disapprove the regular tree of the
	// previous block is ignored for this index because even though the
	// disapproved transactions no longer apply spend semantics, they still
	// exist within the block and thus have to be processed before the next
	// block disapproves them.

	// Build all of the address to transaction mappings in a local map.
	addrsToTxns := make(writeIndexData)
	idx.indexBlock(addrsToTxns, block, prevScripts, isTreasuryEnabled)

	// Remove all of the index entries for each address.
	bucket := dbTx.Metadata().Bucket(addrIndexKey)
	for addrKey, txIdxs := range addrsToTxns {
		err := dbRemoveAddrIndexEntries(bucket, addrKey, len(txIdxs))
		if err != nil {
			return err
		}
	}

	// Update the current index tip.
	return dbPutIndexerTip(dbTx, idx.Key(), &block.MsgBlock().Header.PrevBlock,
		int32(block.Height()-1))
}

// EntriesForAddress returns a slice of details which identify each transaction,
// including a block region, that involves the passed address according to the
// specified number to skip, number requested, and whether or not the results
// should be reversed.  It also returns the number actually skipped since it
// could be less in the case where there are not enough entries.
//
// NOTE: These results only include transactions confirmed in blocks.  See the
// UnconfirmedTxnsForAddress method for obtaining unconfirmed transactions
// that involve a given address.
//
// This function is safe for concurrent access.
func (idx *AddrIndex) EntriesForAddress(dbTx database.Tx, addr stdaddr.Address, numToSkip, numRequested uint32, reverse bool) ([]TxIndexEntry, uint32, error) {
	addrKey, err := addrToKey(addr)
	if err != nil {
		return nil, 0, err
	}

	var entries []TxIndexEntry
	var skipped uint32
	err = idx.db.View(func(dbTx database.Tx) error {
		// Create closure to lookup the block hash given the ID using
		// the database transaction.
		fetchBlockHash := func(id []byte) (*chainhash.Hash, error) {
			// Deserialize and populate the result.
			return dbFetchBlockHashBySerializedID(dbTx, id)
		}

		var err error
		addrIdxBucket := dbTx.Metadata().Bucket(addrIndexKey)
		entries, skipped, err = dbFetchAddrIndexEntries(addrIdxBucket,
			addrKey, numToSkip, numRequested, reverse,
			fetchBlockHash)
		return err
	})

	return entries, skipped, err
}

// indexUnconfirmedAddresses modifies the unconfirmed (memory-only) address
// index to include mappings for the addresses encoded by the passed public key
// script to the transaction.
//
// This function is safe for concurrent access.
func (idx *AddrIndex) indexUnconfirmedAddresses(scriptVersion uint16, pkScript []byte, tx *dcrutil.Tx, isSStx bool, isTreasuryEnabled bool) {
	// The error is ignored here since the only reason it can fail is if the
	// script fails to parse and it was already validated before being
	// admitted to the mempool.
	class, addrs, _, _ := txscript.ExtractPkScriptAddrs(scriptVersion, pkScript,
		idx.chainParams, isTreasuryEnabled)

	if isSStx && class == txscript.NullDataTy {
		addr, err := stake.AddrFromSStxPkScrCommitment(pkScript, idx.chainParams)
		if err != nil {
			// Fail if this fails to decode. It should.
			return
		}

		addrs = append(addrs, addr)
	}

	for _, addr := range addrs {
		// Ignore unsupported address types.
		addrKey, err := addrToKey(addr)
		if err != nil {
			continue
		}

		// Add a mapping from the address to the transaction.
		idx.unconfirmedLock.Lock()
		addrIndexEntry := idx.txnsByAddr[addrKey]
		if addrIndexEntry == nil {
			addrIndexEntry = make(map[chainhash.Hash]*dcrutil.Tx)
			idx.txnsByAddr[addrKey] = addrIndexEntry
		}
		addrIndexEntry[*tx.Hash()] = tx

		// Add a mapping from the transaction to the address.
		addrsByTxEntry := idx.addrsByTx[*tx.Hash()]
		if addrsByTxEntry == nil {
			addrsByTxEntry = make(map[[addrKeySize]byte]struct{})
			idx.addrsByTx[*tx.Hash()] = addrsByTxEntry
		}
		addrsByTxEntry[addrKey] = struct{}{}
		idx.unconfirmedLock.Unlock()
	}
}

// AddUnconfirmedTx adds all addresses related to the transaction to the
// unconfirmed (memory-only) address index.
//
// NOTE: This transaction MUST have already been validated by the memory pool
// before calling this function with it and have all of the inputs available via
// the provided previous scripter interface.  Failure to do so could result in
// some or all addresses not being indexed.
//
// This function is safe for concurrent access.
func (idx *AddrIndex) AddUnconfirmedTx(tx *dcrutil.Tx, prevScripts PrevScripter, isTreasuryEnabled bool) {
	// Index addresses of all referenced previous transaction outputs.
	//
	// The existence checks are elided since this is only called after the
	// transaction has already been validated and thus all inputs are
	// already known to exist.
	msgTx := tx.MsgTx()
	isSSGen := stake.IsSSGen(msgTx, isTreasuryEnabled)
	for i, txIn := range msgTx.TxIn {
		// Skip stakebase.
		if i == 0 && isSSGen {
			continue
		}

		version, pkScript, ok := prevScripts.PrevScript(&txIn.PreviousOutPoint)
		if !ok {
			// Ignore missing entries.  This should never happen in practice
			// since the function comments specifically call out all inputs must
			// be available.
			continue
		}
		idx.indexUnconfirmedAddresses(version, pkScript, tx, false,
			isTreasuryEnabled)
	}

	// Index addresses of all created outputs.
	isSStx := stake.IsSStx(msgTx)
	for _, txOut := range msgTx.TxOut {
		idx.indexUnconfirmedAddresses(txOut.Version, txOut.PkScript, tx,
			isSStx, isTreasuryEnabled)
	}
}

// RemoveUnconfirmedTx removes the passed transaction from the unconfirmed
// (memory-only) address index.
//
// This function is safe for concurrent access.
func (idx *AddrIndex) RemoveUnconfirmedTx(hash *chainhash.Hash) {
	idx.unconfirmedLock.Lock()
	defer idx.unconfirmedLock.Unlock()

	// Remove all address references to the transaction from the address
	// index and remove the entry for the address altogether if it no longer
	// references any transactions.
	for addrKey := range idx.addrsByTx[*hash] {
		delete(idx.txnsByAddr[addrKey], *hash)
		if len(idx.txnsByAddr[addrKey]) == 0 {
			delete(idx.txnsByAddr, addrKey)
		}
	}

	// Remove the entry from the transaction to address lookup map as well.
	delete(idx.addrsByTx, *hash)
}

// UnconfirmedTxnsForAddress returns all transactions currently in the
// unconfirmed (memory-only) address index that involve the passed address.
// Unsupported address types are ignored and will result in no results.
//
// This function is safe for concurrent access.
func (idx *AddrIndex) UnconfirmedTxnsForAddress(addr stdaddr.Address) []*dcrutil.Tx {
	// Ignore unsupported address types.
	addrKey, err := addrToKey(addr)
	if err != nil {
		return nil
	}

	// Protect concurrent access.
	idx.unconfirmedLock.RLock()
	defer idx.unconfirmedLock.RUnlock()

	// Return a new slice with the results if there are any.  This ensures
	// safe concurrency.
	if txns, exists := idx.txnsByAddr[addrKey]; exists {
		addressTxns := make([]*dcrutil.Tx, 0, len(txns))
		for _, tx := range txns {
			addressTxns = append(addressTxns, tx)
		}
		return addressTxns
	}

	return nil
}

// NewAddrIndex returns a new instance of an indexer that is used to create a
// mapping of all addresses in the blockchain to the respective transactions
// that involve them.
func NewAddrIndex(subscriber *IndexSubscriber, db database.DB, chain ChainQueryer) (*AddrIndex, error) {
	idx := &AddrIndex{
		db:          db,
		chain:       chain,
		chainParams: chain.ChainParams(),
		subscribers: make(map[chan bool]struct{}),
		txnsByAddr:  make(map[[addrKeySize]byte]map[chainhash.Hash]*dcrutil.Tx),
		addrsByTx:   make(map[chainhash.Hash]map[[addrKeySize]byte]struct{}),
		cancel:      subscriber.cancel,
	}

	sc, err := chain.FetchSpendConsumer(idx.Name())
	if err != nil {
		return nil, err
	}

	consumer, ok := sc.(*SpendConsumer)
	if !ok {
		return nil, errors.New("consumer not of type SpendConsumer")
	}

	idx.consumer = consumer

	// The address index is an optional index. It depends on the
	// transaction index and as a result synchronously updates with it.
	sub, err := subscriber.Subscribe(idx, txIndexName)
	if err != nil {
		return nil, err
	}

	idx.sub = sub

	err = idx.Init(subscriber.ctx, idx.chain.ChainParams())
	if err != nil {
		return nil, err
	}

	return idx, nil
}

// DropAddrIndex drops the address index from the provided database if it
// exists.
func DropAddrIndex(ctx context.Context, db database.DB) error {
	return dropFlatIndex(ctx, db, addrIndexKey, addrIndexName)
}

// DropIndex drops the address index from the provided database if it exists.
func (*AddrIndex) DropIndex(ctx context.Context, db database.DB) error {
	return DropAddrIndex(ctx, db)
}

// ProcessNotification indexes the provided notification based on its
// notification type.
//
// This is part of the Indexer interface.
func (idx *AddrIndex) ProcessNotification(dbTx database.Tx, ntfn *IndexNtfn) error {
	switch ntfn.NtfnType {
	case ConnectNtfn:
		err := idx.connectBlock(dbTx, ntfn.Block, ntfn.Parent,
			ntfn.PrevScripts, ntfn.IsTreasuryEnabled)
		if err != nil {
			return fmt.Errorf("%s: unable to connect block: %v", idx.Name(), err)
		}

		idx.consumer.UpdateTip(ntfn.Block.Hash())

	case DisconnectNtfn:
		err := idx.disconnectBlock(dbTx, ntfn.Block, ntfn.Parent,
			ntfn.PrevScripts, ntfn.IsTreasuryEnabled)
		if err != nil {
			log.Errorf("%s: unable to disconnect block: %v", idx.Name(), err)
		}

		idx.consumer.UpdateTip(ntfn.Parent.Hash())

	default:
		return fmt.Errorf("%s: unknown notification type provided: %d",
			idx.Name(), ntfn.NtfnType)
	}

	return nil
}
