// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/decred/dcrd/blockchain/standalone/v2"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/wire"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/filter"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"
)

const (
	// currentUtxoDatabaseVersion indicates the current UTXO database version.
	currentUtxoDatabaseVersion = 2

	// utxoDbDir is the directory for the UTXO database.
	utxoDbDir = "utxodb"

	// utxoLdbName is the name of UTXO leveldb database.  It is itself within the
	// utxoDbDir directory.
	utxoLdbName = "metadata"
)

// -----------------------------------------------------------------------------
// utxoKeySet represents a top level key set in the UTXO backend.  All keys in
// the UTXO backend start with a serialized prefix consisting of the key set
// and version of that key set as follows:
//
//   <key set><version>
//
//   Key        Value    Size      Description
//   key set    uint8    1 byte    The key set identifier, as defined below
//   version    uint8    1 byte    The version of the key set
//
// -----------------------------------------------------------------------------
type utxoKeySet uint8

// These constants define the available UTXO backend key sets.
const (
	utxoKeySetDbInfo    utxoKeySet = iota + 1 // 1
	utxoKeySetUtxoState                       // 2
	utxoKeySetUtxoSet                         // 3
)

// utxoKeySetVersions defines the current version for each UTXO backend key
// set.
var utxoKeySetVersions = map[utxoKeySet]uint8{
	utxoKeySetDbInfo:    1,
	utxoKeySetUtxoState: 1,
	utxoKeySetUtxoSet:   3,
}

// These variables define the serialized prefix for each key set and associated
// version.
var (
	// utxoPrefixDbInfo is the prefix for all keys in the database info
	// key set.
	utxoPrefixDbInfo = []byte{byte(utxoKeySetDbInfo),
		utxoKeySetVersions[utxoKeySetDbInfo]}

	// utxoPrefixUtxoState is the prefix for all keys in the UTXO state key set.
	utxoPrefixUtxoState = []byte{byte(utxoKeySetUtxoState),
		utxoKeySetVersions[utxoKeySetUtxoState]}

	// utxoPrefixUtxoSet is the prefix for all keys in the UTXO set key set.
	utxoPrefixUtxoSet = []byte{byte(utxoKeySetUtxoSet),
		utxoKeySetVersions[utxoKeySetUtxoSet]}
)

// prefixedKey returns a new byte slice that consists of the provided prefix
// appended with the provided key.
func prefixedKey(prefix []byte, key []byte) []byte {
	lenPrefix := len(prefix)
	prefixedKey := make([]byte, lenPrefix+len(key))
	_ = copy(prefixedKey, prefix)
	_ = copy(prefixedKey[lenPrefix:], key)
	return prefixedKey
}

// These variables define keys that are part of the database info key set.
var (
	// utxoDbInfoVersionKeyName is the name of the database key used to house the
	// database version.  It is itself under utxoPrefixDbInfo.
	utxoDbInfoVersionKeyName = []byte("version")

	// utxoDbInfoCompVerKeyName is the name of the database key used to house the
	// database compression version.  It is itself under utxoPrefixDbInfo.
	utxoDbInfoCompVerKeyName = []byte("compver")

	// utxoDbInfoUtxoVerKeyName is the name of the database key used to house the
	// database UTXO set version.  It is itself under utxoPrefixDbInfo.
	utxoDbInfoUtxoVerKeyName = []byte("utxover")

	// utxoDbInfoCreatedKeyName is the name of the database key used to house the
	// date the database was created.  It is itself under utxoPrefixDbInfo.
	utxoDbInfoCreatedKeyName = []byte("created")

	// utxoDbInfoVersionKey is the database key used to house the database
	// version.
	utxoDbInfoVersionKey = prefixedKey(utxoPrefixDbInfo, utxoDbInfoVersionKeyName)

	// utxoDbInfoCompVerKey is the database key used to house the database
	// compression version.
	utxoDbInfoCompVerKey = prefixedKey(utxoPrefixDbInfo, utxoDbInfoCompVerKeyName)

	// utxoDbInfoUtxoVerKey is the database key used to house the database UTXO
	// set version.
	utxoDbInfoUtxoVerKey = prefixedKey(utxoPrefixDbInfo, utxoDbInfoUtxoVerKeyName)

	// utxoDbInfoCreatedKey is the database key used to house the date the
	// database was created.
	utxoDbInfoCreatedKey = prefixedKey(utxoPrefixDbInfo, utxoDbInfoCreatedKeyName)
)

// These variables define keys that are part of the UTXO state key set.
var (
	// utxoSetStateKeyName is the name of the database key used to house the state
	// of the unspent transaction output set.  It is itself under
	// utxoPrefixUtxoState.
	utxoSetStateKeyName = []byte("utxosetstate")

	// utxoSetStateKey is the database key used to house the state of the unspent
	// transaction output set.
	utxoSetStateKey = prefixedKey(utxoPrefixUtxoState, utxoSetStateKeyName)
)

// -----------------------------------------------------------------------------
// The UTXO backend information contains information about the version and date
// of the UTXO backend.
//
// It consists of a separate key for each individual piece of information:
//
//  Key        Value    Size      Description
//  version    uint32   4 bytes   The version of the backend
//  compver    uint32   4 bytes   The script compression version of the backend
//  utxover    uint32   4 bytes   The UTXO set version of the backend
//  created    uint64   8 bytes   The date of the creation of the backend
// -----------------------------------------------------------------------------

// UtxoBackendInfo is the structure that holds the versioning and date
// information for the UTXO backend.
type UtxoBackendInfo struct {
	version uint32
	compVer uint32
	utxoVer uint32
	created time.Time
}

// UtxoStats represents unspent output statistics on the current utxo set.
type UtxoStats struct {
	Utxos          int64
	Transactions   int64
	Size           int64
	Total          int64
	SerializedHash chainhash.Hash
}

// UtxoBackend represents a persistent storage layer for the UTXO set.
//
// The interface contract requires that all of these methods are safe for
// concurrent access.
type UtxoBackend interface {
	// FetchEntry returns the specified transaction output from the UTXO set.
	//
	// When there is no entry for the provided output, nil will be returned for
	// both the entry and the error.
	FetchEntry(outpoint wire.OutPoint) (*UtxoEntry, error)

	// FetchInfo returns versioning and creation information for the UTXO backend.
	FetchInfo() (*UtxoBackendInfo, error)

	// FetchState returns the current state of the UTXO set.
	FetchState() (*UtxoSetState, error)

	// FetchStats returns statistics on the current UTXO set.
	FetchStats() (*UtxoStats, error)

	// Get returns the value for the given key.  It returns nil if the key does
	// not exist.  An empty slice is returned for keys that exist but have no
	// value assigned.
	//
	// The returned slice is safe to modify.  Additionally, it is safe to modify
	// the slice passed as an argument after Get returns.
	Get(key []byte) ([]byte, error)

	// InitInfo loads (or creates if necessary) the UTXO backend info.
	InitInfo(blockDBVersion uint32) error

	// NewIterator returns an iterator over the key/value pairs in the UTXO
	// backend.  The returned iterator is NOT safe for concurrent use, but it is
	// safe to use multiple iterators concurrently, with each in a dedicated
	// goroutine.
	//
	// The prefix parameter allows for slicing the iterator to only contain keys
	// with the given prefix.  A nil prefix is treated as a key BEFORE all keys.
	//
	// NOTE: The contents of any slice returned by the iterator should NOT be
	// modified unless noted otherwise.
	//
	// The iterator must be released after use, by calling Release method.
	NewIterator(prefix []byte) UtxoBackendIterator

	// PutInfo sets the versioning and creation information for the UTXO backend.
	PutInfo(info *UtxoBackendInfo) error

	// PutUtxos atomically updates the UTXO set with the entries from the provided
	// map along with the current state.
	PutUtxos(utxos map[wire.OutPoint]*UtxoEntry, state *UtxoSetState) error

	// Update invokes the passed function in the context of a UTXO Backend
	// transaction.  Any errors returned from the user-supplied function will
	// cause the transaction to be rolled back and are returned from this
	// function.  Otherwise, the transaction is committed when the user-supplied
	// function returns a nil error.
	Update(fn func(tx UtxoBackendTx) error) error

	// Upgrade upgrades the UTXO backend by applying all possible upgrades
	// iteratively as needed.
	Upgrade(ctx context.Context, b *BlockChain) error
}

// LevelDbUtxoBackend implements the UtxoBackend interface using an underlying
// leveldb database instance.
type LevelDbUtxoBackend struct {
	// db is the database that contains the UTXO set.  It is set when the instance
	// is created and is not changed afterward.
	db *leveldb.DB
}

// Ensure LevelDbUtxoBackend implements the UtxoBackend interface.
var _ UtxoBackend = (*LevelDbUtxoBackend)(nil)

// removeDB removes the database at the provided path.  The fi parameter MUST
// agree with the provided path.
func removeDB(dbPath string, fi os.FileInfo) error {
	if fi.IsDir() {
		return os.RemoveAll(dbPath)
	}

	return os.Remove(dbPath)
}

// removeRegressionDB removes the existing regression test database if running
// in regression test mode and it already exists.
func removeRegressionDB(net wire.CurrencyNet, dbPath string) error {
	// Don't do anything if not in regression test mode.
	if net != wire.RegNet {
		return nil
	}

	// Remove the old regression test database if it already exists.
	fi, err := os.Stat(dbPath)
	if err == nil {
		log.Infof("Removing regression test UTXO database from '%s'", dbPath)
		return removeDB(dbPath, fi)
	}

	return nil
}

// LoadUtxoDB loads (or creates when needed) the UTXO database and returns a
// handle to it.  It also contains additional logic such as ensuring the
// regression test database is clean when in regression test mode.
func LoadUtxoDB(params *chaincfg.Params, dataDir string) (*leveldb.DB, error) {
	// Set the database path based on the data directory, UTXO database directory,
	// and database name.
	dbPath := filepath.Join(dataDir, utxoDbDir, utxoLdbName)

	// The regression test is special in that it needs a clean database for each
	// run, so remove it now if it already exists.
	removeRegressionDB(params.Net, dbPath)

	// Create the data dir if it does not exist.
	err := os.MkdirAll(dataDir, 0700)
	if err != nil {
		return nil, fmt.Errorf("failed to create data directory for UTXO "+
			"database: %v", err)
	}

	// Open the database (will create it if needed).
	log.Infof("Loading UTXO database from '%s'", dbPath)
	opts := opt.Options{
		Strict:      opt.DefaultStrict,
		Compression: opt.NoCompression,
		Filter:      filter.NewBloomFilter(10),
	}
	db, err := leveldb.OpenFile(dbPath, &opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open UTXO database: %v", err)
	}

	log.Info("UTXO database loaded")

	return db, nil
}

// NewLevelDbUtxoBackend returns a new LevelDbUtxoBackend instance using the
// provided database.
func NewLevelDbUtxoBackend(db *leveldb.DB) *LevelDbUtxoBackend {
	return &LevelDbUtxoBackend{
		db: db,
	}
}

// Get gets the value for the given key from the leveldb database.  It
// returns nil for both the value and the error if the database does not
// contain the key.
//
// It is safe to modify the contents of the returned slice, and it is safe to
// modify the contents of the argument after Get returns.
func (l *LevelDbUtxoBackend) Get(key []byte) ([]byte, error) {
	serialized, err := l.db.Get(key, nil)
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get key %x from leveldb: %v", key, err)
	}
	return serialized, nil
}

// Update invokes the passed function in the context of a UTXO Backend
// transaction.  Any errors returned from the user-supplied function will cause
// the transaction to be rolled back and are returned from this function.
// Otherwise, the transaction is committed when the user-supplied function
// returns a nil error.
func (l *LevelDbUtxoBackend) Update(fn func(tx UtxoBackendTx) error) error {
	// Start a leveldb transaction.
	//
	// Note: A leveldb.Transaction is used rather than a leveldb.Batch because
	// it uses signficantly less memory when atomically updating a large amount of
	// data.  Due to the UtxoCache only flushing to the UtxoBackend periodically,
	// the UtxoBackend is almost always updating a large amount of data at once,
	// and thus leveldb transactions are used by default over batches.
	ldbTx, err := l.db.OpenTransaction()
	if err != nil {
		return fmt.Errorf("failed to open leveldb transaction: %v", err)
	}

	if err := fn(&levelDbUtxoBackendTx{ldbTx}); err != nil {
		ldbTx.Discard()
		return err
	}

	// Commit the leveldb transaction.
	if err := ldbTx.Commit(); err != nil {
		ldbTx.Discard()
		return fmt.Errorf("failed to commit leveldb transaction: %v", err)
	}
	return nil
}

// NewIterator returns an iterator over the key/value pairs in the UTXO backend.
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
func (l *LevelDbUtxoBackend) NewIterator(prefix []byte) UtxoBackendIterator {
	var slice *util.Range
	if prefix != nil {
		slice = util.BytesPrefix(prefix)
	}
	return l.db.NewIterator(slice, nil)
}

// dbFetchUtxoEntry fetches the specified transaction output from the utxo set.
//
// When there is no entry for the provided output, nil will be returned for both
// the entry and the error.
func (l *LevelDbUtxoBackend) dbFetchUtxoEntry(outpoint wire.OutPoint) (*UtxoEntry, error) {
	// Fetch the unspent transaction output information for the passed transaction
	// output.  Return now when there is no entry.
	key := outpointKey(outpoint)
	serializedUtxo, err := l.Get(*key)
	recycleOutpointKey(key)
	if err != nil {
		return nil, err
	}
	if serializedUtxo == nil {
		return nil, nil
	}

	// A non-nil zero-length entry means there is an entry in the database for a
	// spent transaction output which should never be the case.
	if len(serializedUtxo) == 0 {
		return nil, AssertError(fmt.Sprintf("database contains entry for spent tx "+
			"output %v", outpoint))
	}

	// Deserialize the utxo entry and return it.
	entry, err := deserializeUtxoEntry(serializedUtxo, outpoint.Index)
	if err != nil {
		// Ensure any deserialization errors are returned as database corruption
		// errors.
		if isDeserializeErr(err) {
			return nil, AssertError(fmt.Sprintf("corrupt utxo entry for %v: %v",
				outpoint, err))
		}

		return nil, err
	}

	return entry, nil
}

// FetchEntry returns the specified transaction output from the UTXO set.
//
// When there is no entry for the provided output, nil will be returned for both
// the entry and the error.
func (l *LevelDbUtxoBackend) FetchEntry(outpoint wire.OutPoint) (*UtxoEntry, error) {
	// Fetch the entry from the database.
	//
	// NOTE: Missing entries are not considered an error here and instead
	// will result in nil entries in the view.  This is intentionally done
	// so other code can use the presence of an entry in the view as a way
	// to unnecessarily avoid attempting to reload it from the database.
	return l.dbFetchUtxoEntry(outpoint)
}

// FetchState returns the current state of the UTXO set.
func (l *LevelDbUtxoBackend) FetchState() (*UtxoSetState, error) {
	// Fetch the utxo set state from the database.
	serialized, err := l.Get(utxoSetStateKey)
	if err != nil {
		return nil, err
	}

	// Return nil if the utxo set state does not exist in the database.  This
	// should only be the case when starting from a fresh database or a
	// database that has not been run with the utxo cache yet.
	if serialized == nil {
		return nil, nil
	}

	// Deserialize the utxo set state and return it.
	return deserializeUtxoSetState(serialized)
}

// dbFetchUtxoStats fetches statistics on the current unspent transaction output
// set.
func (l *LevelDbUtxoBackend) dbFetchUtxoStats() (*UtxoStats, error) {
	var stats UtxoStats
	transactions := make(map[chainhash.Hash]struct{})
	leaves := make([]chainhash.Hash, 0)
	iter := l.NewIterator(utxoPrefixUtxoSet)
	defer iter.Release()

	for iter.Next() {
		key := iter.Key()
		var outpoint wire.OutPoint
		err := decodeOutpointKey(key, &outpoint)
		if err != nil {
			return nil, err
		}

		serializedUtxo := iter.Value()
		entrySize := len(serializedUtxo)

		// A non-nil zero-length entry means there is an entry in the database for a
		// spent transaction output which should never be the case.
		if entrySize == 0 {
			return nil, AssertError(fmt.Sprintf("database contains entry for spent "+
				"tx output %v", outpoint))
		}

		stats.Utxos++
		stats.Size += int64(entrySize)
		transactions[outpoint.Hash] = struct{}{}

		leaves = append(leaves, chainhash.HashH(serializedUtxo))

		// Deserialize the utxo entry.
		entry, err := deserializeUtxoEntry(serializedUtxo, outpoint.Index)
		if err != nil {
			// Ensure any deserialization errors are returned as database corruption
			// errors.
			if isDeserializeErr(err) {
				return nil, AssertError(fmt.Sprintf("corrupt utxo entry for %v: %v",
					outpoint, err))
			}

			return nil, err
		}

		stats.Total += entry.amount
	}
	err := iter.Error()
	if err != nil {
		return nil, err
	}

	stats.SerializedHash = standalone.CalcMerkleRootInPlace(leaves)
	stats.Transactions = int64(len(transactions))

	return &stats, nil
}

// FetchStats returns statistics on the current UTXO set.
func (l *LevelDbUtxoBackend) FetchStats() (*UtxoStats, error) {
	return l.dbFetchUtxoStats()
}

// dbPutUtxoBackendInfo uses an existing UTXO backend transaction to store the
// backend information.
func (l *LevelDbUtxoBackend) dbPutUtxoBackendInfo(tx UtxoBackendTx,
	info *UtxoBackendInfo) error {

	// uint32Bytes is a helper function to convert a uint32 to a byte slice
	// using the byte order specified by the database namespace.
	uint32Bytes := func(ui32 uint32) []byte {
		var b [4]byte
		byteOrder.PutUint32(b[:], ui32)
		return b[:]
	}

	// uint64Bytes is a helper function to convert a uint64 to a byte slice
	// using the byte order specified by the database namespace.
	uint64Bytes := func(ui64 uint64) []byte {
		var b [8]byte
		byteOrder.PutUint64(b[:], ui64)
		return b[:]
	}

	// Store the database version.
	err := tx.Put(utxoDbInfoVersionKey, uint32Bytes(info.version))
	if err != nil {
		return err
	}

	// Store the compression version.
	err = tx.Put(utxoDbInfoCompVerKey, uint32Bytes(info.compVer))
	if err != nil {
		return err
	}

	// Store the UTXO set version.
	err = tx.Put(utxoDbInfoUtxoVerKey, uint32Bytes(info.utxoVer))
	if err != nil {
		return err
	}

	// Store the database creation date.
	return tx.Put(utxoDbInfoCreatedKey,
		uint64Bytes(uint64(info.created.Unix())))
}

// dbFetchUtxoBackendInfo fetches the backend versioning and creation
// information.
func (l *LevelDbUtxoBackend) dbFetchUtxoBackendInfo() (*UtxoBackendInfo, error) {
	// Load the database version.
	prefix := utxoPrefixDbInfo
	versionBytes, err := l.Get(utxoDbInfoVersionKey)
	if err != nil {
		return nil, err
	}
	if versionBytes == nil {
		// If the database info was not found, attempt to find it in the legacy
		// bucket.
		dbInfoLegacyBucketName := []byte("dbinfo")
		dbInfoBucketId, err := fetchLegacyBucketId(l.Get, dbInfoLegacyBucketName)
		if err != nil {
			return nil, err
		}
		prefix = dbInfoBucketId
		versionBytes, err = l.Get(prefixedKey(prefix, utxoDbInfoVersionKeyName))
		if err != nil {
			return nil, err
		}
		if versionBytes == nil {
			// Uninitialized state.
			return nil, nil
		}
	}
	version := byteOrder.Uint32(versionBytes)

	// Load the database compression version.
	var compVer uint32
	compVerKey := prefixedKey(prefix, utxoDbInfoCompVerKeyName)
	compVerBytes, err := l.Get(compVerKey)
	if err != nil {
		return nil, err
	}
	if compVerBytes != nil {
		compVer = byteOrder.Uint32(compVerBytes)
	}

	// Load the database UTXO set version.
	var utxoVer uint32
	utxoVerKey := prefixedKey(prefix, utxoDbInfoUtxoVerKeyName)
	utxoVerBytes, err := l.Get(utxoVerKey)
	if err != nil {
		return nil, err
	}
	if utxoVerBytes != nil {
		utxoVer = byteOrder.Uint32(utxoVerBytes)
	}

	// Load the database creation date.
	var created time.Time
	createdKey := prefixedKey(prefix, utxoDbInfoCreatedKeyName)
	createdBytes, err := l.Get(createdKey)
	if err != nil {
		return nil, err
	}
	if createdBytes != nil {
		ts := byteOrder.Uint64(createdBytes)
		created = time.Unix(int64(ts), 0)
	}

	return &UtxoBackendInfo{
		version: version,
		compVer: compVer,
		utxoVer: utxoVer,
		created: created,
	}, nil
}

// createUtxoBackendInfo initializes the UTXO backend info.  It must only be
// called on an uninitialized backend.
func (l *LevelDbUtxoBackend) createUtxoBackendInfo(blockDBVersion uint32) error {
	// Initialize the UTXO set version.  If the block database version is before
	// version 9, then initialize the UTXO set version based on the block
	// database version since that is what tracked the UTXO set version at that
	// point in time.
	utxoVer := uint32(utxoKeySetVersions[utxoKeySetUtxoSet])
	if blockDBVersion >= 7 && blockDBVersion < 9 {
		utxoVer = 2
	} else if blockDBVersion < 7 {
		utxoVer = 1
	}

	// Write the creation and version information to the database.
	return l.Update(func(tx UtxoBackendTx) error {
		return l.dbPutUtxoBackendInfo(tx, &UtxoBackendInfo{
			version: currentUtxoDatabaseVersion,
			compVer: currentCompressionVersion,
			utxoVer: utxoVer,
			created: time.Now(),
		})
	})
}

// FetchInfo returns versioning and creation information for the backend.
func (l *LevelDbUtxoBackend) FetchInfo() (*UtxoBackendInfo, error) {
	return l.dbFetchUtxoBackendInfo()
}

// InitInfo loads (or creates if necessary) the UTXO backend info.
func (l *LevelDbUtxoBackend) InitInfo(blockDBVersion uint32) error {
	// Fetch the backend versioning information.
	dbInfo, err := l.dbFetchUtxoBackendInfo()
	if err != nil {
		return err
	}

	// Don't allow downgrades of the UTXO database.
	if dbInfo != nil && dbInfo.version > currentUtxoDatabaseVersion {
		return fmt.Errorf("the current UTXO database is no longer compatible "+
			"with this version of the software (%d > %d)", dbInfo.version,
			currentUtxoDatabaseVersion)
	}

	// Don't allow downgrades of the database compression version.
	if dbInfo != nil && dbInfo.compVer > currentCompressionVersion {
		return fmt.Errorf("the current database compression version is no "+
			"longer compatible with this version of the software (%d > %d)",
			dbInfo.compVer, currentCompressionVersion)
	}

	// Initialize the backend if it has not already been done.
	if dbInfo == nil {
		if err := l.createUtxoBackendInfo(blockDBVersion); err != nil {
			return err
		}
	}

	return nil
}

// PutInfo sets the versioning and creation information for the backend.
func (l *LevelDbUtxoBackend) PutInfo(info *UtxoBackendInfo) error {
	return l.Update(func(tx UtxoBackendTx) error {
		return l.dbPutUtxoBackendInfo(tx, info)
	})
}

// dbPutUtxoEntry uses an existing UTXO backend transaction to update the utxo
// entry for the given outpoint based on the provided utxo entry state.  In
// particular, the entry is only written to the database if it is marked as
// modified, and if the entry is marked as spent it is removed from the
// database.
func (l *LevelDbUtxoBackend) dbPutUtxoEntry(tx UtxoBackendTx,
	outpoint wire.OutPoint, entry *UtxoEntry) error {

	// No need to update the database if the entry was not modified.
	if entry == nil || !entry.isModified() {
		return nil
	}

	// Remove the utxo entry if it is spent.
	if entry.IsSpent() {
		key := outpointKey(outpoint)
		err := tx.Delete(*key)
		recycleOutpointKey(key)
		if err != nil {
			return err
		}
		return nil
	}

	// Serialize and store the utxo entry.
	serialized, err := serializeUtxoEntry(entry)
	if err != nil {
		return err
	}
	key := outpointKey(outpoint)
	err = tx.Put(*key, serialized)
	recycleOutpointKey(key)
	if err != nil {
		return err
	}

	return nil
}

// PutUtxos atomically updates the UTXO set with the entries from the provided
// map along with the current state.
func (l *LevelDbUtxoBackend) PutUtxos(utxos map[wire.OutPoint]*UtxoEntry,
	state *UtxoSetState) error {

	// Update the database with the provided entries and UTXO set state.
	//
	// It is important that the UTXO set state is always updated in the same
	// UTXO backend transaction as the utxo set itself so that it is always in
	// sync.
	return l.Update(func(tx UtxoBackendTx) error {
		for outpoint, entry := range utxos {
			// Write the entry to the database.
			err := l.dbPutUtxoEntry(tx, outpoint, entry)
			if err != nil {
				return err
			}
		}

		// Update the UTXO set state in the database.
		return tx.Put(utxoSetStateKey, serializeUtxoSetState(state))
	})
}

// Upgrade upgrades the UTXO backend by applying all possible upgrades
// iteratively as needed.
func (l *LevelDbUtxoBackend) Upgrade(ctx context.Context, b *BlockChain) error {
	// Upgrade the UTXO database as needed.
	return upgradeUtxoDb(ctx, b.db, l)
}
