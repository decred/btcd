// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"fmt"
	"time"

	"github.com/decred/dcrd/blockchain/standalone/v2"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/database/v2"
	"github.com/decred/dcrd/wire"
)

const (
	// currentUtxoDatabaseVersion indicates the current UTXO database version.
	currentUtxoDatabaseVersion = 1

	// currentUtxoSetVersion indicates the current UTXO set database version.
	currentUtxoSetVersion = 3
)

var (
	// utxoDbInfoBucketName is the name of the database bucket used to house
	// global versioning and date information for the UTXO database.
	utxoDbInfoBucketName = []byte("dbinfo")

	// utxoDbInfoVersionKeyName is the name of the database key used to house the
	// database version.  It is itself under the utxoDbInfoBucketName bucket.
	utxoDbInfoVersionKeyName = []byte("version")

	// utxoDbInfoCompressionVerKeyName is the name of the database key used to
	// house the database compression version.  It is itself under the
	// utxoDbInfoBucketName bucket.
	utxoDbInfoCompressionVerKeyName = []byte("compver")

	// utxoDbInfoUtxoVerKeyName is the name of the database key used to house the
	// database UTXO set version.  It is itself under the utxoDbInfoBucketName
	// bucket.
	utxoDbInfoUtxoVerKeyName = []byte("utxover")

	// utxoDbInfoCreatedKeyName is the name of the database key used to house
	// the date the database was created.  It is itself under the
	// utxoDbInfoBucketName bucket.
	utxoDbInfoCreatedKeyName = []byte("created")

	// utxoSetBucketName is the name of the db bucket used to house the unspent
	// transaction output set.
	utxoSetBucketName = []byte("utxosetv3")

	// utxoSetStateKeyName is the name of the database key used to house the
	// state of the unspent transaction output set.
	utxoSetStateKeyName = []byte("utxosetstate")
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

	// InitInfo loads (or creates if necessary) the UTXO backend info.
	InitInfo(blockDBVersion uint32) error

	// PutInfo sets the versioning and creation information for the UTXO backend.
	PutInfo(info *UtxoBackendInfo) error

	// PutUtxos atomically updates the UTXO set with the entries from the provided
	// map along with the current state.
	PutUtxos(utxos map[wire.OutPoint]*UtxoEntry, state *UtxoSetState) error
}

// LevelDbUtxoBackend implements the UtxoBackend interface using an underlying
// leveldb database instance.
type LevelDbUtxoBackend struct {
	// db is the database that contains the UTXO set.  It is set when the instance
	// is created and is not changed afterward.
	db database.DB
}

// Ensure LevelDbUtxoBackend implements the UtxoBackend interface.
var _ UtxoBackend = (*LevelDbUtxoBackend)(nil)

// NewLevelDbUtxoBackend returns a new LevelDbUtxoBackend instance using the
// provided database.
func NewLevelDbUtxoBackend(db database.DB) *LevelDbUtxoBackend {
	return &LevelDbUtxoBackend{
		db: db,
	}
}

// dbFetchUtxoEntry uses an existing database transaction to fetch the specified
// transaction output from the utxo set.
//
// When there is no entry for the provided output, nil will be returned for both
// the entry and the error.
func (l *LevelDbUtxoBackend) dbFetchUtxoEntry(dbTx database.Tx,
	outpoint wire.OutPoint) (*UtxoEntry, error) {

	// Fetch the unspent transaction output information for the passed transaction
	// output.  Return now when there is no entry.
	key := outpointKey(outpoint)
	utxoBucket := dbTx.Metadata().Bucket(utxoSetBucketName)
	serializedUtxo := utxoBucket.Get(*key)
	recycleOutpointKey(key)
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
			str := fmt.Sprintf("corrupt utxo entry for %v: %v", outpoint, err)
			return nil, makeDbErr(database.ErrCorruption, str)
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
	var entry *UtxoEntry
	err := l.db.View(func(dbTx database.Tx) error {
		var err error
		entry, err = l.dbFetchUtxoEntry(dbTx, outpoint)
		return err
	})
	if err != nil {
		return nil, err
	}

	return entry, nil
}

// FetchState returns the current state of the UTXO set.
func (l *LevelDbUtxoBackend) FetchState() (*UtxoSetState, error) {
	// Fetch the utxo set state from the database.
	var serialized []byte
	err := l.db.View(func(dbTx database.Tx) error {
		// Fetch the serialized utxo set state from the database.
		serialized = dbTx.Metadata().Get(utxoSetStateKeyName)
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Return nil if the utxo set state does not exist in the database.  This
	// should only be the case when starting from a fresh database or a database
	// that has not been run with the utxo cache yet.
	if serialized == nil {
		return nil, nil
	}

	// Deserialize the utxo set state and return it.
	return deserializeUtxoSetState(serialized)
}

// dbFetchUxtoStats fetches statistics on the current unspent transaction output
// set.
func (l *LevelDbUtxoBackend) dbFetchUtxoStats(dbTx database.Tx) (*UtxoStats, error) {
	utxoBucket := dbTx.Metadata().Bucket(utxoSetBucketName)

	var stats UtxoStats
	transactions := make(map[chainhash.Hash]struct{})
	leaves := make([]chainhash.Hash, 0)
	cursor := utxoBucket.Cursor()

	for ok := cursor.First(); ok; ok = cursor.Next() {
		key := cursor.Key()
		var outpoint wire.OutPoint
		err := decodeOutpointKey(key, &outpoint)
		if err != nil {
			return nil, err
		}

		serializedUtxo := cursor.Value()
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
				str := fmt.Sprintf("corrupt utxo entry for %v: %v", outpoint, err)
				return nil, makeDbErr(database.ErrCorruption, str)
			}

			return nil, err
		}

		stats.Total += entry.amount
	}

	stats.SerializedHash = standalone.CalcMerkleRootInPlace(leaves)
	stats.Transactions = int64(len(transactions))

	return &stats, nil
}

// FetchStats returns statistics on the current UTXO set.
func (l *LevelDbUtxoBackend) FetchStats() (*UtxoStats, error) {
	var stats *UtxoStats
	err := l.db.View(func(dbTx database.Tx) error {
		var err error
		stats, err = l.dbFetchUtxoStats(dbTx)
		return err
	})
	if err != nil {
		return nil, err
	}

	return stats, nil
}

// dbPutUtxoBackendInfo uses an existing database transaction to store the
// backend information.
func (l *LevelDbUtxoBackend) dbPutUtxoBackendInfo(dbTx database.Tx,
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
	meta := dbTx.Metadata()
	bucket := meta.Bucket(utxoDbInfoBucketName)
	err := bucket.Put(utxoDbInfoVersionKeyName, uint32Bytes(info.version))
	if err != nil {
		return err
	}

	// Store the compression version.
	err = bucket.Put(utxoDbInfoCompressionVerKeyName, uint32Bytes(info.compVer))
	if err != nil {
		return err
	}

	// Store the UTXO set version.
	err = bucket.Put(utxoDbInfoUtxoVerKeyName, uint32Bytes(info.utxoVer))
	if err != nil {
		return err
	}

	// Store the database creation date.
	return bucket.Put(utxoDbInfoCreatedKeyName,
		uint64Bytes(uint64(info.created.Unix())))
}

// dbFetchUtxoBackendInfo uses an existing database transaction to fetch the
// backend versioning and creation information.
func (l *LevelDbUtxoBackend) dbFetchUtxoBackendInfo(dbTx database.Tx) *UtxoBackendInfo {
	meta := dbTx.Metadata()
	bucket := meta.Bucket(utxoDbInfoBucketName)

	// Uninitialized state.
	if bucket == nil {
		return nil
	}

	// Load the database version.
	var version uint32
	versionBytes := bucket.Get(utxoDbInfoVersionKeyName)
	if versionBytes != nil {
		version = byteOrder.Uint32(versionBytes)
	}

	// Load the database compression version.
	var compVer uint32
	compVerBytes := bucket.Get(utxoDbInfoCompressionVerKeyName)
	if compVerBytes != nil {
		compVer = byteOrder.Uint32(compVerBytes)
	}

	// Load the database UTXO set version.
	var utxoVer uint32
	utxoVerBytes := bucket.Get(utxoDbInfoUtxoVerKeyName)
	if utxoVerBytes != nil {
		utxoVer = byteOrder.Uint32(utxoVerBytes)
	}

	// Load the database creation date.
	var created time.Time
	createdBytes := bucket.Get(utxoDbInfoCreatedKeyName)
	if createdBytes != nil {
		ts := byteOrder.Uint64(createdBytes)
		created = time.Unix(int64(ts), 0)
	}

	return &UtxoBackendInfo{
		version: version,
		compVer: compVer,
		utxoVer: utxoVer,
		created: created,
	}
}

// createUtxoBackendInfo initializes the UTXO backend info.  It must only be
// called on an uninitialized backend.
func (l *LevelDbUtxoBackend) createUtxoBackendInfo(blockDBVersion uint32) error {
	// Create the initial UTXO database state.
	err := l.db.Update(func(dbTx database.Tx) error {
		meta := dbTx.Metadata()

		// Create the bucket that houses information about the database's creation
		// and version.
		_, err := meta.CreateBucketIfNotExists(utxoDbInfoBucketName)
		if err != nil {
			return err
		}

		// Initialize the UTXO set version.  If the block database version is before
		// version 9, then initialize the UTXO set version based on the block
		// database version since that is what tracked the UTXO set version at that
		// point in time.
		utxoVer := uint32(currentUtxoSetVersion)
		if blockDBVersion >= 7 && blockDBVersion < 9 {
			utxoVer = 2
		} else if blockDBVersion < 7 {
			utxoVer = 1
		}

		// Write the creation and version information to the database.
		err = l.dbPutUtxoBackendInfo(dbTx, &UtxoBackendInfo{
			version: currentUtxoDatabaseVersion,
			compVer: currentCompressionVersion,
			utxoVer: utxoVer,
			created: time.Now(),
		})
		if err != nil {
			return err
		}

		// Create the bucket that houses the UTXO set.
		_, err = meta.CreateBucketIfNotExists(utxoSetBucketName)
		if err != nil {
			return err
		}

		return nil
	})
	return err
}

// FetchInfo returns versioning and creation information for the backend.
func (l *LevelDbUtxoBackend) FetchInfo() (*UtxoBackendInfo, error) {
	var backendInfo *UtxoBackendInfo
	err := l.db.View(func(dbTx database.Tx) error {
		backendInfo = l.dbFetchUtxoBackendInfo(dbTx)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return backendInfo, nil
}

// InitInfo loads (or creates if necessary) the UTXO backend info.
func (l *LevelDbUtxoBackend) InitInfo(blockDBVersion uint32) error {
	// Determine the state of the database.
	var isStateInitialized bool
	err := l.db.View(func(dbTx database.Tx) error {
		// Fetch the backend versioning information.
		dbInfo := l.dbFetchUtxoBackendInfo(dbTx)

		// The database bucket for the versioning information is missing.
		if dbInfo == nil {
			return nil
		}

		// Don't allow downgrades of the UTXO database.
		if dbInfo.version > currentUtxoDatabaseVersion {
			return fmt.Errorf("the current UTXO database is no longer compatible "+
				"with this version of the software (%d > %d)", dbInfo.version,
				currentUtxoDatabaseVersion)
		}

		// Don't allow downgrades of the database compression version.
		if dbInfo.compVer > currentCompressionVersion {
			return fmt.Errorf("the current database compression version is no "+
				"longer compatible with this version of the software (%d > %d)",
				dbInfo.compVer, currentCompressionVersion)
		}

		isStateInitialized = true

		return nil
	})
	if err != nil {
		return err
	}

	// Initialize the backend if it has not already been done.
	if !isStateInitialized {
		if err := l.createUtxoBackendInfo(blockDBVersion); err != nil {
			return err
		}
	}

	return nil
}

// PutInfo sets the versioning and creation information for the backend.
func (l *LevelDbUtxoBackend) PutInfo(info *UtxoBackendInfo) error {
	return l.db.Update(func(dbTx database.Tx) error {
		return l.dbPutUtxoBackendInfo(dbTx, info)
	})
}

// dbPutUtxoEntry uses an existing database transaction to update the utxo
// entry for the given outpoint based on the provided utxo entry state.  In
// particular, the entry is only written to the database if it is marked as
// modified, and if the entry is marked as spent it is removed from the
// database.
func (l *LevelDbUtxoBackend) dbPutUtxoEntry(dbTx database.Tx,
	outpoint wire.OutPoint, entry *UtxoEntry) error {

	// No need to update the database if the entry was not modified.
	if entry == nil || !entry.isModified() {
		return nil
	}

	// Remove the utxo entry if it is spent.
	utxoBucket := dbTx.Metadata().Bucket(utxoSetBucketName)
	if entry.IsSpent() {
		key := outpointKey(outpoint)
		err := utxoBucket.Delete(*key)
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
	err = utxoBucket.Put(*key, serialized)
	// NOTE: The key is intentionally not recycled here since the database
	// interface contract prohibits modifications.  It will be garbage collected
	// normally when the database is done with it.
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
	// database transaction as the utxo set itself so that it is always in sync.
	err := l.db.Update(func(dbTx database.Tx) error {
		for outpoint, entry := range utxos {
			// Write the entry to the database.
			err := l.dbPutUtxoEntry(dbTx, outpoint, entry)
			if err != nil {
				return err
			}
		}

		// Update the UTXO set state in the database.
		return dbTx.Metadata().Put(utxoSetStateKeyName,
			serializeUtxoSetState(state))
	})
	if err != nil {
		return err
	}

	// Flush the UTXO database to disk.  This is necessary in the case that the
	// UTXO set state was just initialized so that if the block database is
	// flushed, and then an unclean shutdown occurs, the UTXO cache will know
	// where to start from when recovering on startup.
	return l.db.Flush()
}
