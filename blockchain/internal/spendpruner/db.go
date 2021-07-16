// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package spendpruner

import (
	"bytes"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/database/v2"
)

const (
	// depsSeparator is the character used in separating
	// spend journal consumer dependencies when serializing.
	depsSeparator = ','
)

var (
	// spendConsumerDepsBucketName is the name of the bucket used in
	// storing spend journal consumer dependencies.
	spendConsumerDepsBucketName = []byte("spendconsumerdeps")
)

// initConsumerDepsBucket creates the spend consumer dependencies bucket
// if it does not exist.
func initConsumerDepsBucket(db database.DB) error {
	// Create the spend consumer dependencies bucket if it does not exist yet.
	return db.Update(func(dbTx database.Tx) error {
		meta := dbTx.Metadata()
		_, err := meta.CreateBucketIfNotExists(spendConsumerDepsBucketName)
		return err
	})
}

// serializeSpendConsumerDeps returns serialized bytes of
// the provided spend journal consumer dependencies.
func serializeSpendConsumerDeps(deps []string) []byte {
	buf := new(bytes.Buffer)
	for idx := 0; idx < len(deps); idx++ {
		buf.WriteString(deps[idx])
		if idx < len(deps)-1 {
			buf.WriteByte(depsSeparator)
		}
	}

	return buf.Bytes()
}

// deserializeSpendConsumerDeps returns deserialized spend consumer
// dependencies from the provided serialized bytes.
func deserializeSpendConsumerDeps(serializedBytes []byte) []string {
	depBytes := bytes.Split(serializedBytes, []byte{depsSeparator})
	deps := make([]string, len(depBytes))
	for idx := 0; idx < len(depBytes); idx++ {
		deps[idx] = string(depBytes[idx])
	}

	return deps
}

// dbUpdateSpendConsumerDeps uses an existing database transaction
// to update the spend consumer dependency entry for the provided block hash.
func dbUpdateSpendConsumerDeps(dbTx database.Tx, blockHash chainhash.Hash, consumerDeps []string) error {
	depsBucket := dbTx.Metadata().Bucket(spendConsumerDepsBucketName)

	// Remove the dependency entry if there are no spend consumer dependencies
	// left for the block hash.
	if len(consumerDeps) == 0 {
		return depsBucket.Delete(blockHash[:])
	}

	// Update the dependency entry.
	serialized := serializeSpendConsumerDeps(consumerDeps)
	return depsBucket.Put(blockHash[:], serialized)
}

// dbFetchSpendConsumerDeps uses an existing database transaction
// to fetch all spend consumer dependency entries in the database.
func dbFetchSpendConsumerDeps(dbTx database.Tx) (map[chainhash.Hash][]string, error) {
	depsBucket := dbTx.Metadata().Bucket(spendConsumerDepsBucketName)
	consumerDeps := make(map[chainhash.Hash][]string)
	cursor := depsBucket.Cursor()
	for ok := cursor.First(); ok; ok = cursor.Next() {
		hash, err := chainhash.NewHash(cursor.Key())
		if err != nil {
			return nil, err
		}

		deps := deserializeSpendConsumerDeps(cursor.Value())
		consumerDeps[*hash] = deps
	}

	return consumerDeps, nil
}
