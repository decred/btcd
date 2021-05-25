// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"reflect"
	"testing"
	"time"

	"github.com/decred/dcrd/wire"
)

// createTestUtxoBackend creates a test backend with the utxo set bucket.
func createTestUtxoBackend(t *testing.T) *LevelDbUtxoBackend {
	t.Helper()

	db, teardown, err := createTestUtxoDatabase(t.Name())
	if err != nil {
		t.Fatalf("error creating test database: %v", err)
	}
	t.Cleanup(func() {
		teardown()
	})

	return NewLevelDbUtxoBackend(db)
}

// TestFetchEntryFromBackend validates that fetch entry returns the correct
// entry from the backend under a variety of conditions.
func TestFetchEntryFromBackend(t *testing.T) {
	t.Parallel()

	// Create a test backend.
	backend := createTestUtxoBackend(t)

	// Create test entries to be used throughout the tests.
	outpoint := outpoint299()
	entry := entry299()

	tests := []struct {
		name           string
		backendEntries map[wire.OutPoint][]byte
		outpoint       wire.OutPoint
		wantEntry      *UtxoEntry
		wantErr        bool
	}{{
		name:     "entry is not in the backend",
		outpoint: outpoint,
	}, {
		name: "entry is in the backend",
		backendEntries: map[wire.OutPoint][]byte{
			outpoint: hexToBytes("812b010080fba8a41b0000454017705ab80470d089c7f644e" +
				"39cc9e0fd308e"),
		},
		outpoint:  outpoint,
		wantEntry: entry,
	}, {
		name: "entry is non-nil but has zero length",
		backendEntries: map[wire.OutPoint][]byte{
			outpoint: hexToBytes(""),
		},
		outpoint: outpoint,
		wantErr:  true,
	}, {
		name: "deserialization error",
		backendEntries: map[wire.OutPoint][]byte{
			outpoint: hexToBytes("812b"),
		},
		outpoint: outpoint,
		wantErr:  true,
	}}

	for _, test := range tests {
		// Add entries specified by the test to the test backend.
		err := backend.Update(func(tx UtxoBackendTx) error {
			for outpoint, serialized := range test.backendEntries {
				key := outpointKey(outpoint)
				err := tx.Put(*key, serialized)
				if err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("%q: unexpected error adding entries to test backend: %v",
				test.name, err)
		}

		// Attempt to fetch the entry for the outpoint specified by the test.
		entry, err = backend.FetchEntry(test.outpoint)
		if test.wantErr && err == nil {
			t.Fatalf("%q: did not receive expected error", test.name)
		}
		if !test.wantErr && err != nil {
			t.Fatalf("%q: unexpected error fetching entry: %v", test.name, err)
		}

		// Ensure that the fetched entry matches the expected entry.
		if !reflect.DeepEqual(entry, test.wantEntry) {
			t.Fatalf("%q: mismatched entry:\nwant: %+v\n got: %+v\n", test.name,
				test.wantEntry, entry)
		}
	}
}

// TestPutUtxos validates that the UTXO set in the backend is updated as
// expected under a variety of conditions.
func TestPutUtxos(t *testing.T) {
	t.Parallel()

	// Create a test backend.
	backend := createTestUtxoBackend(t)

	// Create test hashes to be used throughout the tests.
	block1000Hash := mustParseHash("0000000000004740ad140c86753f9295e09f9cc81b1" +
		"bb75d7f5552aeeedb7012")
	block2000Hash := mustParseHash("0000000000000c8a886e3f7c32b1bb08422066dcfd0" +
		"08de596471f11a5aff475")

	// entry299Fresh is from block height 299 and is modified and fresh.
	outpoint299 := outpoint299()
	entry299Fresh := entry299()
	entry299Fresh.state |= utxoStateModified | utxoStateFresh

	// entry299Unmodified is from block height 299 and is unmodified.
	entry299Unmodified := entry299()

	// entry1100Spent is from block height 1100 and is modified and spent.
	outpoint1100 := outpoint1100()
	entry1100Spent := entry1100()
	entry1100Spent.Spend()

	// entry1100Modified is from block height 1100 and is modified and unspent.
	entry1100Modified := entry1100()
	entry1100Modified.state |= utxoStateModified

	// entry1200Unmodified is from block height 1200 and is unspent and
	// unmodified.
	outpoint1200 := outpoint1200()
	entry1200Unmodified := entry1200()

	tests := []struct {
		name               string
		utxos              map[wire.OutPoint]*UtxoEntry
		state              *UtxoSetState
		backendEntries     map[wire.OutPoint]*UtxoEntry
		backendState       *UtxoSetState
		wantBackendEntries map[wire.OutPoint]*UtxoEntry
		wantState          *UtxoSetState
	}{{
		name: "update the UTXO set with entries in various states",
		utxos: map[wire.OutPoint]*UtxoEntry{
			outpoint299:  entry299Fresh,
			outpoint1100: entry1100Spent,
			outpoint1200: entry1200Unmodified,
		},
		state: &UtxoSetState{
			lastFlushHash:   *block2000Hash,
			lastFlushHeight: 2000,
		},
		backendEntries: map[wire.OutPoint]*UtxoEntry{
			outpoint1100: entry1100Modified,
		},
		backendState: &UtxoSetState{
			lastFlushHash:   *block1000Hash,
			lastFlushHeight: 1000,
		},
		// entry299 should be added to the backend.
		// entry1100 should be removed from the backend since it now spent.
		// entry1200 should not be added to the backend since it is unmodified.
		wantBackendEntries: map[wire.OutPoint]*UtxoEntry{
			outpoint299: entry299Unmodified,
		},
		wantState: &UtxoSetState{
			lastFlushHash:   *block2000Hash,
			lastFlushHeight: 2000,
		},
	}}

	for _, test := range tests {
		// Add existing entries specified by the test to the test backend.
		err := backend.PutUtxos(test.backendEntries, test.backendState)
		if err != nil {
			t.Fatalf("%q: unexpected error adding entries to test backend: %v",
				test.name, err)
		}

		// Update the UTXO set and state as specified by the test.
		err = backend.PutUtxos(test.utxos, test.state)
		if err != nil {
			t.Fatalf("%q: unexpected error putting utxos: %v", test.name, err)
		}

		// Validate that the backend entries match the expected entries after
		// updating the UTXO set.
		backendEntries := make(map[wire.OutPoint]*UtxoEntry)
		for outpoint := range test.utxos {
			entry, err := backend.FetchEntry(outpoint)
			if err != nil {
				t.Fatalf("%q: unexpected error fetching entries from test backend: %v",
					test.name, err)
			}

			if entry != nil {
				backendEntries[outpoint] = entry
			}
		}
		if !reflect.DeepEqual(backendEntries, test.wantBackendEntries) {
			t.Fatalf("%q: mismatched backend entries:\nwant: %+v\n got: %+v\n",
				test.name, test.wantBackendEntries, backendEntries)
		}

		// Validate that the state has been updated in the backend as expexted.
		gotState, err := backend.FetchState()
		if err != nil {
			t.Fatalf("%q: error fetching utxo set state: %v", test.name, err)
		}
		if !reflect.DeepEqual(gotState, test.state) {
			t.Fatalf("%q: mismatched state:\nwant: %+v\n got: %+v\n", test.name,
				test.state, gotState)
		}
	}
}

// TestFetchState ensures that fetching the utxo set state from the backend
// works as expected.
func TestFetchState(t *testing.T) {
	t.Parallel()

	// Create a test backend.
	backend := createTestUtxoBackend(t)

	tests := []struct {
		name  string
		state *UtxoSetState
	}{{
		name:  "fresh backend (no utxo set state saved)",
		state: nil,
	}, {
		name: "last flush saved in backend",
		state: &UtxoSetState{
			lastFlushHeight: 432100,
			lastFlushHash: *mustParseHash("000000000000000023455b4328635d8e014dbeea" +
				"99c6140aa715836cc7e55981"),
		},
	}}

	for _, test := range tests {
		// Update the utxo set state in the backend.
		if test.state != nil {
			err := backend.Update(func(tx UtxoBackendTx) error {
				return tx.Put(utxoSetStateKey,
					serializeUtxoSetState(test.state))
			})
			if err != nil {
				t.Fatalf("%q: error putting utxo set state: %v", test.name, err)
			}
		}

		// Fetch the utxo set state from the backend.
		gotState, err := backend.FetchState()
		if err != nil {
			t.Fatalf("%q: error fetching utxo set state: %v", test.name, err)
		}

		// Ensure that the fetched utxo set state matches the expected state.
		if !reflect.DeepEqual(gotState, test.state) {
			t.Fatalf("%q: mismatched state:\nwant: %+v\n got: %+v\n", test.name,
				test.state, gotState)
		}
	}
}

// TestPutInfo ensures that putting and fetching the UTXO backend info works as
// expected.
func TestPutInfo(t *testing.T) {
	t.Parallel()

	// Create a test backend.
	backend := createTestUtxoBackend(t)

	tests := []struct {
		name        string
		backendInfo *UtxoBackendInfo
	}{{
		name:        "without UTXO backend info (fresh backend)",
		backendInfo: nil,
	}, {
		name: "with UTXO backend info",
		backendInfo: &UtxoBackendInfo{
			version: 1,
			compVer: 2,
			utxoVer: 3,
			created: time.Unix(1584246683, 0), // 2020-03-15 04:31:23 UTC
		},
	}}

	for _, test := range tests {
		if test.backendInfo != nil {
			// Update the UTXO backend info.
			err := backend.PutInfo(test.backendInfo)
			if err != nil {
				t.Fatalf("%q: error putting UTXO backend info: %v", test.name, err)
			}
		}

		// Fetch the UTXO backend info.
		gotBackendInfo, err := backend.FetchInfo()
		if err != nil {
			t.Fatalf("%q: error fetching UTXO backend info: %v", test.name, err)
		}

		// Ensure that the fetched UTXO backend info matches the expected UTXO
		// backend info.
		if !reflect.DeepEqual(gotBackendInfo, test.backendInfo) {
			t.Fatalf("%q: mismatched backend info:\nwant: %+v\n got: %+v\n",
				test.name, test.backendInfo, gotBackendInfo)
		}
	}
}
