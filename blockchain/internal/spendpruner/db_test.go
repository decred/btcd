// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package spendpruner

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/decred/dcrd/database/v2"
	_ "github.com/decred/dcrd/database/v2/ffldb"
	"github.com/decred/dcrd/wire"
)

// TestSerializeConsumerDeps ensures consumer dependencies serialize as intended.
func TestSerializeConsumerDeps(t *testing.T) {
	tests := []struct {
		name     string
		deps     []string
		expected []byte
	}{{
		name:     "no dependencies",
		deps:     []string{},
		expected: []byte{},
	}, {
		name:     "one dependency",
		deps:     []string{"alpha"},
		expected: []byte("alpha"),
	}, {
		name:     "odd number of dependencies",
		deps:     []string{"alpha", "bravo", "charlie"},
		expected: []byte("alpha,bravo,charlie"),
	}, {
		name:     "even numeber of dependencies",
		deps:     []string{"alpha", "bravo", "charlie", "echo"},
		expected: []byte("alpha,bravo,charlie,echo"),
	}}

	for _, test := range tests {
		serialized := serializeSpendConsumerDeps(test.deps)
		if !bytes.Equal(serialized, test.expected) {
			t.Errorf("%q: unexpected serialized mismatch, "+
				"expected %q, got %q", test.name, test.expected, serialized)
			continue
		}
	}
}

// TestDeserializeConsumerDeps ensures consumer dependencies deserialize as
// intended.
func TestDeserializeConsumerDeps(t *testing.T) {
	tests := []struct {
		name       string
		serialized []byte
		expected   []string
	}{{
		name:       "no dependencies",
		serialized: []byte{},
		expected:   []string{},
	}, {
		name:       "one dependency",
		serialized: []byte("alpha"),
		expected:   []string{"alpha"},
	}, {
		name:       "odd number of dependencies",
		serialized: []byte("alpha,bravo,charlie"),
		expected:   []string{"alpha", "bravo", "charlie"},
	}, {
		name:       "even numeber of dependencies",
		serialized: []byte("alpha,bravo,charlie,echo"),
		expected:   []string{"alpha", "bravo", "charlie", "echo"},
	}}

	for _, test := range tests {
		deserialized := deserializeSpendConsumerDeps(test.serialized)
		for idx := range test.expected {
			if deserialized[idx] != test.expected[idx] {
				t.Errorf("%q: unexpected dependency mismatch at index %d, "+
					"expected %q, got %q", test.name, idx,
					test.expected[idx], deserialized[idx])
				continue
			}
		}
	}
}

// createdDB creates the test database. This is intended to be used
// for testing purposes only.
func createDB() (database.DB, func(), error) {
	dbPath := filepath.Join(os.TempDir(), "spdb")

	err := os.MkdirAll(dbPath, 0700)
	if err != nil {
		return nil, nil, err
	}

	db, err := database.Create("ffldb", dbPath, wire.SimNet)
	if err != nil {
		return nil, nil, err
	}

	err = initConsumerDepsBucket(db)
	if err != nil {
		return nil, nil, err
	}

	teardown := func() {
		db.Close()
		os.RemoveAll(dbPath)
	}

	return db, teardown, nil
}
