// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.
package indexers

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/decred/dcrd/blockchain/v4/chaingen"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/database/v2"
	"github.com/decred/dcrd/wire"
)

// TestSpendConsumer ensures the spend consumer behaves as expected.
func TestSpendConsumer(t *testing.T) {
	dbPath, err := ioutil.TempDir("", "test_spendconsumer")
	if err != nil {
		t.Fatalf("unable to create test db path: %v", err)
	}

	db, err := database.Create("ffldb", dbPath, wire.SimNet)
	if err != nil {
		os.RemoveAll(dbPath)
		t.Fatalf("error creating db: %v", err)
	}
	defer func() {
		db.Close()
		os.RemoveAll(dbPath)
	}()

	chain, err := newTestChain()
	if err != nil {
		t.Fatal(err)
	}

	g, err := chaingen.MakeGenerator(chaincfg.SimNetParams())
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	// Add four blocks to the chain.
	bk1 := addBlock(t, chain, &g, "bk1")
	bk2 := addBlock(t, chain, &g, "bk2")
	bk3 := addBlock(t, chain, &g, "bk3")
	bk4 := addBlock(t, chain, &g, "bk4")

	id := "testConsumer"
	consumer := NewSpendConsumer(id, bk3.Hash(), chain)

	// Ensure the consumer is correctly identified.
	if id != consumer.ID() {
		t.Fatalf("expected consumer id to be %v, got %v", id, consumer.ID())
	}

	// Ensure bk2 is needed by the consumer since it is an ancestor
	// of the current tip, bk3.
	needed, err := consumer.NeedSpendData(bk2.Hash())
	if err != nil {
		t.Fatalf("unexpected NeedSpendData error: %v", err)
	}

	if !needed {
		t.Fatalf("expected the spend data for block bk2 to be needed")
	}

	// Ensure bk4 is not needed by the address index since it is an ancestor
	// of the current tip, bk4.
	needed, err = consumer.NeedSpendData(bk4.Hash())
	if err != nil {
		t.Fatalf("unexpected NeedSpendData error: %v", err)
	}

	if needed {
		t.Fatalf("expected the spend data for block bk4 to not be needed")
	}

	// Ensure finding the ancestor of an unknown block hash fails.
	_, err = consumer.NeedSpendData(&chainhash.Hash{0})
	if err == nil {
		t.Fatal("expected an unknown block error")
	}

	// Update the consumer tip to bk1.
	consumer.UpdateTip(bk1.Hash())

	// Ensure bk2 is now no longer needed by the consumer since it is
	// not an ancestor of the current tip, bk1.
	needed, err = consumer.NeedSpendData(bk2.Hash())
	if err != nil {
		t.Fatalf("unexpected NeedSpendData error: %v", err)
	}

	if needed {
		t.Fatalf("expected the spend data for block bk2 to not be needed")
	}
}
