// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package spendpruner

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/decred/dcrd/chaincfg/chainhash"
)

// testSpendConsumer represents a mock spend consumer for testing purposes only.
type testSpendConsumer struct {
	id               string
	queryer          *testSpendPurger
	tip              *chainhash.Hash
	needSpendData    bool
	needSpendDataErr error
}

// ID returns the identifier of the consumer.
func (t *testSpendConsumer) ID() string {
	return t.id
}

// NeedSpendData checks whether the associated spend journal entry
// for the provided block hash will be needed by the consumer.
func (t *testSpendConsumer) NeedSpendData(hash *chainhash.Hash) (bool, error) {
	return t.needSpendData, t.needSpendDataErr
}

// testSpendPurger represents a mock spend purger for testing purposes only.
type testSpendPurger struct {
	removedSpendEntries map[chainhash.Hash]struct{}
	removeSpendEntryErr error
	mtx                 sync.Mutex
}

// RemoveSpendEntry purges the associated spend journal entry of the
// provided block hash.
func (t *testSpendPurger) RemoveSpendEntry(hash *chainhash.Hash) error {
	if t.removeSpendEntryErr != nil {
		return t.removeSpendEntryErr
	}

	t.mtx.Lock()
	t.removedSpendEntries[*hash] = struct{}{}
	t.mtx.Unlock()

	return nil
}

// TestSpendPruner ensures the spend pruner works as intended.
func TestSpendPruner(t *testing.T) {
	chain := &testSpendPurger{
		removedSpendEntries: make(map[chainhash.Hash]struct{}),
	}

	consumerA := &testSpendConsumer{
		id:            "consumer_a",
		queryer:       chain,
		tip:           &chainhash.Hash{0},
		needSpendData: true,
	}

	consumerB := &testSpendConsumer{
		id:               "consumer_b",
		queryer:          chain,
		tip:              &chainhash.Hash{0},
		needSpendData:    false,
		needSpendDataErr: fmt.Errorf("unable to confirm spend data need"),
	}

	db, teardown, err := createDB()
	if err != nil {
		t.Fatal(err)
	}

	defer teardown()

	ctx, cancel := context.WithCancel(context.Background())
	pruner, err := NewSpendJournalPruner(db, chain)
	if err != nil {
		t.Fatal(err)
	}

	go pruner.HandleSignals(ctx)

	pruner.AddConsumer(consumerA)
	pruner.AddConsumer(consumerB)

	// Ensure adding the same consumer does not create a duplicate.
	pruner.AddConsumer(consumerB)

	pruner.consumersMtx.Lock()
	consumers := len(pruner.consumers)
	pruner.consumersMtx.Unlock()

	if consumers != 2 {
		t.Fatalf("expected 2 consumers, got %d", consumers)
	}

	// Ensure adding dependents fails if a consumer errors checking if the
	// data is needed.
	hashA := &chainhash.Hash{'a'}
	err = pruner.addSpendConsumerDeps(hashA)
	if !errors.Is(err, ErrNeedSpendData) {
		t.Fatalf("expected a spend data error, got %v", err)
	}

	fetchHashSpendDependents := func(pruner *SpendJournalPruner, hash *chainhash.Hash) ([]string, bool) {
		pruner.dependentsMtx.Lock()
		dependents, ok := pruner.dependents[*hash]
		pruner.dependentsMtx.Unlock()

		return dependents, ok
	}

	isRemovedSpendEntry := func(chain *testSpendPurger, hash *chainhash.Hash) bool {
		chain.mtx.Lock()
		_, ok := chain.removedSpendEntries[*hash]
		chain.mtx.Unlock()

		return ok
	}

	consumerB.needSpendDataErr = nil

	// Ensure adding dependents creates entries for consumers that need
	// the spend data of the provided block hash.
	err = pruner.addSpendConsumerDeps(hashA)
	if err != nil {
		t.Fatalf("unexpected error adding consumer dependencies: %v", err)
	}

	// Ensure there is only one dependent entry for hashA, belonging to
	// consumerA.
	dependents, ok := fetchHashSpendDependents(pruner, hashA)
	if !ok {
		t.Fatalf("expected dependents to have an entry for %s", hashA)
	}

	if len(dependents) != 1 {
		t.Fatalf("expected one dependent entry for hashA, got %d",
			len(dependents))
	}

	if dependents[0] != consumerA.ID() {
		t.Fatalf("expected hashA's dependent to be %s, got %s",
			consumerA.ID(), dependents[0])
	}

	// Ensure there is no existing dependency for consumerB on hashA.
	exists := pruner.dependencyExistsInternal(hashA, consumerB.ID())
	if exists {
		t.Fatal("unexpected dependency found for consumerB on hashA")
	}

	// Ensure there is an existing dependency for consumerA on hashA.
	exists = pruner.dependencyExistsInternal(hashA, consumerA.ID())
	if !exists {
		t.Fatal("expected dependency found for consumerA on hashA")
	}

	// Ensure consumerC and consumerA now have dependencies on hashA.
	consumerC := &testSpendConsumer{
		id:            "consumer_c",
		tip:           &chainhash.Hash{0},
		needSpendData: true,
	}

	pruner.AddConsumer(consumerC)

	setConsumerNeedSpendData := func(state bool) {
		consumerA.needSpendData = state
		consumerB.needSpendData = state
		consumerC.needSpendData = state
	}

	err = pruner.addSpendConsumerDeps(hashA)
	if err != nil {
		t.Fatalf("unexpected error adding spend data dependents "+
			"for hashA: %v", err)
	}

	exists = pruner.DependencyExists(hashA)
	if !exists {
		t.Fatal("expected existing dependencies for hashA")
	}

	exists = pruner.dependencyExistsInternal(hashA, consumerC.ID())
	if !exists {
		t.Fatal("expected dependency found for consumerC on hashA")
	}

	exists = pruner.dependencyExistsInternal(hashA, consumerA.ID())
	if !exists {
		t.Fatal("expected dependency found for consumerA on hashA")
	}

	// Ensure there are now two dependent entries for hashA.
	dependents, _ = fetchHashSpendDependents(pruner, hashA)
	if len(dependents) != 2 {
		t.Fatalf("expected two dependent entry for hashA, got %d",
			len(dependents))
	}

	// Ensure removing a non-existent dependency does nothing.
	pruner.RemoveSpendConsumerDependency(hashA, "consumer_x")

	// Ensure removing dependencies for a non-existent block hash does nothing.
	hashT := &chainhash.Hash{'T'}
	pruner.RemoveSpendConsumerDependency(hashT, "consumer_x")

	dependents, _ = fetchHashSpendDependents(pruner, hashA)
	if len(dependents) != 2 {
		t.Fatalf("expected two dependent entry for hashA, got %d",
			len(dependents))
	}

	// Update spend consumers to not need spend data for upcoming tests.
	setConsumerNeedSpendData(false)

	// Ensure the spend pruner does not remove the spend entries if
	// there are existing dependencies for it.
	err = pruner.MaybePruneSpendData(hashA)
	if err != nil {
		t.Fatalf("[MaybePruneSpendData] unexpected error: %v", err)
	}

	ok = isRemovedSpendEntry(chain, hashA)
	if ok {
		t.Fatal("unexpected hashA spend data pruned")
	}

	// Ensure the spend pruner does remove spend entries for
	// a hash if there are no existing spend dependencies for it.
	hashX := &chainhash.Hash{'x'}
	err = pruner.MaybePruneSpendData(hashX)
	if err != nil {
		t.Fatalf("[MaybePruneSpendData] unexpected error: %v", err)
	}

	ok = isRemovedSpendEntry(chain, hashX)
	if !ok {
		t.Fatalf("expected hashX spend data to be pruned")
	}

	// Remove the HashA dependency for consumerC.
	pruner.RemoveSpendConsumerDependency(hashA, consumerC.ID())

	dependents, _ = fetchHashSpendDependents(pruner, hashA)
	if len(dependents) != 1 {
		t.Fatalf("expected no dependent entry for hashA, got %d",
			len(dependents))
	}

	// Trigger a spend journal prune for HashA's entry by removing the
	// last dependency for it.
	pruner.RemoveSpendConsumerDependency(hashA, consumerA.ID())

	// Ensure the pruner no longer has a dependent entry for HashA.
	_, ok = pruner.dependents[*hashA]
	if ok {
		t.Fatal("expected no dependent entry for hashA")
	}

	ok = isRemovedSpendEntry(chain, hashX)
	if !ok {
		t.Fatal("expected hashA spend data to be pruned")
	}

	// Update spend consumers to need spend data for upcoming tests.
	setConsumerNeedSpendData(true)

	// Create consumer dependencies for hashB and hashC.
	hashB := &chainhash.Hash{'b'}
	err = pruner.addSpendConsumerDeps(hashB)
	if err != nil {
		t.Fatal("unexpected error adding consumer dependencies "+
			"for hashB: %v", err)
	}

	hashC := &chainhash.Hash{'c'}
	err = pruner.addSpendConsumerDeps(hashC)
	if err != nil {
		t.Fatalf("unexpected error adding consumer dependencies "+
			"for hashC: %v", err)
	}

	if !pruner.DependencyExists(hashB) {
		t.Fatal("expected consumer dependencies for hashB")
	}

	// Trigger a consumer dependencies purge by signalling hashB as a
	// connected block.
	go pruner.NotifyConnectedBlock(hashB)
	time.Sleep(time.Millisecond * 100)

	if pruner.DependencyExists(hashB) {
		t.Fatal("expected no consumer dependencies entry for hashB")
	}

	// Ensure the spend pruner does nothing if the provided connected block
	// does not have any spend consumer dependencies.
	go pruner.NotifyConnectedBlock(hashT)
	time.Sleep(time.Millisecond * 100)

	// Ensure there are consumer dependencies for hashC before shutting down.
	if !pruner.DependencyExists(hashC) {
		t.Fatal("expected consumer dependencies for hashC")
	}

	pruner.dependentsMtx.Lock()
	expected := len(pruner.dependents[*hashC])
	pruner.dependentsMtx.Unlock()

	cancel()

	// Load the spend pruner from the database.
	pruner, err = NewSpendJournalPruner(db, chain)
	if err != nil {
		t.Fatal(err)
	}

	// Ensure the consumer dependencies for hashC were loaded from
	// the database.
	if !pruner.DependencyExists(hashC) {
		t.Fatal("expected consumer dependencies for hashC")
	}

	// Ensure the expected number of dependents for hashC are identical
	// after loading from the database.
	deps, _ := fetchHashSpendDependents(pruner, hashC)

	if len(deps) != expected {
		t.Fatalf("dependencies mismatch, expected count of %d, got %d",
			expected, len(deps))
	}
}
