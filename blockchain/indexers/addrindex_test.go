// Copyright (c) 2016 The btcsuite developers
// Copyright (c) 2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/decred/dcrd/blockchain/v4/chaingen"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/database/v2"
	"github.com/decred/dcrd/txscript/v4"
	"github.com/decred/dcrd/wire"
)

// addrIndexBucket provides a mock address index database bucket by implementing
// the internalBucket interface.
type addrIndexBucket struct {
	levels map[[levelKeySize]byte][]byte
}

// Clone returns a deep copy of the mock address index bucket.
func (b *addrIndexBucket) Clone() *addrIndexBucket {
	levels := make(map[[levelKeySize]byte][]byte)
	for k, v := range b.levels {
		vCopy := make([]byte, len(v))
		copy(vCopy, v)
		levels[k] = vCopy
	}
	return &addrIndexBucket{levels: levels}
}

// Get returns the value associated with the key from the mock address index
// bucket.
//
// This is part of the internalBucket interface.
func (b *addrIndexBucket) Get(key []byte) []byte {
	var levelKey [levelKeySize]byte
	copy(levelKey[:], key)
	return b.levels[levelKey]
}

// Put stores the provided key/value pair to the mock address index bucket.
//
// This is part of the internalBucket interface.
func (b *addrIndexBucket) Put(key []byte, value []byte) error {
	var levelKey [levelKeySize]byte
	copy(levelKey[:], key)
	b.levels[levelKey] = value
	return nil
}

// Delete removes the provided key from the mock address index bucket.
//
// This is part of the internalBucket interface.
func (b *addrIndexBucket) Delete(key []byte) error {
	var levelKey [levelKeySize]byte
	copy(levelKey[:], key)
	delete(b.levels, levelKey)
	return nil
}

// printLevels returns a string with a visual representation of the provided
// address key taking into account the max size of each level.  It is useful
// when creating and debugging test cases.
func (b *addrIndexBucket) printLevels(addrKey [addrKeySize]byte) string {
	highestLevel := uint8(0)
	for k := range b.levels {
		if !bytes.Equal(k[:levelOffset], addrKey[:]) {
			continue
		}
		level := k[levelOffset]
		if level > highestLevel {
			highestLevel = level
		}
	}

	var levelBuf bytes.Buffer
	_, _ = levelBuf.WriteString("\n")
	maxEntries := level0MaxEntries
	for level := uint8(0); level <= highestLevel; level++ {
		data := b.levels[keyForLevel(addrKey, level)]
		numEntries := len(data) / txEntrySize
		for i := 0; i < numEntries; i++ {
			start := i * txEntrySize
			num := byteOrder.Uint32(data[start:])
			_, _ = levelBuf.WriteString(fmt.Sprintf("%02d ", num))
		}
		for i := numEntries; i < maxEntries; i++ {
			_, _ = levelBuf.WriteString("_  ")
		}
		_, _ = levelBuf.WriteString("\n")
		maxEntries *= 2
	}

	return levelBuf.String()
}

// sanityCheck ensures that all data stored in the bucket for the given address
// adheres to the level-based rules described by the address index
// documentation.
func (b *addrIndexBucket) sanityCheck(addrKey [addrKeySize]byte, expectedTotal int) error {
	// Find the highest level for the key.
	highestLevel := uint8(0)
	for k := range b.levels {
		if !bytes.Equal(k[:levelOffset], addrKey[:]) {
			continue
		}
		level := k[levelOffset]
		if level > highestLevel {
			highestLevel = level
		}
	}

	// Ensure the expected total number of entries are present and that
	// all levels adhere to the rules described in the address index
	// documentation.
	var totalEntries int
	maxEntries := level0MaxEntries
	for level := uint8(0); level <= highestLevel; level++ {
		// Level 0 can't have more entries than the max allowed if the
		// levels after it have data and it can't be empty.  All other
		// levels must either be half full or full.
		data := b.levels[keyForLevel(addrKey, level)]
		numEntries := len(data) / txEntrySize
		totalEntries += numEntries
		if level == 0 {
			if (highestLevel != 0 && numEntries == 0) ||
				numEntries > maxEntries {

				return fmt.Errorf("level %d has %d entries",
					level, numEntries)
			}
		} else if numEntries != maxEntries && numEntries != maxEntries/2 {
			return fmt.Errorf("level %d has %d entries", level,
				numEntries)
		}
		maxEntries *= 2
	}
	if totalEntries != expectedTotal {
		return fmt.Errorf("expected %d entries - got %d", expectedTotal,
			totalEntries)
	}

	// Ensure all of the numbers are in order starting from the highest
	// level moving to the lowest level.
	expectedNum := uint32(0)
	for level := highestLevel + 1; level > 0; level-- {
		data := b.levels[keyForLevel(addrKey, level)]
		numEntries := len(data) / txEntrySize
		for i := 0; i < numEntries; i++ {
			start := i * txEntrySize
			num := byteOrder.Uint32(data[start:])
			if num != expectedNum {
				return fmt.Errorf("level %d offset %d does "+
					"not contain the expected number of "+
					"%d - got %d", level, i, num,
					expectedNum)
			}
			expectedNum++
		}
	}

	return nil
}

// TestAddrIndexLevels ensures that adding and deleting entries to the address
// index creates multiple levels as described by the address index documentation.
func TestAddrIndexLevels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		key         [addrKeySize]byte
		numInsert   int
		printLevels bool // Set to help debug a specific test.
	}{
		{
			name:      "level 0 not full",
			numInsert: level0MaxEntries - 1,
		},
		{
			name:      "level 1 half",
			numInsert: level0MaxEntries + 1,
		},
		{
			name:      "level 1 full",
			numInsert: level0MaxEntries*2 + 1,
		},
		{
			name:      "level 2 half, level 1 half",
			numInsert: level0MaxEntries*3 + 1,
		},
		{
			name:      "level 2 half, level 1 full",
			numInsert: level0MaxEntries*4 + 1,
		},
		{
			name:      "level 2 full, level 1 half",
			numInsert: level0MaxEntries*5 + 1,
		},
		{
			name:      "level 2 full, level 1 full",
			numInsert: level0MaxEntries*6 + 1,
		},
		{
			name:      "level 3 half, level 2 half, level 1 half",
			numInsert: level0MaxEntries*7 + 1,
		},
		{
			name:      "level 3 full, level 2 half, level 1 full",
			numInsert: level0MaxEntries*12 + 1,
		},
	}

nextTest:
	for testNum, test := range tests {
		// Insert entries in order.
		populatedBucket := &addrIndexBucket{
			levels: make(map[[levelKeySize]byte][]byte),
		}
		for i := 0; i < test.numInsert; i++ {
			txLoc := wire.TxLoc{TxStart: i * 2}
			err := dbPutAddrIndexEntry(populatedBucket, test.key,
				uint32(i), txLoc, uint32(i%100))
			if err != nil {
				t.Errorf("dbPutAddrIndexEntry #%d (%s) - "+
					"unexpected error: %v", testNum,
					test.name, err)
				continue nextTest
			}
		}
		if test.printLevels {
			t.Log(populatedBucket.printLevels(test.key))
		}

		// Delete entries from the populated bucket until all entries
		// have been deleted.  The bucket is reset to the fully
		// populated bucket on each iteration so every combination is
		// tested.  Notice the upper limit purposes exceeds the number
		// of entries to ensure attempting to delete more entries than
		// there are works correctly.
		for numDelete := 0; numDelete <= test.numInsert+1; numDelete++ {
			// Clone populated bucket to run each delete against.
			bucket := populatedBucket.Clone()

			// Remove the number of entries for this iteration.
			err := dbRemoveAddrIndexEntries(bucket, test.key,
				numDelete)
			if err != nil {
				if numDelete <= test.numInsert {
					t.Errorf("dbRemoveAddrIndexEntries (%s) "+
						" delete %d - unexpected error: "+
						"%v", test.name, numDelete, err)
					continue nextTest
				}
			}
			if test.printLevels {
				t.Log(bucket.printLevels(test.key))
			}

			// Sanity check the levels to ensure the adhere to all
			// rules.
			numExpected := test.numInsert
			if numDelete <= test.numInsert {
				numExpected -= numDelete
			}
			err = bucket.sanityCheck(test.key, numExpected)
			if err != nil {
				t.Errorf("sanity check fail (%s) delete %d: %v",
					test.name, numDelete, err)
				continue nextTest
			}
		}
	}
}

// TestAddrIndexAsync ensures the address index behaves
// receiving updates asynchronously.
func TestAddrIndexAsync(t *testing.T) {
	db, path := setupDB(t, "test_addrindex")
	defer teardownDB(db, path)

	// Create the test chain.
	chain, err := newTestChain()
	if err != nil {
		t.Fatal(err)
	}

	g, err := chaingen.MakeGenerator(chaincfg.SimNetParams())
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	// Add three blocks to the chain.
	addBlock(t, chain, &g, "bk1")
	addBlock(t, chain, &g, "bk2")
	bk3 := addBlock(t, chain, &g, "bk3")

	// Initialize the tx index and address index. The tx index is required
	// because the address index depends on it.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	subber := NewIndexSubscriber(ctx)
	go subber.Run(ctx)

	txIdx, err := NewTxIndex(subber, db, chain)
	if err != nil {
		t.Fatal(err)
	}

	addrIdx, err := NewAddrIndex(subber, db, chain)
	if err != nil {
		t.Fatal(err)
	}

	err = subber.CatchUp(ctx, db, chain)
	if err != nil {
		t.Fatal(err)
	}

	// Ensure the indexes got synced to bk3 on initialization.
	txIdxTipHeight, txIdxTipHash, err := addrIdx.Tip()
	if err != nil {
		t.Fatal(err)
	}

	if txIdxTipHeight != bk3.Height() {
		t.Fatalf("expected tip height to be %d, got %d", bk3.Height(), txIdxTipHeight)
	}

	if *txIdxTipHash != *bk3.Hash() {
		t.Fatalf("expected tip hash to be %s, got %s", bk3.Hash().String(),
			txIdxTipHash.String())
	}

	addrIdxTipHeight, addrIdxTipHash, err := addrIdx.Tip()
	if err != nil {
		t.Fatal(err)
	}

	if addrIdxTipHeight != bk3.Height() {
		t.Fatalf("expected tip height to be %d, got %d", bk3.Height(), addrIdxTipHeight)
	}

	if *addrIdxTipHash != *bk3.Hash() {
		t.Fatalf("expected tip hash to be %s, got %s", bk3.Hash().String(),
			addrIdxTipHash.String())
	}

	// Ensure the address index remains in sync with the main chain when new
	// blocks are connected.
	bk4 := addBlock(t, chain, &g, "bk4")
	ntfn := &IndexNtfn{
		NtfnType:          ConnectNtfn,
		Block:             bk4,
		Parent:            bk3,
		PrevScripts:       nil,
		IsTreasuryEnabled: false,
	}
	notifyAndWait(t, subber, ntfn)

	bk5 := addBlock(t, chain, &g, "bk5")
	ntfn = &IndexNtfn{
		NtfnType:          ConnectNtfn,
		Block:             bk5,
		Parent:            bk4,
		PrevScripts:       nil,
		IsTreasuryEnabled: false,
	}
	notifyAndWait(t, subber, ntfn)

	// Ensure the indexes got synced to bk5.
	txIdxTipHeight, txIdxTipHash, err = addrIdx.Tip()
	if err != nil {
		t.Fatal(err)
	}

	if txIdxTipHeight != bk5.Height() {
		t.Fatalf("expected tip height to be %d, got %d", bk5.Height(),
			txIdxTipHeight)
	}

	if *txIdxTipHash != *bk5.Hash() {
		t.Fatalf("expected tip hash to be %s, got %s", bk5.Hash().String(),
			txIdxTipHash.String())
	}

	addrIdxTipHeight, addrIdxTipHash, err = addrIdx.Tip()
	if err != nil {
		t.Fatal(err)
	}

	if addrIdxTipHeight != bk5.Height() {
		t.Fatalf("expected tip height to be %d, got %d", bk5.Height(),
			addrIdxTipHeight)
	}

	if *addrIdxTipHash != *bk5.Hash() {
		t.Fatalf("expected tip hash to be %s, got %s", bk5.Hash().String(),
			addrIdxTipHash.String())
	}

	// Ensure the spend consumer's tip was updated to bk5.
	addrIdx.consumer.mtx.Lock()
	tipHash := addrIdx.consumer.tipHash
	addrIdx.consumer.mtx.Unlock()

	if !tipHash.IsEqual(bk5.Hash()) {
		t.Fatalf("expected spend consumer tip hash to be %s, got %s",
			bk5.Hash().String(), tipHash.String())
	}

	// Fetch the first address paid to by bk5's coinbase.
	out := bk5.MsgBlock().Transactions[0].TxOut[0]
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(out.Version,
		out.PkScript, addrIdx.chainParams, true)
	if err != nil {
		t.Fatal(err)
	}

	// Ensure the address index has the first address paid to by bk5's
	// coinbase indexed.
	err = db.View(func(dbTx database.Tx) error {
		entry, _, err := addrIdx.EntriesForAddress(dbTx, addrs[0], 0, 1, false)
		if err != nil {
			return err
		}
		if entry == nil {
			return fmt.Errorf("no index entry found for address %s",
				addrs[0].String())
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a reorg by setting bk4 as the main chain tip. bk5 is now
	// an orphan block.
	g.SetTip("bk4")
	err = chain.RemoveBlock(bk5)
	if err != nil {
		t.Fatal(err)
	}

	// Add bk5a to the main chain.
	bk5a := addBlock(t, chain, &g, "bk5a")

	// Resubscribe the indexes.
	err = addrIdx.sub.stop()
	if err != nil {
		t.Fatal(err)
	}

	err = txIdx.sub.stop()
	if err != nil {
		t.Fatal(err)
	}

	txIdx, err = NewTxIndex(subber, db, chain)
	if err != nil {
		t.Fatal(err)
	}

	addrIdx, err = NewAddrIndex(subber, db, chain)
	if err != nil {
		t.Fatal(err)
	}

	err = subber.CatchUp(ctx, db, chain)
	if err != nil {
		t.Fatal(err)
	}

	// Ensure the indexes recovered to bk4 and synced back to the main chain tip
	// bk5a.
	txIdxTipHeight, txIdxTipHash, err = txIdx.Tip()
	if err != nil {
		t.Fatal(err)
	}

	if txIdxTipHeight != bk5a.Height() {
		t.Fatalf("expected tip height to be %d, got %d",
			bk5a.Height(), txIdxTipHeight)
	}

	if *txIdxTipHash != *bk5a.Hash() {
		t.Fatalf("expected tip hash to be %s, got %s",
			bk5a.Hash().String(), txIdxTipHash.String())
	}

	addrIdxTipHeight, addrIdxTipHash, err = addrIdx.Tip()
	if err != nil {
		t.Fatal(err)
	}

	if addrIdxTipHeight != bk5a.Height() {
		t.Fatalf("expected tip height to be %d, got %d",
			bk5a.Height(), addrIdxTipHeight)
	}

	if *addrIdxTipHash != *bk5a.Hash() {
		t.Fatalf("expected tip hash to be %s, got %s",
			bk5a.Hash().String(), addrIdxTipHash.String())
	}

	// Ensure the spend consumer's tip was updated to bk5a.
	addrIdx.consumer.mtx.Lock()
	tipHash = addrIdx.consumer.tipHash
	addrIdx.consumer.mtx.Unlock()

	if !tipHash.IsEqual(bk5a.Hash()) {
		t.Fatalf("expected spend consumer tip hash to be %s, got %s",
			bk5a.Hash().String(), tipHash.String())
	}

	// Ensure the addreses associated with bk5's coinbase transaction
	// is no longer indexed by the address manager.
	// Ensure the address index no longder has the first address paid to by
	// bk5's coinbase indexed.
	err = db.View(func(dbTx database.Tx) error {
		entry, _, err := addrIdx.EntriesForAddress(dbTx, addrs[0], 0, 1, false)
		if err != nil {
			return err
		}
		if entry != nil {
			return fmt.Errorf("expected no index entry found for address %s",
				addrs[0].String())
		}

		return nil
	})
	if err == nil {
		t.Fatalf("expected no index entry found for address %s",
			addrs[0].String())
	}

	// Ensure the indexes remain in sync when blocks are disconnected.
	err = chain.RemoveBlock(bk5a)
	if err != nil {
		t.Fatal(err)
	}

	g.SetTip("bk4")

	ntfn = &IndexNtfn{
		NtfnType:          DisconnectNtfn,
		Block:             bk5a,
		Parent:            bk4,
		PrevScripts:       nil,
		IsTreasuryEnabled: false,
	}
	notifyAndWait(t, subber, ntfn)

	err = chain.RemoveBlock(bk4)
	if err != nil {
		t.Fatal(err)
	}

	g.SetTip("bk3")

	ntfn = &IndexNtfn{
		NtfnType:          DisconnectNtfn,
		Block:             bk4,
		Parent:            bk3,
		PrevScripts:       nil,
		IsTreasuryEnabled: false,
	}
	notifyAndWait(t, subber, ntfn)

	// Ensure the index tips are now bk3 after the disconnections.
	txIdxTipHeight, txIdxTipHash, err = addrIdx.Tip()
	if err != nil {
		t.Fatal(err)
	}

	if txIdxTipHeight != bk3.Height() {
		t.Fatalf("expected tip height to be %d, got %d",
			bk3.Height(), txIdxTipHeight)
	}

	if *txIdxTipHash != *bk3.Hash() {
		t.Fatalf("expected tip hash to be %s, got %s",
			bk3.Hash().String(), txIdxTipHash.String())
	}

	addrIdxTipHeight, addrIdxTipHash, err = addrIdx.Tip()
	if err != nil {
		t.Fatal(err)
	}

	if addrIdxTipHeight != bk3.Height() {
		t.Fatalf("expected tip height to be %d, got %d", bk3.Height(), addrIdxTipHeight)
	}

	if *addrIdxTipHash != *bk3.Hash() {
		t.Fatalf("expected tip hash to be %s, got %s", bk3.Hash().String(),
			addrIdxTipHash.String())
	}

	// Drop the address index and resubscribe.
	err = addrIdx.sub.stop()
	if err != nil {
		t.Fatal(err)
	}

	err = addrIdx.DropIndex(ctx, db)
	if err != nil {
		t.Fatal(err)
	}

	addrIdx, err = NewAddrIndex(subber, db, chain)
	if err != nil {
		t.Fatal(err)
	}

	err = subber.CatchUp(ctx, db, chain)
	if err != nil {
		t.Fatal(err)
	}

	// Ensure the address index got synced to bk3 on initialization.
	addrIdxTipHeight, addrIdxTipHash, err = addrIdx.Tip()
	if err != nil {
		t.Fatal(err)
	}

	if addrIdxTipHeight != bk3.Height() {
		t.Fatalf("expected tip height to be %d, got %d", bk3.Height(), addrIdxTipHeight)
	}

	if *addrIdxTipHash != *bk3.Hash() {
		t.Fatalf("expected tip hash to be %s, got %s", bk3.Hash().String(),
			addrIdxTipHash.String())
	}

	// Add bk4a to the main chain.
	bk4a := addBlock(t, chain, &g, "bk4a")

	go func() {
		// Stall the index notification for bk4a.
		time.Sleep(time.Millisecond * 150)
		notif := &IndexNtfn{
			NtfnType:    ConnectNtfn,
			Block:       bk4a,
			Parent:      bk3,
			PrevScripts: nil,
			Done:        make(chan bool),
		}
		subber.Notify(notif)
		select {
		case <-notif.Done:
			// Nothing to do.
		case <-time.After(time.Second):
			panic("timeout waiting for done signal for notification")
		}
	}()

	// Wait for the index to sync with the main chain.
	select {
	case <-addrIdx.WaitForSync():
		// Nothing to do.
	case <-time.After(time.Second):
		panic("timeout waiting for index to synchronize")
	}

	// Add bk6 and bk7 to the main chain.
	bk6 := addBlock(t, chain, &g, "bk6")
	bk7 := addBlock(t, chain, &g, "bk7")

	// Ensure sending an unexpected index notification (bk7) does not
	// update the index.
	ntfn = &IndexNtfn{
		NtfnType:    ConnectNtfn,
		Block:       bk7,
		Parent:      bk6,
		PrevScripts: nil,
	}
	notifyAndWait(t, subber, ntfn)

	// Ensure the address index remains at tip bk4a after receiving unexpected
	// index notification for bk7.
	addrIdxTipHeight, addrIdxTipHash, err = addrIdx.Tip()
	if err != nil {
		t.Fatal(err)
	}

	if addrIdxTipHeight != bk4a.Height() {
		t.Fatalf("expected tip height to be %d, got %d",
			bk4a.Height(), addrIdxTipHeight)
	}

	if *addrIdxTipHash != *bk4a.Hash() {
		t.Fatalf("expected tip hash to be %s, got %s",
			bk4a.Hash().String(), addrIdxTipHash.String())
	}
}
