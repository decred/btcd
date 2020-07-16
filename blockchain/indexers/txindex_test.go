// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/decred/dcrd/blockchain/v3/chaingen"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/database/v2"
	_ "github.com/decred/dcrd/database/v2/ffldb"
	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/dcrd/wire"
)

type tChain struct {
	bestHeight    int64
	bestHash      *chainhash.Hash
	keyedByHeight map[int64]*dcrutil.Block
	keyedByHash   map[string]*dcrutil.Block
	orphans       map[string]*dcrutil.Block
	mtx           sync.Mutex
}

func newTChain(genesis *dcrutil.Block) (*tChain, error) {
	tc := &tChain{
		keyedByHeight: make(map[int64]*dcrutil.Block),
		keyedByHash:   make(map[string]*dcrutil.Block),
		orphans:       make(map[string]*dcrutil.Block),
	}
	return tc, tc.AddBlock(genesis)
}

func (tq *tChain) AddBlock(blk *dcrutil.Block) error {
	tq.mtx.Lock()
	defer tq.mtx.Unlock()

	// Ensure the incoming block is the child of the current chain tip.
	if tq.bestHash != nil {
		if !blk.MsgBlock().Header.PrevBlock.IsEqual(tq.bestHash) {
			return fmt.Errorf("block %s is an orphan", blk.Hash().String())
		}
	}

	height := blk.Height()
	hash := blk.Hash()
	tq.keyedByHash[hash.String()] = blk
	tq.keyedByHeight[height] = blk
	tq.bestHeight = height
	tq.bestHash = hash

	return nil
}

func (tq *tChain) RemoveBlock(blk *dcrutil.Block) error {
	tq.mtx.Lock()
	defer tq.mtx.Unlock()

	hash := blk.Hash()

	// Ensure the block being removed is the current chain tip.
	if !tq.bestHash.IsEqual(hash) {
		return fmt.Errorf("block %s is not the current chain tip",
			blk.Hash().String())
	}

	// Set the new chain tip.
	tq.bestHash = &blk.MsgBlock().Header.PrevBlock
	tq.bestHeight--

	height := blk.Height()
	delete(tq.keyedByHash, hash.String())
	delete(tq.keyedByHeight, height)

	tq.orphans[hash.String()] = blk

	return nil
}

func (tq *tChain) MainChainHasBlock(hash *chainhash.Hash) bool {
	tq.mtx.Lock()
	defer tq.mtx.Unlock()

	_, ok := tq.keyedByHash[hash.String()]
	return ok
}

func (tq *tChain) Best() (int64, *chainhash.Hash) {
	tq.mtx.Lock()
	defer tq.mtx.Unlock()

	return tq.bestHeight, tq.bestHash
}

func (tq *tChain) BlockHashByHeight(height int64) (*chainhash.Hash, error) {
	tq.mtx.Lock()
	defer tq.mtx.Unlock()

	blk := tq.keyedByHeight[height]
	if blk == nil {
		return nil, fmt.Errorf("no block found with height %d", height)
	}

	return blk.Hash(), nil
}

func (tq *tChain) BlockByHash(hash *chainhash.Hash) (*dcrutil.Block, error) {
	tq.mtx.Lock()
	defer tq.mtx.Unlock()

	blk := tq.keyedByHash[hash.String()]
	if blk == nil {
		blk = tq.orphans[hash.String()]
		if blk == nil {
			return nil, fmt.Errorf("no block found with hash %s", hash.String())
		}
	}

	return blk, nil
}

func (tq *tChain) PrevScripts(*dcrutil.Block) (PrevScripter, error) {
	return nil, nil
}

func TestTxIndex(t *testing.T) {
	dbPath, err := ioutil.TempDir("", "test_txindex")
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

	genesis := dcrutil.NewBlockDeepCopy(chaincfg.SimNetParams().GenesisBlock)
	chain, err := newTChain(genesis)
	if err != nil {
		t.Fatal(err)
	}

	g, err := chaingen.MakeGenerator(chaincfg.SimNetParams())
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	addBlock := func(blockName string, firstBlock bool) *dcrutil.Block {
		var blk *wire.MsgBlock
		if firstBlock {
			blk = g.CreateBlockOne(blockName, 0)
		} else {
			blk = g.NextBlock(blockName, nil, nil)
			g.SaveTipCoinbaseOuts()
		}

		return dcrutil.NewBlockDeepCopy(blk)
	}

	// Add three blocks to the chain.
	bk1 := addBlock("bk1", true)
	err = chain.AddBlock(bk1)
	if err != nil {
		t.Fatal(err)
	}

	bk2 := addBlock("bk2", false)
	err = chain.AddBlock(bk2)
	if err != nil {
		t.Fatal(err)
	}

	bk3 := addBlock("bk3", false)
	err = chain.AddBlock(bk3)
	if err != nil {
		t.Fatal(err)
	}

	// Initialize the tx index.
	pCtx, pCancel := context.WithCancel(context.Background())
	defer pCancel()

	subber := NewIndexSubscriber(pCtx)
	chainParams := chaincfg.SimNetParams()
	ctx, cancel := context.WithCancel(pCtx)
	idx, err := NewTxIndex(ctx, db, chain, chainParams, subber)
	if err != nil {
		t.Fatal(err)
	}

	// Ensure the index got synced to bk3 on initialization.
	tipHeight, tipHash, err := idx.Tip()
	if err != nil {
		t.Fatal(err)
	}

	if tipHeight != bk3.Height() {
		t.Fatalf("expected tip height to be %d, got %d", bk3.Height(), tipHeight)
	}

	if !tipHash.IsEqual(bk3.Hash()) {
		t.Fatalf("expected tip hash to be %s, got %s", bk3.Hash().String(),
			tipHash.String())
	}

	// Ensure the index remains in sync with the main chain when new
	// blocks are connected.
	bk4 := addBlock("bk4", false)
	err = chain.AddBlock(bk4)
	if err != nil {
		t.Fatal(err)
	}

	ntfn := &IndexNtfn{
		NtfnType:    ConnectNtfn,
		Block:       bk4,
		Parent:      bk3,
		PrevScripts: nil,
	}

	subber.Notify(ntfn)
	time.Sleep(time.Millisecond * 150)

	bk5 := addBlock("bk5", false)
	err = chain.AddBlock(bk5)
	if err != nil {
		t.Fatal(err)
	}

	ntfn = &IndexNtfn{
		NtfnType:    ConnectNtfn,
		Block:       bk5,
		Parent:      bk4,
		PrevScripts: nil,
	}
	subber.Notify(ntfn)
	time.Sleep(time.Millisecond * 150)

	// Ensure the index got synced to bk5.
	tipHeight, tipHash, err = idx.Tip()
	if err != nil {
		t.Fatal(err)
	}

	if tipHeight != bk5.Height() {
		t.Fatalf("expected tip height to be %d, got %d", bk5.Height(), tipHeight)
	}

	if !tipHash.IsEqual(bk5.Hash()) {
		t.Fatalf("expected tip hash to be %s, got %s", bk5.Hash().String(),
			tipHash.String())
	}

	// Simulate a reorg by setting bk4 as the main chain tip. bk5 is now
	// an orphan block.
	g.SetTip("bk4")
	err = chain.RemoveBlock(bk5)
	if err != nil {
		t.Fatal(err)
	}

	// Add bk5a to the main chain.
	bk5a := addBlock("bk5a", false)
	err = chain.AddBlock(bk5a)
	if err != nil {
		t.Fatal(err)
	}

	cancel()

	// Reinitialize the index.
	ctx, cancel = context.WithCancel(pCtx)
	idx, err = NewTxIndex(ctx, db, chain, chainParams, subber)
	if err != nil {
		t.Fatal(err)
	}

	tipHeight, tipHash, err = idx.Tip()
	if err != nil {
		t.Fatal(err)
	}

	// Ensure the index recovered to bk4 and synced back to the main chain tip
	// bk5a.
	if tipHeight != bk5a.Height() {
		t.Fatalf("expected tip height to be %d, got %d", bk5a.Height(), tipHeight)
	}

	if !tipHash.IsEqual(bk5a.Hash()) {
		t.Fatalf("expected tip hash to be %s, got %s", bk5a.Hash().String(),
			tipHash.String())
	}

	// Ensure bk5 is no longer indexed.
	entry, err := idx.Entry(bk5.Hash())
	if err != nil {
		t.Fatal(err)
	}

	if entry != nil {
		t.Fatal("expected no index entry for bk5")
	}

	// Ensure the index remains in sync when blocks are disconnected.
	err = chain.RemoveBlock(bk5a)
	if err != nil {
		t.Fatal(err)
	}

	g.SetTip("bk4")

	ntfn = &IndexNtfn{
		NtfnType:    DisconnectNtfn,
		Block:       bk5a,
		Parent:      bk4,
		PrevScripts: nil,
	}
	subber.Notify(ntfn)
	time.Sleep(time.Millisecond * 150)

	err = chain.RemoveBlock(bk4)
	if err != nil {
		t.Fatal(err)
	}

	g.SetTip("bk3")

	ntfn = &IndexNtfn{
		NtfnType:    DisconnectNtfn,
		Block:       bk4,
		Parent:      bk3,
		PrevScripts: nil,
	}
	subber.Notify(ntfn)
	time.Sleep(time.Millisecond * 150)

	// Ensure the index tip is now bk3 after the disconnections.
	tipHeight, tipHash, err = idx.Tip()
	if err != nil {
		t.Fatal(err)
	}

	if tipHeight != bk3.Height() {
		t.Fatalf("expected tip height to be %d, got %d", bk3.Height(), tipHeight)
	}

	if !tipHash.IsEqual(bk3.Hash()) {
		t.Fatalf("expected tip hash to be %s, got %s", bk3.Hash().String(),
			tipHash.String())
	}

	// Drop the index.
	err = idx.DropIndex(ctx, idx.db)
	if err != nil {
		t.Fatal(err)
	}

	cancel()

	// Reinitialize the index.
	ctx, cancel = context.WithCancel(pCtx)
	idx, err = NewTxIndex(ctx, db, chain, chainParams, subber)
	if err != nil {
		t.Fatal(err)
	}

	// Ensure the index got synced to bk3 on initialization.
	tipHeight, tipHash, err = idx.Tip()
	if err != nil {
		t.Fatal(err)
	}

	if tipHeight != bk3.Height() {
		t.Fatalf("expected tip height to be %d, got %d", bk3.Height(), tipHeight)
	}

	if !tipHash.IsEqual(bk3.Hash()) {
		t.Fatalf("expected tip hash to be %s, got %s", bk3.Hash().String(),
			tipHash.String())
	}

	// Add bk4a to the main chain.
	bk4a := addBlock("bk4a", false)
	err = chain.AddBlock(bk4a)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		// Stall the index notification for bk4a.
		time.Sleep(time.Millisecond * 150)
		ntfn = &IndexNtfn{
			NtfnType:    ConnectNtfn,
			Block:       bk4a,
			Parent:      bk3,
			PrevScripts: nil,
		}
		subber.Notify(ntfn)
	}()

	// Wait for the index to sync with the main chain before terminating.
	<-idx.WaitForSync()

	err = idx.sub.Stop()
	if err != nil {
		t.Fatal(err)
	}

	cancel()
}
