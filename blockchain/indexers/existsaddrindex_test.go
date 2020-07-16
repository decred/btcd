package indexers

import (
	"context"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/decred/dcrd/blockchain/v3/chaingen"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/database/v2"
	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/dcrd/txscript/v3"
	"github.com/decred/dcrd/wire"
)

func TestExistAddrIndex(t *testing.T) {
	dbPath, err := ioutil.TempDir("", "test_existsaddrindex")
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
	idx, err := NewExistsAddrIndex(ctx, db, chain, chainParams, subber)
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

	// Fetch the first address paid to by bk5's coinbase.
	out := bk5.MsgBlock().Transactions[0].TxOut[0]
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(out.Version, out.PkScript,
		idx.chainParams)
	if err != nil {
		t.Fatal(err)
	}

	// Ensure index has the first address paid to by bk5's coinbase indexed.
	indexed, err := idx.ExistsAddress(addrs[0])
	if err != nil {
		t.Fatal(err)
	}

	if !indexed {
		t.Fatalf("expected %s to be indexed", addrs[0].String())
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
	idx, err = NewExistsAddrIndex(ctx, db, chain, chainParams, subber)
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

	// Ensure the index still has the first address paid to by bk5's
	// coinbase indexed after its disconnection.
	indexed, err = idx.ExistsAddress(addrs[0])
	if err != nil {
		t.Fatal(err)
	}

	if !indexed {
		t.Fatalf("expected %s to be indexed", addrs[0].String())
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
	idx, err = NewExistsAddrIndex(ctx, db, chain, chainParams, subber)
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
