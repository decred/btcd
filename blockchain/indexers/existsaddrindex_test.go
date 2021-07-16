package indexers

import (
	"context"
	"testing"
	"time"

	"github.com/decred/dcrd/blockchain/v4/chaingen"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/txscript/v4"
)

// TestExistsAddrIndexAsync ensures the exist address index
// behaves as expected when receiving updates asynchronously.
func TestExistsAddrIndexAsync(t *testing.T) {
	db, path := setupDB(t, "test_existsaddrindex")
	defer teardownDB(db, path)

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

	// Initialize the exists address index.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	subber := NewIndexSubscriber(ctx)
	go subber.Run(ctx)

	idx, err := NewExistsAddrIndex(subber, db, chain)
	if err != nil {
		t.Fatal(err)
	}

	err = subber.CatchUp(ctx, db, chain)
	if err != nil {
		t.Fatal(err)
	}

	// Ensure the index got synced to bk3 on initialization.
	tipHeight, tipHash, err := idx.Tip()
	if err != nil {
		t.Fatal(err)
	}

	if tipHeight != bk3.Height() {
		t.Fatalf("expected tip height to be %d, got %d",
			bk3.Height(), tipHeight)
	}

	if *tipHash != *bk3.Hash() {
		t.Fatalf("expected tip hash to be %s, got %s",
			bk3.Hash().String(), tipHash.String())
	}

	// Ensure the index remains in sync with the main chain when new
	// blocks are connected.
	bk4 := addBlock(t, chain, &g, "bk4")
	ntfn := &IndexNtfn{
		NtfnType:    ConnectNtfn,
		Block:       bk4,
		Parent:      bk3,
		PrevScripts: nil,
	}
	notifyAndWait(t, subber, ntfn)

	bk5 := addBlock(t, chain, &g, "bk5")
	ntfn = &IndexNtfn{
		NtfnType:    ConnectNtfn,
		Block:       bk5,
		Parent:      bk4,
		PrevScripts: nil,
	}
	notifyAndWait(t, subber, ntfn)

	// Ensure the index got synced to bk5.
	tipHeight, tipHash, err = idx.Tip()
	if err != nil {
		t.Fatal(err)
	}

	if tipHeight != bk5.Height() {
		t.Fatalf("expected tip height to be %d, got %d",
			bk5.Height(), tipHeight)
	}

	if *tipHash != *bk5.Hash() {
		t.Fatalf("expected tip hash to be %s, got %s",
			bk5.Hash().String(), tipHash.String())
	}

	isTreasuryEnabled, err := idx.chain.IsTreasuryAgendaActive(bk5.Hash())
	if err != nil {
		t.Fatal(err)
	}

	// Fetch the first address paid to by bk5's coinbase.
	out := bk5.MsgBlock().Transactions[0].TxOut[0]
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(out.Version, out.PkScript,
		idx.chain.ChainParams(), isTreasuryEnabled)
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
	bk5a := addBlock(t, chain, &g, "bk5a")

	// Resubscribe the index.
	err = idx.sub.stop()
	if err != nil {
		t.Fatal(err)
	}

	idx, err = NewExistsAddrIndex(subber, db, chain)
	if err != nil {
		t.Fatal(err)
	}

	err = subber.CatchUp(ctx, db, chain)
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
		t.Fatalf("expected tip height to be %d, got %d",
			bk5a.Height(), tipHeight)
	}

	if *tipHash != *bk5a.Hash() {
		t.Fatalf("expected tip hash to be %s, got %s",
			bk5a.Hash().String(), tipHash.String())
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
	notifyAndWait(t, subber, ntfn)

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
	notifyAndWait(t, subber, ntfn)

	// Ensure the index tip is now bk3 after the disconnections.
	tipHeight, tipHash, err = idx.Tip()
	if err != nil {
		t.Fatal(err)
	}

	if tipHeight != bk3.Height() {
		t.Fatalf("expected tip height to be %d, got %d",
			bk3.Height(), tipHeight)
	}

	if *tipHash != *bk3.Hash() {
		t.Fatalf("expected tip hash to be %s, got %s",
			bk3.Hash().String(), tipHash.String())
	}

	// Drop the index.
	err = idx.DropIndex(ctx, idx.db)
	if err != nil {
		t.Fatal(err)
	}

	// Resubscribe the index.
	err = idx.sub.stop()
	if err != nil {
		t.Fatal(err)
	}

	idx, err = NewExistsAddrIndex(subber, db, chain)
	if err != nil {
		t.Fatal(err)
	}

	err = subber.CatchUp(ctx, db, chain)
	if err != nil {
		t.Fatal(err)
	}

	// Ensure the index got synced to bk3 on initialization.
	tipHeight, tipHash, err = idx.Tip()
	if err != nil {
		t.Fatal(err)
	}

	if tipHeight != bk3.Height() {
		t.Fatalf("expected tip height to be %d, got %d",
			bk3.Height(), tipHeight)
	}

	if *tipHash != *bk3.Hash() {
		t.Fatalf("expected tip hash to be %s, got %s",
			bk3.Hash().String(), tipHash.String())
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

	// Wait for the index to sync with the main chain before terminating.
	select {
	case <-idx.WaitForSync():
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
	tipHeight, tipHash, err = idx.Tip()
	if err != nil {
		t.Fatal(err)
	}

	if tipHeight != bk4a.Height() {
		t.Fatalf("expected tip height to be %d, got %d",
			bk4a.Height(), tipHeight)
	}

	if *tipHash != *bk4a.Hash() {
		t.Fatalf("expected tip hash to be %s, got %s",
			bk4a.Hash().String(), tipHash.String())
	}
}
