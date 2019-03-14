// Copyright (c) 2018 The btcsuite developers
// Copyright (c) 2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package simpleregtest

import (
	"testing"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrd/integration/harness"
	"github.com/decred/dcrd/txscript"
	"github.com/decred/dcrd/wire"
)

func genSpend(t *testing.T, r *harness.Harness, amt dcrutil.Amount) *chainhash.Hash {
	// Grab a fresh address from the wallet.
	addr, err := r.Wallet.NewAddress(&harness.NewAddressArgs{"default"})
	if err != nil {
		t.Fatalf("unable to get new address: %v", err)
	}

	// Next, send amt to this address, spending from one of our
	// mature coinbase outputs.
	addrScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatalf("unable to generate pkscript to addr: %v", err)
	}
	output := wire.NewTxOut(int64(amt), addrScript)
	txid, err := r.Wallet.SendOutputs([]*wire.TxOut{output}, 10)
	if err != nil {
		t.Fatalf("coinbase spend failed: %v", err)
	}
	return txid
}

func assertTxMined(t *testing.T, r *harness.Harness, txid *chainhash.Hash, blockHash *chainhash.Hash) {
	block, err := r.NodeRPCClient().GetBlock(blockHash)
	if err != nil {
		t.Fatalf("unable to get block: %v", err)
	}

	numBlockTxns := len(block.Transactions)
	if numBlockTxns < 2 {
		t.Fatalf("crafted transaction wasn't mined, block should have "+
			"at least %v transactions instead has %v", 2, numBlockTxns)
	}

	txHash1 := block.Transactions[1].TxHash()

	if txHash1 != *txid {
		t.Fatalf("txid's don't match, %v vs %v", txHash1, txid)
	}
}

func TestBallance(t *testing.T) {
	// Skip tests when running with -short
	//if testing.Short() {
	//	t.Skip("Skipping RPC harness tests in short mode")
	//}
	r := ObtainHarness(t.Name() + ".8")

	expectedBalance := dcrutil.Amount(7200 * dcrutil.AtomsPerCoin)
	actualBalance := r.Wallet.ConfirmedBalance()

	if actualBalance != expectedBalance {
		t.Fatalf("expected wallet balance of %v instead have %v",
			expectedBalance, actualBalance)
	}
}

func TestSendOutputs(t *testing.T) {
	// Skip tests when running with -short
	//if testing.Short() {
	//	t.Skip("Skipping RPC harness tests in short mode")
	//}
	r := ObtainHarness("TestSendOutputs")
	r.Wallet.Sync()
	// First, generate a small spend which will require only a single
	// input.
	txid := genSpend(t, r, dcrutil.Amount(5*dcrutil.AtomsPerCoin))

	// Generate a single block, the transaction the wallet created should
	// be found in this block.
	blockHashes, err := r.NodeRPCClient().Generate(1)
	if err != nil {
		t.Fatalf("unable to generate single block: %v", err)
	}
	assertTxMined(t, r, txid, blockHashes[0])

	// Next, generate a spend much greater than the block reward. This
	// transaction should also have been mined properly.
	txid = genSpend(t, r, dcrutil.Amount(1000*dcrutil.AtomsPerCoin))
	blockHashes, err = r.NodeRPCClient().Generate(1)
	if err != nil {
		t.Fatalf("unable to generate single block: %v", err)
	}
	assertTxMined(t, r, txid, blockHashes[0])

	// Generate another block to ensure the transaction is removed from the
	// mempool.
	if _, err := r.NodeRPCClient().Generate(1); err != nil {
		t.Fatalf("unable to generate block: %v", err)
	}
}
