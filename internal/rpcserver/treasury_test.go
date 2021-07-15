// Copyright (c) 2020-2021 The Decred developers

// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package rpcserver

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/decred/dcrd/blockchain/stake/v4"
	"github.com/decred/dcrd/blockchain/standalone/v2"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/dcrec"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrutil/v4"
	"github.com/decred/dcrd/rpcclient/v7"
	"github.com/decred/dcrd/rpctest"
	"github.com/decred/dcrd/txscript/v4"
	"github.com/decred/dcrd/txscript/v4/sign"
	"github.com/decred/dcrd/txscript/v4/stdaddr"
	"github.com/decred/dcrd/wire"
)

// timeoutCtx returns a context with the given timeout and automatically calls
// cancel() if the test fails to clean up.
func timeoutCtx(t testing.TB, timeout time.Duration) context.Context {
	if timeout <= 0 {
		return context.Background()
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel)
	return ctx
}

type tspendPayout struct {
	address stdaddr.Address
	amount  dcrutil.Amount
}

func createTSpend(privKey []byte, payouts []tspendPayout, fee dcrutil.Amount, expiry uint32) *wire.MsgTx {
	// Calculate total payout.
	totalPayout := int64(0)
	for _, v := range payouts {
		totalPayout += int64(v.amount)
	}

	// OP_RETURN <8-byte ValueIn><24 byte random>
	payload := make([]byte, chainhash.HashSize)
	_, err := rand.Read(payload[8:])
	if err != nil {
		panic(err)
	}
	binary.LittleEndian.PutUint64(payload, uint64(totalPayout+int64(fee)))

	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_RETURN)
	builder.AddData(payload)
	opretScript, err := builder.Script()
	if err != nil {
		panic(err)
	}
	msgTx := wire.NewMsgTx()
	msgTx.Version = wire.TxVersionTreasury
	msgTx.Expiry = expiry
	msgTx.AddTxOut(wire.NewTxOut(0, opretScript))

	// OP_TGEN
	for _, v := range payouts {
		addr := v.address.(stdaddr.StakeAddress)
		genScriptVer, genScript := addr.PayFromTreasuryScript()
		msgTx.AddTxOut(newTxOut(int64(v.amount), genScriptVer, genScript))
	}

	// Treasury spend transactions have no inputs since the funds are
	// sourced from a special account, so previous outpoint is zero hash
	// and max index.
	msgTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: *wire.NewOutPoint(&chainhash.Hash{},
			wire.MaxPrevOutIndex, wire.TxTreeRegular),
		Sequence:        wire.MaxTxInSequenceNum,
		ValueIn:         int64(fee) + totalPayout,
		BlockHeight:     wire.NullBlockHeight,
		BlockIndex:      wire.NullBlockIndex,
		SignatureScript: nil,
	})

	// Calculate TSpend signature without SigHashType.
	sigscript, err := sign.TSpendSignatureScript(msgTx, privKey)
	if err != nil {
		panic(err)
	}
	msgTx.TxIn[0].SignatureScript = sigscript

	return msgTx
}

func createTAdd(t testing.TB, privKey []byte, prevOut *wire.OutPoint, pkScript []byte,
	amountIn, amountOut, fee dcrutil.Amount,
	changeAddr stdaddr.StakeAddress) *wire.MsgTx {

	tx := wire.NewMsgTx()
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: *prevOut,
		Sequence:         wire.MaxTxInSequenceNum,
		ValueIn:          int64(amountIn),
	})

	changeScriptVer, changeScript := changeAddr.StakeChangeScript()
	changeAmount := amountIn - amountOut - fee
	tx.AddTxOut(wire.NewTxOut(int64(amountOut), []byte{txscript.OP_TADD}))
	if changeAmount > 0 {
		tx.AddTxOut(newTxOut(int64(changeAmount), changeScriptVer, changeScript))
	}
	tx.Version = wire.TxVersionTreasury

	sig, err := sign.SignatureScript(tx, 0, pkScript, txscript.SigHashAll,
		privKey, dcrec.STEcdsaSecp256k1, true)
	if err != nil {
		t.Fatalf("unable to generate sig: %v", err)
	}
	tx.TxIn[0].SignatureScript = sig

	return tx
}

// assertTSpendVoteCount verifies that the given tspend shows up and has the
// specified vote counts when requesting the current vote counts for mempool
// tspends in the given node.
//
// If the reqSpecific check is specified, then only the vote counts for this
// specific tspend are requested from the backend node, which allows fetching
// vote counts even if the tspend has already been mined.
func assertTSpendVoteCount(t *testing.T, node *rpcclient.Client, tspend *wire.MsgTx, reqSpecific bool, yesVotes, noVotes int64) {
	t.Helper()

	txh := tspend.TxHash()
	var reqTSpends []*chainhash.Hash
	if reqSpecific {
		reqTSpends = []*chainhash.Hash{&txh}
		time.Sleep(time.Second * 3)
	}

	res, err := node.GetTreasurySpendVotes(timeoutCtx(t, time.Second*5), nil, reqTSpends)
	if err != nil {
		t.Fatalf("unable to query node for tspend votes: %v", err)
	}

	found := false
	for _, tsVote := range res.Votes {
		if txh.String() != tsVote.Hash {
			continue
		}
		found = true

		if tsVote.YesVotes != yesVotes {
			t.Fatalf("unexpected nb of yes votes. want %d, got=%d",
				yesVotes, tsVote.YesVotes)
		}
		if tsVote.NoVotes != noVotes {
			t.Fatalf("unexpected nb of no votes. want %d, got %d",
				noVotes, tsVote.NoVotes)
		}
	}

	if !found {
		t.Fatalf("could not find tspend %s in gettreasuryspendvotes "+
			"response %v", txh, res)
	}
}

// assertTBaseAmount verifies the treasury base output amount for the tip block
// equals the given value.
func assertTBaseAmount(t *testing.T, node *rpcclient.Client, amount int64) {
	t.Helper()

	bh, _, err := node.GetBestBlock(timeoutCtx(t, time.Second))
	if err != nil {
		t.Fatalf("unable to get best block hash: %v", err)
	}
	bl, err := node.GetBlock(timeoutCtx(t, time.Second), bh)
	if err != nil {
		t.Fatalf("unable to get block: %v", err)
	}
	tbase := bl.STransactions[0]
	if err := stake.CheckTreasuryBase(tbase); err != nil {
		t.Fatalf("stransactions[0] is not a treasury base: %v", err)
	}
	if tbase.TxOut[0].Value != amount {
		t.Fatalf("unexpected tbase amount. want=%d got=%d", amount,
			tbase.TxOut[0].Value)
	}
}

// TestTreasury performs a test of treasury functionality across the entire
// dcrd stack.
func TestTreasury(t *testing.T) {
	var handlers *rpcclient.NotificationHandlers
	net := chaincfg.SimNetParams()

	defaultFeeRate := dcrutil.Amount(1e4)

	// Setup the log dir for tests to ease debugging after failures.
	logDir := ".dcrdlogs"
	extraArgs := []string{
		"--rejectnonstd",
		"--debuglevel=MINR=trace,TRSY=trace",
		"--logdir=" + logDir,
	}
	info, err := os.Stat(logDir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("error stating log dir: %v", err)
	}
	if info != nil {
		if !info.IsDir() {
			t.Fatalf("logdir (%s) is not a dir", logDir)
		}
		err = os.RemoveAll(logDir)
		if err != nil {
			t.Fatalf("error removing logdir: %v", err)
		}
	}

	// Create the rpctest harness and mine outputs for the voting wallet to
	// use.
	hn, err := rpctest.New(t, net, handlers, extraArgs)
	if err != nil {
		t.Fatal(err)
	}
	err = hn.SetUp(false, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer hn.TearDown()
	_, err = rpctest.AdjustedSimnetMiner(timeoutCtx(t, time.Minute), hn.Node, 64)
	if err != nil {
		t.Fatal(err)
	}

	// Create the voting wallet.
	vw, err := rpctest.NewVotingWallet(context.Background(), hn)
	if err != nil {
		t.Fatalf("unable to create voting wallet for test: %v", err)
	}
	err = vw.Start()
	if err != nil {
		t.Fatalf("unable to setup voting wallet: %v", err)
	}
	vw.SetErrorReporting(func(vwerr error) {
		t.Fatalf("voting wallet errored: %v", vwerr)
	})
	vw.SetMiner(func(ctx context.Context, nb uint32) ([]*chainhash.Hash, error) {
		return rpctest.AdjustedSimnetMiner(ctx, hn.Node, nb)
	})

	// Create a privkey and p2pkh addr we control for use in the tests.
	privKey := secp256k1.NewPrivateKey(new(secp256k1.ModNScalar).SetInt(1))
	pubKey := privKey.PubKey().SerializeCompressed()
	pubKeyHash := stdaddr.Hash160(pubKey)
	p2pkhAddr, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(pubKeyHash,
		net)
	if err != nil {
		t.Fatal(err)
	}
	p2pkhScriptVer, p2pkhScript := p2pkhAddr.PaymentScript()

	// Generate a p2sh script and addr we control for use in the tests.
	redeemScript := []byte{txscript.OP_TRUE}
	p2shSigScript := []byte{txscript.OP_DATA_1, txscript.OP_TRUE}
	p2shAddr, err := stdaddr.NewAddressScriptHashV0(redeemScript, net)
	if err != nil {
		t.Fatal(err)
	}

	// Send funds to outputs we control so we can spend it on TAdds.
	nbTAddPrevOuts := 3
	taddInAmt := dcrutil.Amount(1e8) // 1 DCR
	taddPrevOuts := make([]*wire.OutPoint, nbTAddPrevOuts)
	for i := 0; i < nbTAddPrevOuts; i++ {
		txOut := newTxOut(int64(taddInAmt), p2pkhScriptVer, p2pkhScript)
		txHash, err := hn.SendOutputs([]*wire.TxOut{txOut}, defaultFeeRate)
		if err != nil {
			t.Fatal(err)
		}
		taddPrevOuts[i] = &wire.OutPoint{Hash: *txHash}
	}

	// Advance until SVH.
	_, startHeight, err := hn.Node.GetBestBlock(timeoutCtx(t, time.Second))
	if err != nil {
		t.Fatalf("unable to obtain best block: %v", err)
	}
	targetHeight := net.StakeValidationHeight
	if targetHeight > startHeight {
		nbBlocks := uint32(targetHeight - startHeight)
		_, err = vw.GenerateBlocks(timeoutCtx(t, 5*time.Minute), nbBlocks)
		if err != nil {
			t.Fatalf("unable to mine to SVH: %v", err)
		}
	}

	// Shorter versions of useful params for convenience.
	tvi := net.TreasuryVoteInterval
	mul := net.TreasuryVoteIntervalMultiplier
	piKey, _ := hex.DecodeString("62deae1ab2b1ebd96a28c80e870aee325bed359e83d8db2464ef999e616a9eef")

	// Create a TSpend that pays to a privkey we control and to a P2SH
	// address we know how to redeem.
	expiry := standalone.CalcTSpendExpiry(targetHeight+1, tvi, mul)
	tspendFee := dcrutil.Amount(5190)
	tspendAmount := dcrutil.Amount(7e8) // 7 DCR
	payouts := []tspendPayout{
		{address: p2pkhAddr, amount: tspendAmount},
		{address: p2shAddr, amount: tspendAmount},
	}
	tspendYes := createTSpend(piKey, payouts, tspendFee, expiry)

	// Create a tspend that will be disapproved (voted no).
	tspendNo := createTSpend(piKey, payouts, tspendFee, expiry)

	// Create a tspend that will never be voted, therefore shouldn't be
	// mined.
	tspendAbstain := createTSpend(piKey, payouts, tspendFee, expiry)

	// Create a very large tspend that will be approved but shouldn't be
	// mined due to spending more than allowed by the expenditure policy.
	largeAmount := dcrutil.Amount(30000e8)
	largePayout := []tspendPayout{{address: p2pkhAddr, amount: largeAmount}}
	tspendLarge := createTSpend(piKey, largePayout, tspendFee, expiry)

	// Create a TAdd that pays the change back to a privkey we control.
	taddFee := dcrutil.Amount(2550)
	taddChange := taddInAmt - taddInAmt/2 - taddFee
	tadd1 := createTAdd(t, privKey.Serialize(), taddPrevOuts[0], p2pkhScript, taddInAmt,
		taddInAmt/2, taddFee, p2pkhAddr)
	tadd1Hash := tadd1.TxHash()

	// Create a TAdd that pays the change back to a p2sh we control.
	tadd2 := createTAdd(t, privKey.Serialize(), taddPrevOuts[1], p2pkhScript, taddInAmt,
		taddInAmt/2, taddFee, p2shAddr)
	tadd2Hash := tadd2.TxHash()

	// Create a TAdd that doesn't have change.
	tadd3 := createTAdd(t, privKey.Serialize(), taddPrevOuts[2], p2pkhScript, taddInAmt,
		taddInAmt-taddFee, taddFee, p2pkhAddr)
	if len(tadd3.TxOut) > 1 {
		t.Fatalf("tadd3 should not have had change")
	}

	// Set the voting wallet to vote for our tspends.
	tspendYesHash := tspendYes.TxHash()
	tspendNoHash := tspendNo.TxHash()
	tspendLargeHash := tspendLarge.TxHash()
	vw.VoteForTSpends([]*stake.TreasuryVoteTuple{
		{Hash: tspendYesHash, Vote: stake.TreasuryVoteYes},
		{Hash: tspendNoHash, Vote: stake.TreasuryVoteNo},
		{Hash: tspendLargeHash, Vote: stake.TreasuryVoteYes},
	})

	// Publish the tspends so the node will include them once they're
	// approved.
	txs := []*wire.MsgTx{tspendYes, tspendNo, tspendLarge, tspendAbstain}
	for i, tx := range txs {
		_, err = hn.Node.SendRawTransaction(timeoutCtx(t, time.Second), tx, true)
		if err != nil {
			t.Fatalf("unable to publish tspend %d: %v", i, err)
		}
	}

	// The vote counts for the tspends should be empty.
	assertTSpendVoteCount(t, hn.Node, tspendYes, false, 0, 0)
	assertTSpendVoteCount(t, hn.Node, tspendNo, false, 0, 0)
	assertTSpendVoteCount(t, hn.Node, tspendLarge, false, 0, 0)
	assertTSpendVoteCount(t, hn.Node, tspendAbstain, false, 0, 0)

	// Generate one TVI worth of blocks to start voting then TVI*2 blocks
	// to approve but stop just before the tspend will be mined.
	nbBlocks := uint32(tvi + tvi*2 - 1)
	_, err = vw.GenerateBlocks(timeoutCtx(t, time.Minute), nbBlocks)
	if err != nil {
		t.Fatalf("unable to mine to blocks to approve tspend: %v", err)
	}

	// The vote counts for the tspends should correspond to the max
	// possible for the amount of mined blocks.
	maxVotes := int64(tvi * 2 * 5)
	assertTSpendVoteCount(t, hn.Node, tspendYes, false, maxVotes, 0)
	assertTSpendVoteCount(t, hn.Node, tspendNo, false, 0, maxVotes)
	assertTSpendVoteCount(t, hn.Node, tspendLarge, false, maxVotes, 0)
	assertTSpendVoteCount(t, hn.Node, tspendAbstain, false, 0, 0)

	// Publish the tadds so both the tspend and tadds are mined at the same
	// block.
	txs = []*wire.MsgTx{tadd1, tadd2, tadd3}
	for i, tx := range txs {
		_, err = hn.Node.SendRawTransaction(timeoutCtx(t, time.Second), tx, true)
		if err != nil {
			t.Fatalf("unable to publish tadd %d: %v", i, err)
		}
	}

	// Mine the tspend and tadds and then until their funds are mature and
	// spendable and their outputs are reflected in the treasury balance.
	nbBlocks = uint32(1 + net.CoinbaseMaturity + 1)
	_, err = vw.GenerateBlocks(timeoutCtx(t, time.Minute), nbBlocks)
	if err != nil {
		t.Fatalf("unable to mine to blocks to approve tspend: %v", err)
	}

	// Ensure vote counts for the mined tspend are fixed after it was
	// mined.
	assertTSpendVoteCount(t, hn.Node, tspendYes, true, maxVotes, 0)

	// The other tspends are still being voted.
	nbVotes := maxVotes + int64(nbBlocks*5)
	assertTSpendVoteCount(t, hn.Node, tspendNo, false, 0, nbVotes)
	assertTSpendVoteCount(t, hn.Node, tspendLarge, false, nbVotes, 0)
	assertTSpendVoteCount(t, hn.Node, tspendAbstain, false, 0, 0)

	// Create a tx that spends from the TSPend outputs and the TAdd change
	// outputs.
	tx := wire.NewMsgTx()
	txFee := dcrutil.Amount(5550)
	tx.AddTxIn(&wire.TxIn{ // TSpend P2PKH output
		PreviousOutPoint: wire.OutPoint{
			Hash:  tspendYesHash,
			Index: 1,
			Tree:  1,
		},
		Sequence: wire.MaxTxInSequenceNum,
		ValueIn:  int64(tspendAmount),
	})
	tx.AddTxIn(&wire.TxIn{ // TSpend P2SH output
		PreviousOutPoint: wire.OutPoint{
			Hash:  tspendYesHash,
			Index: 2,
			Tree:  1,
		},
		Sequence:        wire.MaxTxInSequenceNum,
		ValueIn:         int64(tspendAmount),
		SignatureScript: p2shSigScript,
	})
	tx.AddTxIn(&wire.TxIn{ // TAdd P2PKH output
		PreviousOutPoint: wire.OutPoint{
			Hash:  tadd1Hash,
			Index: 1,
			Tree:  1,
		},
		Sequence: wire.MaxTxInSequenceNum,
		ValueIn:  int64(taddChange),
	})
	tx.AddTxIn(&wire.TxIn{ // TAdd P2SH output
		PreviousOutPoint: wire.OutPoint{
			Hash:  tadd2Hash,
			Index: 1,
			Tree:  1,
		},
		Sequence:        wire.MaxTxInSequenceNum,
		ValueIn:         int64(taddChange),
		SignatureScript: p2shSigScript,
	})
	tx.AddTxOut(&wire.TxOut{
		Version:  0,
		Value:    int64(tspendAmount + taddChange - txFee),
		PkScript: p2pkhScript,
	})

	// Generate signatures for the P2PKH inputs.
	sig, err := sign.SignatureScript(tx, 0, tspendYes.TxOut[1].PkScript,
		txscript.SigHashAll, privKey.Serialize(), dcrec.STEcdsaSecp256k1, true)
	if err != nil {
		t.Fatalf("unable to generate sig: %v", err)
	}
	tx.TxIn[0].SignatureScript = sig

	sig, err = sign.SignatureScript(tx, 2, tadd1.TxOut[1].PkScript,
		txscript.SigHashAll, privKey.Serialize(), dcrec.STEcdsaSecp256k1, true)
	if err != nil {
		t.Fatalf("unable to generate sig: %v", err)
	}
	tx.TxIn[2].SignatureScript = sig

	// Publish the spending tx.
	spendTxHash, err := hn.Node.SendRawTransaction(timeoutCtx(t, time.Second), tx, true)
	if err != nil {
		t.Fatalf("unable to publish spend tx: %v", err)
	}

	// Mine it and keep track of running number of votes issued.
	_, err = vw.GenerateBlocks(timeoutCtx(t, time.Minute), 1)
	if err != nil {
		t.Fatalf("unable to mine to blocks to approve tspend: %v", err)
	}
	nbVotes += 5

	// Ensure the spending tx output is part of the utxo set and has 1
	// confirmation.
	utxo, err := hn.Node.GetTxOut(timeoutCtx(t, time.Second), spendTxHash, 0,
		wire.TxTreeRegular, false)
	if err != nil {
		t.Fatalf("unable to fetch spend tx utxo: %v", err)
	}
	if utxo.Confirmations != 1 {
		t.Fatalf("unexpected confirmations in spend tx utxo. want=%d got=%d",
			1, utxo.Confirmations)
	}

	// Ensure the disapproved, large and abstained tspend outputs are not
	// part of the utxo set (i.e. they were not mined).
	tspendAbstainHash := tspendAbstain.TxHash()
	hashes := []*chainhash.Hash{&tspendLargeHash, &tspendNoHash, &tspendAbstainHash}
	for i, h := range hashes {
		utxo, err = hn.Node.GetTxOut(timeoutCtx(t, time.Second), h, 1,
			wire.TxTreeRegular, false)
		if err != nil {
			t.Fatalf("unable to fetch tspend %d utxo: %v", i, err)
		}
		if utxo != nil {
			t.Fatalf("unexpected confirmations in tspend %d utxo: %v",
				i, utxo)
		}
	}

	// Fetch current block for tbase calculation.
	_, height, err := hn.Node.GetBestBlock(timeoutCtx(t, time.Second))
	if err != nil {
		t.Fatalf("unable to obtain best block: %v", err)
	}

	// Calculate the final expected treasury balance. It should be:
	//      Sum(treasury bases)
	//    + tadd1 amount - tadd1 change - tadd fees   ; p2pkh tadd
	//    + tadd2 amount - tadd2 change - tadd fees   ; p2sh tadd
	//    + tadd3 amount - tadd fees                  ; changeless tadd
	//    - tspend amount                             ; p2pkh out
	//    - tspend amount                             ; p2sh out
	//    - tspend fee
	//
	// Note that since we mine a lot of blocks, we've likely passed subsidy
	// reduction intervals, so we need to account for that when summing
	// treasury bases.

	// Calculate sum of treasurybases. Loop through all subsidy reduction
	// intervals until the last block that affected the treasury balance.
	var tbaseTotal dcrutil.Amount
	lastMatureTbaseBlock := height - int64(net.CoinbaseMaturity) + 1
	subsidy := net.BaseSubsidy
	tbaseSubsidy := subsidy * int64(net.BlockTaxProportion) /
		int64(net.TotalSubsidyProportions())
	sri := net.SubsidyReductionInterval
	for i := int64(0); i < lastMatureTbaseBlock; {
		nbBlocks := sri
		if i == 0 {
			// First SRI needs to ignore blocks 0 and 1 which don't
			// have treasury base.
			nbBlocks -= 2
		}
		if i+nbBlocks > lastMatureTbaseBlock {
			// On the last interval we only sum up to the last
			// mature tbase block.
			nbBlocks = lastMatureTbaseBlock % sri
		}
		tbaseTotal += dcrutil.Amount(nbBlocks * tbaseSubsidy)
		i += sri
		if i >= lastMatureTbaseBlock {
			// Quit early so tbaseSubsidy still contains the most
			// recent tbase subsidy amount.
			break
		}
		subsidy = subsidy * net.MulSubsidy / net.DivSubsidy
		tbaseSubsidy = subsidy * int64(net.BlockTaxProportion) /
			int64(net.TotalSubsidyProportions())
	}

	// Calculate the final expected balance
	wantBalance := tbaseTotal +
		taddInAmt - taddChange - taddFee + // p2pkh tadd
		taddInAmt - taddChange - taddFee + // p2sh tadd
		taddInAmt - taddFee + // tadd without change
		-tspendAmount*2 - tspendFee // p2pkh+p2sh tspend
	bal, err := hn.Node.GetTreasuryBalance(timeoutCtx(t, time.Second), nil, false)
	if err != nil {
		t.Fatalf("unable to get treasury balance: %v", err)
	}
	gotBalance := dcrutil.Amount(bal.Balance)
	if gotBalance != wantBalance {
		t.Logf("height %d", height)
		t.Logf("tbaseTotal %s   taddInAmt %d   taddChange   %d",
			tbaseTotal, taddInAmt, taddChange)
		t.Logf("taddFee %d   tspendAmount %d   tspendFee %d",
			taddFee, tspendAmount, tspendFee)
		t.Fatalf("unexpected treasury balance. want=%s got=%s",
			wantBalance, gotBalance)
	}

	// We'll now test that when casting less than the total amount of votes
	// on the network the correct treasury base and vote counts are still
	// generated.
	//
	// First limit the number of votes to 4, then generate a block so that
	// the _next_ block has only 4 votes. Keep track of the total number of
	// tspend votes issued.
	if err := vw.LimitNbVotes(4); err != nil {
		t.Fatal(err)
	}
	if _, err := vw.GenerateBlocks(timeoutCtx(t, time.Minute), 1); err != nil {
		t.Fatal(err)
	}
	nbVotes += 5

	// Generate a block with 4 votes and assert the treasury base and vote
	// counts are correct.
	//
	// We also limit the total number of votes to 3 so that the _next_ test
	// can be done.
	if err := vw.LimitNbVotes(3); err != nil {
		t.Fatal(err)
	}
	if _, err := vw.GenerateBlocks(timeoutCtx(t, time.Minute), 1); err != nil {
		t.Fatal(err)
	}
	assertTBaseAmount(t, hn.Node, tbaseSubsidy)
	nbVotes = nbVotes + int64(4)
	assertTSpendVoteCount(t, hn.Node, tspendNo, false, 0, nbVotes)
	assertTSpendVoteCount(t, hn.Node, tspendLarge, false, nbVotes, 0)

	// Generate a block with 3 votes and assert the treasury base and vote
	// counts are correct.
	if err := vw.LimitNbVotes(3); err != nil {
		t.Fatal(err)
	}
	if _, err := vw.GenerateBlocks(timeoutCtx(t, time.Minute), 1); err != nil {
		t.Fatal(err)
	}
	nbVotes = nbVotes + int64(3)
	assertTBaseAmount(t, hn.Node, tbaseSubsidy)
	assertTSpendVoteCount(t, hn.Node, tspendNo, false, 0, nbVotes)
	assertTSpendVoteCount(t, hn.Node, tspendLarge, false, nbVotes, 0)
}
