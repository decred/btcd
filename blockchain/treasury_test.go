// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/decred/dcrd/blockchain/stake/v4"
	"github.com/decred/dcrd/blockchain/standalone/v2"
	"github.com/decred/dcrd/blockchain/v4/chaingen"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/database/v2"
	"github.com/decred/dcrd/dcrec"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrutil/v4"
	"github.com/decred/dcrd/gcs/v3/blockcf2"
	"github.com/decred/dcrd/lru"
	"github.com/decred/dcrd/txscript/v4"
	"github.com/decred/dcrd/txscript/v4/sign"
	"github.com/decred/dcrd/txscript/v4/stdaddr"
	"github.com/decred/dcrd/wire"
)

var (
	// These keys come from chaincfg/regnetparams.go
	privKey  = hexToBytes("68ab7efdac0eb99b1edf83b23374cc7a9c8d0a4183a2627afc8ea0437b20589e")
	privKey2 = hexToBytes("2527f13f61024c9b9f4b30186f16e0b0af35b08c54ed2ed67def863b447ea11b")
)

// TestTreasuryStateSerialization ensures serializing and deserializing treasury
// states works as expected, including the possible error conditions.
func TestTreasuryStateSerialization(t *testing.T) {
	tests := []struct {
		name       string
		state      *treasuryState
		serialized []byte
		encodeErr  error
		decodeErr  error
	}{{
		name: "equal",
		state: &treasuryState{
			balance: 100,
			values: []treasuryValue{
				{treasuryValueTBase, 1},
				{treasuryValueTAdd, 2},
				{treasuryValueTAdd, 3},
				{treasuryValueTSpend, -3},
				{treasuryValueFee, -2},
			},
		},
		serialized: hexToBytes("640501010202020304030302"),
	}, {
		name: "negative balance",
		state: &treasuryState{
			balance: -100,
			values: []treasuryValue{
				{treasuryValueTBase, 1},
				{treasuryValueTAdd, 2},
				{treasuryValueTAdd, 3},
				{treasuryValueTSpend, -3},
				{treasuryValueFee, -2},
			},
		},
		encodeErr: errDbTreasury(""),
		decodeErr: errDeserialize(""),
	}, {
		name:       "empty data",
		state:      nil,
		serialized: hexToBytes(""),
		decodeErr:  errDeserialize(""),
	}, {
		name:       "no data after balance",
		state:      nil,
		serialized: hexToBytes("64"),
		decodeErr:  errDeserialize(""),
	}, {
		name:       "no data after num values",
		state:      nil,
		serialized: hexToBytes("6401"),
		decodeErr:  errDeserialize(""),
	}, {
		name:       "no data after first value",
		state:      nil,
		serialized: hexToBytes("640201"),
		decodeErr:  errDeserialize(""),
	}, {
		name: "trying to serialize incorrect negative tbase",
		state: &treasuryState{
			values: []treasuryValue{{typ: treasuryValueTBase, amount: -1}},
		},
		encodeErr:  errDbTreasury(""),
		serialized: nil,
		decodeErr:  errDeserialize(""),
	}, {
		name: "trying to serialize incorrect negative tadd",
		state: &treasuryState{
			values: []treasuryValue{{typ: treasuryValueTAdd, amount: -1}},
		},
		encodeErr:  errDbTreasury(""),
		serialized: nil,
		decodeErr:  errDeserialize(""),
	}, {
		name: "trying to serialize incorrect positive tspend",
		state: &treasuryState{
			values: []treasuryValue{{typ: treasuryValueTSpend, amount: 1}},
		},
		encodeErr:  errDbTreasury(""),
		serialized: nil,
		decodeErr:  errDeserialize(""),
	}, {
		name: "trying to serialize incorrect positive fee",
		state: &treasuryState{
			values: []treasuryValue{{typ: treasuryValueFee, amount: 1}},
		},
		encodeErr:  errDbTreasury(""),
		serialized: nil,
		decodeErr:  errDeserialize(""),
	}, {
		name: "serialize zero amounts for all value types",
		state: &treasuryState{
			balance: 100,
			values: []treasuryValue{
				{typ: treasuryValueTBase, amount: 0},
				{typ: treasuryValueTAdd, amount: 0},
				{typ: treasuryValueTSpend, amount: 0},
				{typ: treasuryValueFee, amount: 0},
			},
		},
		serialized: hexToBytes("64040100020004000300"),
	}}

	for _, test := range tests {
		// Ensure the serialized bytes are deserialized back to the expected
		// treasury state.
		gotState, err := deserializeTreasuryState(test.serialized)
		if !errors.Is(err, test.decodeErr) {
			t.Errorf("%s: mismatched err -- got %v, want %v", test.name, err,
				test.decodeErr)
			continue
		}
		if test.decodeErr == nil && !reflect.DeepEqual(gotState, test.state) {
			t.Errorf("%s: mismatched states\ngot %+v\nwant %+v", test.name,
				gotState, test.state)
			continue
		}

		// Skip serialization tests for nil states.
		if test.state == nil {
			continue
		}

		// Ensure the treasury state serializes to the expected value.
		gotSerialized, err := serializeTreasuryState(*test.state)
		if !errors.Is(err, test.encodeErr) {
			t.Errorf("%s: mismatched err -- got %v, want %v", test.name, err,
				test.encodeErr)
		}
		if !bytes.Equal(gotSerialized, test.serialized) {
			t.Errorf("%s: did not get expected bytes - got %x, want %x",
				test.name, gotSerialized, test.serialized)
			continue
		}
	}
}

// TestTreasuryDatabase tests treasury database functionality.
func TestTreasuryDatabase(t *testing.T) {
	// Create a new database to store treasury state.
	dbName := "ffldb_treasurydb_test"
	dbPath, err := ioutil.TempDir("", dbName)
	if err != nil {
		t.Fatalf("unable to create treasury db path: %v", err)
	}
	defer os.RemoveAll(dbPath)
	net := chaincfg.RegNetParams().Net
	testDb, err := database.Create(testDbType, dbPath, net)
	if err != nil {
		t.Fatalf("error creating treasury db: %v", err)
	}
	defer testDb.Close()

	// Add bucket.
	err = testDb.Update(func(dbTx database.Tx) error {
		_, err := dbTx.Metadata().CreateBucketIfNotExists(treasuryBucketName)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	// Write maxTreasuryState records out.
	maxTreasuryState := uint64(1024)
	for i := uint64(0); i < maxTreasuryState; i++ {
		// Create synthetic treasury state
		ts := treasuryState{
			balance: int64(i),
			values: []treasuryValue{
				{typ: treasuryValueTBase, amount: int64(i)},
				{typ: treasuryValueTSpend, amount: -1 - int64(i)},
			},
		}

		// Create hash of counter.
		b := make([]byte, 16)
		binary.LittleEndian.PutUint64(b[0:], i)
		hash := chainhash.HashH(b)

		err = testDb.Update(func(dbTx database.Tx) error {
			return dbPutTreasuryBalance(dbTx, hash, ts)
		})
		if err != nil {
			t.Fatalf("%v", err)
		}
	}

	// Pull records back out.
	for i := uint64(0); i < maxTreasuryState; i++ {
		// Create synthetic treasury state
		ts := treasuryState{
			balance: int64(i),
			values: []treasuryValue{
				{typ: treasuryValueTBase, amount: int64(i)},
				{typ: treasuryValueTSpend, amount: -1 - int64(i)},
			},
		}

		// Create hash of counter.
		b := make([]byte, 16)
		binary.LittleEndian.PutUint64(b[0:], i)
		hash := chainhash.HashH(b)

		var tsr *treasuryState
		err = testDb.View(func(dbTx database.Tx) error {
			tsr, err = dbFetchTreasuryBalance(dbTx, hash)
			return err
		})
		if err != nil {
			t.Fatalf("%v", err)
		}

		if !reflect.DeepEqual(ts, *tsr) {
			t.Fatalf("not same treasury state got %v wanted %v", ts, *tsr)
		}
	}
}

// TestTspendDatabase tests tspend database functionality including
// serialization and deserialization.
func TestTSpendDatabase(t *testing.T) {
	// Create a new database to store treasury state.
	dbName := "ffldb_tspenddb_test"
	dbPath, err := ioutil.TempDir("", dbName)
	if err != nil {
		t.Fatalf("unable to create tspend db path: %v", err)
	}
	defer os.RemoveAll(dbPath)
	net := chaincfg.RegNetParams().Net
	testDb, err := database.Create(testDbType, dbPath, net)
	if err != nil {
		t.Fatalf("error creating tspend db: %v", err)
	}
	defer testDb.Close()

	// Add bucket.
	err = testDb.Update(func(dbTx database.Tx) error {
		_, err := dbTx.Metadata().CreateBucketIfNotExists(treasuryTSpendBucketName)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	// Write maxTSpendState records out.
	maxTSpendState := uint64(8)
	txHash := chainhash.Hash{}
	for i := uint64(0); i < maxTSpendState; i++ {
		// Create hash of counter.
		b := make([]byte, 16)
		binary.LittleEndian.PutUint64(b[0:], i)
		blockHash := chainhash.HashH(b)

		err = testDb.Update(func(dbTx database.Tx) error {
			return dbUpdateTSpend(dbTx, txHash, blockHash)
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	// Pull records back out.
	var hashes []chainhash.Hash
	err = testDb.View(func(dbTx database.Tx) error {
		hashes, err = dbFetchTSpend(dbTx, txHash)
		return err
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for i := uint64(0); i < maxTSpendState; i++ {
		// Create hash of counter.
		b := make([]byte, 16)
		binary.LittleEndian.PutUint64(b[0:], i)
		hash := chainhash.HashH(b)
		if !hash.IsEqual(&hashes[i]) {
			t.Fatalf("not same tspend hash got %v wanted %v", hashes[i], hash)
		}
	}
}

// appendHashes takes a slice of chainhash and votebits and appends it all
// together for a TV script.
func appendHashes(tspendHashes []*chainhash.Hash, votes []stake.TreasuryVoteT) []byte {
	if len(tspendHashes) != len(votes) {
		panic(fmt.Sprintf("assert appendHashes %v != %v", len(tspendHashes),
			len(votes)))
	}
	blob := make([]byte, 0, 2+chainhash.HashSize*7+7)
	blob = append(blob, 'T', 'V')
	for k, v := range tspendHashes {
		blob = append(blob, v[:]...)
		blob = append(blob, byte(votes[k]))
	}
	return blob
}

// addTSpendVotes return a munge function that votes according to voteBits.
func addTSpendVotes(t *testing.T, tspendHashes []*chainhash.Hash, votes []stake.TreasuryVoteT, nrVotes uint16, skipAssert bool) func(*wire.MsgBlock) {
	if len(tspendHashes) != len(votes) {
		panic(fmt.Sprintf("assert addTSpendVotes %v != %v", len(tspendHashes),
			len(votes)))
	}
	return func(b *wire.MsgBlock) {
		// Find SSGEN and append votes.
		for k, v := range b.STransactions {
			if !stake.IsSSGen(v, yesTreasury) {
				continue
			}
			if len(v.TxOut) != 3 {
				t.Fatalf("expected SSGEN.TxOut len 3 got %v", len(v.TxOut))
			}

			// Only allow provided number of votes.
			if uint16(k) > nrVotes {
				break
			}

			// Append vote:
			// OP_RETURN OP_DATA <TV> <tspend hash> <vote bits>
			vote := appendHashes(tspendHashes, votes)
			s, err := txscript.NewScriptBuilder().AddOp(txscript.OP_RETURN).
				AddData(vote).Script()
			if err != nil {
				t.Fatal(err)
			}
			b.STransactions[k].TxOut = append(b.STransactions[k].TxOut,
				&wire.TxOut{
					PkScript: s,
				})
			// Only TxVersionTreasury supports optional votes.
			b.STransactions[k].Version = wire.TxVersionTreasury

			// See if we should skip asserts. This is used for
			// munging votes and bits.
			if skipAssert {
				continue
			}

			// Assert vote insertion worked.
			_, err = stake.GetSSGenTreasuryVotes(s)
			if err != nil {
				t.Fatalf("expected treasury vote: %v", err)
			}

			// Assert this remains a valid SSGEN.
			err = stake.CheckSSGen(b.STransactions[k], yesTreasury)
			if err != nil {
				t.Fatalf("expected SSGen: %v", err)
			}
		}
	}
}

const devsub = 5000000000

// standardTreasurybaseOpReturn creates a standard OP_RETURN output to insert
// into coinbase. This function autogenerates the extranonce. The OP_RETURN
// pushes 12 bytes.
func standardTreasurybaseOpReturn(height uint32) []byte {
	extraNonce, err := wire.RandomUint64()
	if err != nil {
		panic(err)
	}

	enData := make([]byte, 12)
	binary.LittleEndian.PutUint32(enData[0:4], height)
	binary.LittleEndian.PutUint64(enData[4:12], extraNonce)
	extraNonceScript, err := txscript.GenerateProvablyPruneableOut(enData)
	if err != nil {
		panic(err)
	}

	return extraNonceScript
}

// replaceCoinbase is a munge function that takes the coinbase and removes the
// treasury payout and moves it to a TADD treasury agenda based version. It
// also bumps all STransactions indexes by 1 since we require treasurybase to
// be the 0th entry in the stake tree.
func replaceCoinbase(b *wire.MsgBlock) {
	// Find coinbase tx and remove dev subsidy.
	coinbaseTx := b.Transactions[0]
	devSubsidy := coinbaseTx.TxOut[0].Value
	coinbaseTx.TxOut = coinbaseTx.TxOut[1:]
	coinbaseTx.Version = wire.TxVersionTreasury
	coinbaseTx.TxIn[0].ValueIn -= devSubsidy

	// Create treasuryBase and insert it at position 0 of the stake
	// tree.
	oldSTransactions := b.STransactions
	b.STransactions = make([]*wire.MsgTx, len(b.STransactions)+1)
	for k, v := range oldSTransactions {
		b.STransactions[k+1] = v
	}
	treasurybaseTx := wire.NewMsgTx()
	treasurybaseTx.Version = wire.TxVersionTreasury
	treasurybaseTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: *wire.NewOutPoint(&chainhash.Hash{},
			wire.MaxPrevOutIndex, wire.TxTreeRegular),
		Sequence:    wire.MaxTxInSequenceNum,
		BlockHeight: wire.NullBlockHeight,
		BlockIndex:  wire.NullBlockIndex,
		// Required 0 len SignatureScript
	})
	treasurybaseTx.TxIn[0].ValueIn = devSubsidy
	treasurybaseTx.AddTxOut(&wire.TxOut{
		Value:    devSubsidy,
		PkScript: []byte{txscript.OP_TADD},
	})
	// Encoded height.
	treasurybaseTx.AddTxOut(&wire.TxOut{
		Value:    0,
		PkScript: standardTreasurybaseOpReturn(b.Header.Height),
	})
	retTx := dcrutil.NewTx(treasurybaseTx)
	retTx.SetTree(wire.TxTreeStake)
	b.STransactions[0] = retTx.MsgTx()

	// Sanity check treasury base.
	if !standalone.IsTreasuryBase(retTx.MsgTx()) {
		panic(stake.CheckTreasuryBase(retTx.MsgTx()))
	}
}

func TestTSpendVoteCount(t *testing.T) {
	// Use a set of test chain parameters which allow for quicker vote
	// activation as compared to various existing network params.
	params := quickVoteActivationParams()

	// Clone the parameters so they can be mutated, find the correct
	// deployment for the treasury agenda, and, finally, ensure it is
	// always available to vote by removing the time constraints to prevent
	// test failures when the real expiration time passes.
	const tVoteID = chaincfg.VoteIDTreasury
	params = cloneParams(params)
	tVersion, deployment, err := findDeployment(params, tVoteID)
	if err != nil {
		t.Fatal(err)
	}
	removeDeploymentTimeConstraints(deployment)

	// Shorter versions of useful params for convenience.
	tvi := params.TreasuryVoteInterval
	mul := params.TreasuryVoteIntervalMultiplier

	// Create a test harness initialized with the genesis block as the tip.
	g, teardownFunc := newChaingenHarness(t, params, "treasurytest")
	defer teardownFunc()

	// replaceTreasuryVersions is a munge function which modifies the
	// provided block by replacing the block, stake, and vote versions with
	// the treasury deployment version.
	replaceTreasuryVersions := func(b *wire.MsgBlock) {
		chaingen.ReplaceBlockVersion(int32(tVersion))(b)
		chaingen.ReplaceStakeVersion(tVersion)(b)
		chaingen.ReplaceVoteVersions(tVersion)(b)
	}

	// ---------------------------------------------------------------------
	// Generate and accept enough blocks with the appropriate vote bits set
	// to reach one block prior to the treasury agenda becoming active.
	// ---------------------------------------------------------------------

	g.AdvanceToStakeValidationHeight()
	g.AdvanceFromSVHToActiveAgendas(tVoteID)

	// Ensure treasury agenda is active.
	tipHash := &g.chain.BestSnapshot().Hash
	gotActive, err := g.chain.IsTreasuryAgendaActive(tipHash)
	if err != nil {
		t.Fatalf("IsTreasuryAgendaActive: %v", err)
	}
	if !gotActive {
		t.Fatalf("IsTreasuryAgendaActive: expected enabled treasury")
	}

	startTip := g.TipName()

	// ---------------------------------------------------------------------
	// Create TSpend in "mempool"
	// ---------------------------------------------------------------------

	nextBlockHeight := g.Tip().Header.Height + 1
	tspendAmount := devsub
	tspendFee := 100
	expiry := standalone.CalcTSpendExpiry(int64(nextBlockHeight), tvi, mul)
	start, end, err := standalone.CalcTSpendWindow(expiry, tvi, mul)
	if err != nil {
		t.Fatal(err)
	}

	tspend := g.CreateTreasuryTSpend(privKey, []chaingen.AddressAmountTuple{{
		Amount: dcrutil.Amount(tspendAmount - tspendFee),
	}}, dcrutil.Amount(tspendFee), expiry)
	tspendHash := tspend.TxHash()

	// ---------------------------------------------------------------------
	// Try to insert TSPEND while not on a TVI
	//
	//   ... -> bva19
	//                  \-> bnottvi0
	// ---------------------------------------------------------------------

	// Assert we are not on a TVI and generate block. This should fail.
	if standalone.IsTreasuryVoteInterval(uint64(nextBlockHeight), tvi) {
		t.Fatalf("expected !TVI %v", nextBlockHeight)
	}
	outs := g.OldestCoinbaseOuts()
	name := "bnottvi0"
	g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase,
		func(b *wire.MsgBlock) {
			// Add TSpend
			b.AddSTransaction(tspend)
		})
	g.RejectTipBlock(ErrNotTVI)

	// ---------------------------------------------------------------------
	// Generate enough blocks to get to TVI.
	//
	//   ... -> bva19 -> bpretvi0 -> bpretvi1
	//                  \-> bnottvi0
	// ---------------------------------------------------------------------

	// Generate votes up to TVI. This is legal however they should NOT be
	// counted in the totals since they are outside of the voting window.
	g.SetTip(startTip)
	voteCount := params.TicketsPerBlock
	for i := uint32(0); i < start-nextBlockHeight; i++ {
		name := fmt.Sprintf("bpretvi%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase,
			addTSpendVotes(t, []*chainhash.Hash{&tspendHash},
				[]stake.TreasuryVoteT{stake.TreasuryVoteYes},
				voteCount, false))
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
	}

	// ---------------------------------------------------------------------
	// Add TSpend on first block of window. This should fail with not
	// enough votes.
	//
	//   ... -> bpretvi1
	//         \-> btvinotenough0
	// ---------------------------------------------------------------------

	// Assert we are on a TVI and generate block. This should fail.
	startTip = g.TipName()
	if standalone.IsTreasuryVoteInterval(uint64(g.Tip().Header.Height), tvi) {
		t.Fatalf("expected !TVI %v", g.Tip().Header.Height)
	}
	name = "btvinotenough0"
	g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase,
		func(b *wire.MsgBlock) {
			// Add TSpend
			b.AddSTransaction(tspend)
		})
	g.RejectTipBlock(ErrNotEnoughTSpendVotes)

	// ---------------------------------------------------------------------
	// Generate 1 TVI of No votes and add TSpend,
	//
	//   ... -> bpretvi1 -> btvi0 -> ... -> btvi3
	// ---------------------------------------------------------------------
	g.SetTip(startTip)
	for i := uint64(0); i < tvi; i++ {
		name := fmt.Sprintf("btvi%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase,
			addTSpendVotes(t, []*chainhash.Hash{&tspendHash},
				[]stake.TreasuryVoteT{stake.TreasuryVoteNo},
				voteCount, false))
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
	}

	// Assert we are on a TVI and generate block. This should fail.
	startTip = g.TipName()
	if standalone.IsTreasuryVoteInterval(uint64(g.Tip().Header.Height), tvi) {
		t.Fatalf("expected !TVI %v", g.Tip().Header.Height)
	}
	name = "btvinotenough1"
	g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase,
		func(b *wire.MsgBlock) {
			// Add TSpend
			b.AddSTransaction(tspend)
		})
	g.RejectTipBlock(ErrNotEnoughTSpendVotes)

	// ---------------------------------------------------------------------
	// Generate two more TVI of no votes.
	//
	//   ... -> btvinotenough0 -> btvi4 -> ... -> btvi7
	// ---------------------------------------------------------------------

	g.SetTip(startTip)
	for i := uint64(0); i < tvi*2; i++ {
		name := fmt.Sprintf("btvi%v", tvi+i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase,
			addTSpendVotes(t, []*chainhash.Hash{&tspendHash},
				[]stake.TreasuryVoteT{stake.TreasuryVoteNo},
				voteCount, false))
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
	}

	// Assert we are on a TVI and generate block. This should fail with No
	// vote (TSpend should not have been submitted).
	startTip = g.TipName()
	if standalone.IsTreasuryVoteInterval(uint64(g.Tip().Header.Height), tvi) {
		t.Fatalf("expected !TVI %v", g.Tip().Header.Height)
	}
	name = "btvienough0"
	g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase,
		func(b *wire.MsgBlock) {
			// Add TSpend
			b.AddSTransaction(tspend)
		})
	g.RejectTipBlock(ErrNotEnoughTSpendVotes)

	// Assert we have the correct number of votes and voting window.
	tv, err := g.chain.tSpendCountVotes(g.chain.bestChain.Tip(),
		dcrutil.NewTx(tspend))
	if err != nil {
		t.Fatal(err)
	}

	if start != tv.start {
		t.Fatalf("invalid start block got %v wanted %v", tv.start, start)
	}
	if end != tv.end {
		t.Fatalf("invalid end block got %v wanted %v", tv.end, end)
	}

	expectedYesVotes := 0 // We voted a bunch of times outside the window
	expectedNoVotes := tvi * mul * uint64(params.TicketsPerBlock)
	if expectedYesVotes != tv.yes {
		t.Fatalf("invalid yes votes got %v wanted %v",
			expectedYesVotes, tv.yes)
	}
	if expectedNoVotes != uint64(tv.no) {
		t.Fatalf("invalid no votes got %v wanted %v",
			expectedNoVotes, tv.no)
	}

	// ---------------------------------------------------------------------
	// Generate one more TVI and append expired TSpend.
	//
	//   ... -> bposttvi0 ... -> bposttvi3 ->
	//                                     \-> bexpired0
	// ---------------------------------------------------------------------

	g.SetTip(startTip)
	for i := uint64(0); i < tvi; i++ {
		name := fmt.Sprintf("bposttvi%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase)
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
	}

	// Assert TSpend expired
	startTip = g.TipName()
	if standalone.IsTreasuryVoteInterval(uint64(g.Tip().Header.Height), tvi) {
		t.Fatalf("expected !TVI %v", g.Tip().Header.Height)
	}
	name = "bexpired0"
	g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase,
		func(b *wire.MsgBlock) {
			// Add TSpend
			b.AddSTransaction(tspend)
		})
	g.RejectTipBlock(ErrExpiredTx)

	// ---------------------------------------------------------------------
	// Create TSpend in "mempool"
	//
	// Test corner of quorum-1 vote and exact quorum yes vote.
	// ---------------------------------------------------------------------

	// Use exact hight to validate that tspend starts on next tvi.
	expiry = standalone.CalcTSpendExpiry(int64(g.Tip().Header.Height), tvi, mul)
	start, _, err = standalone.CalcTSpendWindow(expiry, tvi, mul)
	if err != nil {
		t.Fatal(err)
	}

	// While here test that start is next tvi while on tvi.
	if g.Tip().Header.Height+uint32(tvi) != start {
		t.Fatalf("expected to see exactly next tvi got %v wanted %v",
			start, g.Tip().Header.Height+uint32(tvi))
	}

	tspend = g.CreateTreasuryTSpend(privKey, []chaingen.AddressAmountTuple{
		{
			Amount: dcrutil.Amount(tspendAmount - tspendFee),
		},
	},
		dcrutil.Amount(tspendFee), expiry)
	tspendHash = tspend.TxHash()

	// Fast forward to next tvi and add no votes which should not count.
	g.SetTip(startTip)
	for i := uint64(0); i < tvi; i++ {
		name := fmt.Sprintf("bnovote%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase,
			addTSpendVotes(t, []*chainhash.Hash{&tspendHash},
				[]stake.TreasuryVoteT{stake.TreasuryVoteNo},
				voteCount, false))
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
	}

	// Hit quorum-1 yes votes.
	maxVotes := uint32(params.TicketsPerBlock) *
		(tv.end - tv.start)
	quorum := uint64(maxVotes) * params.TreasuryVoteQuorumMultiplier /
		params.TreasuryVoteQuorumDivisor
	totalVotes := uint16(quorum - 1)
	for i := uint64(0); i < tvi; i++ {
		name := fmt.Sprintf("byesvote%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase,
			addTSpendVotes(t, []*chainhash.Hash{&tspendHash},
				[]stake.TreasuryVoteT{stake.TreasuryVoteYes},
				totalVotes, false))
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()

		if totalVotes > params.TicketsPerBlock {
			totalVotes -= params.TicketsPerBlock
		} else {
			totalVotes = 0
		}
	}

	// Verify we are one vote shy of quorum
	startTip = g.TipName()
	if standalone.IsTreasuryVoteInterval(uint64(g.Tip().Header.Height), tvi) {
		t.Fatalf("expected !TVI %v", g.Tip().Header.Height)
	}
	name = "bquorum0"
	g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase,
		func(b *wire.MsgBlock) {
			// Add TSpend
			b.AddSTransaction(tspend)
		})
	g.RejectTipBlock(ErrNotEnoughTSpendVotes)

	// Count votes.
	tv, err = g.chain.tSpendCountVotes(g.chain.bestChain.Tip(),
		dcrutil.NewTx(tspend))
	if err != nil {
		t.Fatal(err)
	}
	if int(quorum-1) != tv.yes {
		t.Fatalf("unexpected yesVote count got %v wanted %v",
			tv.yes, quorum-1)
	}

	// Hit exact yes vote quorum
	g.SetTip(startTip)
	totalVotes = uint16(1)
	for i := uint64(0); i < tvi*2; i++ {
		name := fmt.Sprintf("byesvote%v", tvi+i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase,
			addTSpendVotes(t, []*chainhash.Hash{&tspendHash},
				[]stake.TreasuryVoteT{stake.TreasuryVoteYes},
				totalVotes, false))
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()

		if totalVotes > params.TicketsPerBlock {
			totalVotes -= params.TicketsPerBlock
		} else {
			totalVotes = 0
		}
	}

	// Count votes.
	tv, err = g.chain.tSpendCountVotes(g.chain.bestChain.Tip(),
		dcrutil.NewTx(tspend))
	if err != nil {
		t.Fatal(err)
	}
	if int(quorum) != tv.yes {
		t.Fatalf("unexpected yesVote count got %v wanted %v",
			tv.yes, quorum)
	}

	// Verify TSpend can be added exactly on quorum.
	if standalone.IsTreasuryVoteInterval(uint64(g.Tip().Header.Height), tvi) {
		t.Fatalf("expected !TVI %v", g.Tip().Header.Height)
	}
	name = "bquorum1"
	g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase,
		func(b *wire.MsgBlock) {
			// Add TSpend
			b.AddSTransaction(tspend)
		})
	g.AcceptTipBlock()
}

// getTreasuryState retrieves the treasury state for the provided hash.
func getTreasuryState(g *chaingenHarness, hash chainhash.Hash) (*treasuryState, error) {
	var (
		tsr *treasuryState
		err error
	)
	err = g.chain.db.View(func(dbTx database.Tx) error {
		tsr, err = dbFetchTreasuryBalance(dbTx, hash)
		return err
	})
	return tsr, nil
}

// TestTSpendEmptyTreasury tests that we can't generate a tspend that spends
// more funds than available in the treasury even when otherwise allowed by
// policy.
func TestTSpendEmptyTreasury(t *testing.T) {
	// Use a set of test chain parameters which allow for quicker vote
	// activation as compared to various existing network params.
	params := quickVoteActivationParams()

	// To ensure we can completely drain the treasury, increase the
	// bootstrap policy to allow a tspend with a _very_ high value.
	params.TreasuryExpenditureBootstrap = 21e6 * 1e8

	// Clone the parameters so they can be mutated, find the correct
	// deployment for the treasury agenda, and, finally, ensure it is
	// always available to vote by removing the time constraints to prevent
	// test failures when the real expiration time passes.
	const tVoteID = chaincfg.VoteIDTreasury
	params = cloneParams(params)
	tVersion, deployment, err := findDeployment(params, tVoteID)
	if err != nil {
		t.Fatal(err)
	}
	removeDeploymentTimeConstraints(deployment)

	// Shorter versions of useful params for convenience.
	tvi := params.TreasuryVoteInterval
	mul := params.TreasuryVoteIntervalMultiplier

	// Create a test harness initialized with the genesis block as the tip.
	g, teardownFunc := newChaingenHarness(t, params, "treasurytest")
	defer teardownFunc()

	// replaceTreasuryVersions is a munge function which modifies the
	// provided block by replacing the block, stake, and vote versions with
	// the treasury deployment version.
	replaceTreasuryVersions := func(b *wire.MsgBlock) {
		chaingen.ReplaceBlockVersion(int32(tVersion))(b)
		chaingen.ReplaceStakeVersion(tVersion)(b)
		chaingen.ReplaceVoteVersions(tVersion)(b)
	}

	// ---------------------------------------------------------------------
	// Generate and accept enough blocks with the appropriate vote bits set
	// to reach one block prior to the treasury agenda becoming active.
	// ---------------------------------------------------------------------

	g.AdvanceToStakeValidationHeight()
	g.AdvanceFromSVHToActiveAgendas(tVoteID)

	// Ensure treasury agenda is active.
	tipHash := &g.chain.BestSnapshot().Hash
	gotActive, err := g.chain.IsTreasuryAgendaActive(tipHash)
	if err != nil {
		t.Fatalf("IsTreasuryAgendaActive: %v", err)
	}
	if !gotActive {
		t.Fatalf("IsTreasuryAgendaActive: expected enabled treasury")
	}

	// ---------------------------------------------------------------------
	// Create TSPEND in mempool for exact amount of treasury + 1 atom
	// ---------------------------------------------------------------------
	nextBlockHeight := g.Tip().Header.Height + 1
	expiry := standalone.CalcTSpendExpiry(int64(nextBlockHeight), tvi, mul)
	start, _, err := standalone.CalcTSpendWindow(expiry, tvi, mul)
	if err != nil {
		t.Fatal(err)
	}

	tspendAmount := devsub*(tvi*mul-uint64(params.CoinbaseMaturity)+
		uint64(start-nextBlockHeight)) + 1 // One atom too many
	tspendFee := uint64(0)
	tspend := g.CreateTreasuryTSpend(privKey, []chaingen.AddressAmountTuple{
		{
			Amount: dcrutil.Amount(tspendAmount - tspendFee),
		},
	},
		dcrutil.Amount(tspendFee), expiry)
	tspendHash := tspend.TxHash()

	// ---------------------------------------------------------------------
	// Generate enough blocks to get to TVI.
	//
	//   ... -> bva19 -> bpretvi0 -> bpretvi1
	// ---------------------------------------------------------------------

	// Generate votes up to TVI. This is legal however they should NOT be
	// counted in the totals since they are outside of the voting window.
	outs := g.OldestCoinbaseOuts()
	for i := uint32(0); i < start-nextBlockHeight; i++ {
		name := fmt.Sprintf("bpretvi%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase)
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
	}

	// ---------------------------------------------------------------------
	// Generate a TVI worth of rewards and try to spend more.
	//
	//   ... -> b0 ... -> b7
	//                 \-> btoomuch0
	// ---------------------------------------------------------------------

	voteCount := params.TicketsPerBlock
	for i := uint64(0); i < tvi*mul; i++ {
		name := fmt.Sprintf("b%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase,
			addTSpendVotes(t, []*chainhash.Hash{&tspendHash},
				[]stake.TreasuryVoteT{stake.TreasuryVoteYes},
				voteCount, false))
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
	}

	// Assert treasury balance is 1 atom less than calculated amount.
	ts, err := getTreasuryState(g, g.Tip().BlockHash())
	if err != nil {
		t.Fatal(err)
	}
	if int64(tspendAmount-tspendFee)-ts.balance != 1 {
		t.Fatalf("Assert treasury balance error: got %v want %v",
			ts.balance, int64(tspendAmount-tspendFee)-ts.balance)
	}

	// Try spending 1 atom more than treasury balance.
	name := "btoomuch0"
	g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase,
		func(b *wire.MsgBlock) {
			// Add TSpend
			b.AddSTransaction(tspend)
		})
	g.RejectTipBlock(ErrInvalidExpenditure)
}

// TestTSpendExpendituresPolicy performs tests against the treasury policy
// window rules. The following is the rough test plan:
//
// - Start chain and approve treasury vote
// - Mine and mature the following treasury txs:
//   - 4 tspends that spend the maximum allowed by the bootstrap policy
//   - 1 tadd
// - Advance until the previous tspends and tadd are out of the "current"
// expenditure window and in a past "policy check"
// - Attempt to drain as much as possible from the treasury given the update
// of the expenditure policy
// - Advance the chain until all previous tspends are outside the policy check
// range
// - Attempt to drain the bootstrap policy again.
func TestTSpendExpendituresPolicy(t *testing.T) {
	// Use a set of test chain parameters which allow for quicker vote
	// activation as compared to various existing network params.
	params := quickVoteActivationParams()

	// We'll significantly increase the SRI so that the treasurybase isn't
	// reduced throughout these tests and our arithmetic can be simpler.
	params.SubsidyReductionInterval = 1000

	// CoinbaseMaturity MUST be lower than TVI otherwise assumptions about
	// tspend maturity expenditure are broken. This is a sanity check to
	// ensure we're testing reasonable scenarios.
	if uint64(params.CoinbaseMaturity) > params.TreasuryVoteInterval {
		t.Fatalf("params sanity check failed. CBM > TVI ")
	}

	// Clone the parameters so they can be mutated, find the correct
	// deployment for the treasury agenda, and, finally, ensure it is
	// always available to vote by removing the time constraints to prevent
	// test failures when the real expiration time passes.
	const tVoteID = chaincfg.VoteIDTreasury
	params = cloneParams(params)
	tVersion, deployment, err := findDeployment(params, tVoteID)
	if err != nil {
		t.Fatal(err)
	}
	removeDeploymentTimeConstraints(deployment)

	// Shorter versions of useful params for convenience.
	tvi := params.TreasuryVoteInterval
	mul := params.TreasuryVoteIntervalMultiplier
	tew := params.TreasuryExpenditureWindow
	tep := params.TreasuryExpenditurePolicy

	// Before any tspends are mined on the chain, the maximum allowed to be
	// spent is 150% of the expenditure bootstrap amount.
	expendBootstrap := int64(params.TreasuryExpenditureBootstrap +
		params.TreasuryExpenditureBootstrap/2)

	// Create a test harness initialized with the genesis block as the tip.
	g, teardownFunc := newChaingenHarness(t, params, "treasurytest")
	defer teardownFunc()

	// Helper to verify the tip balance.
	assertTipTreasuryBalance := func(wantBalance int64) {
		t.Helper()
		ts, err := getTreasuryState(g, g.Tip().BlockHash())
		if err != nil {
			t.Fatal(err)
		}
		if ts.balance != wantBalance {
			t.Fatalf("unexpected treasury balance. want=%d got %d",
				wantBalance, ts.balance)
		}
	}

	// replaceTreasuryVersions is a munge function which modifies the
	// provided block by replacing the block, stake, and vote versions with
	// the treasury deployment version.
	replaceTreasuryVersions := func(b *wire.MsgBlock) {
		chaingen.ReplaceBlockVersion(int32(tVersion))(b)
		chaingen.ReplaceStakeVersion(tVersion)(b)
		chaingen.ReplaceVoteVersions(tVersion)(b)
	}

	// ---------------------------------------------------------------------
	// Generate and accept enough blocks with the appropriate vote bits set
	// to reach one block prior to the treasury agenda becoming active.
	// ---------------------------------------------------------------------

	g.AdvanceToStakeValidationHeight()
	g.AdvanceFromSVHToActiveAgendas(tVoteID)

	// Ensure treasury agenda is active.
	tipHash := &g.chain.BestSnapshot().Hash
	gotActive, err := g.chain.IsTreasuryAgendaActive(tipHash)
	if err != nil {
		t.Fatalf("IsTreasuryAgendaActive: %v", err)
	}
	if !gotActive {
		t.Fatalf("IsTreasuryAgendaActive: expected enabled treasury")
	}

	// tbaseBlocks will keep track of how many blocks with a treasury base
	// have been added to the chain.
	var tbaseBlocks int

	// ---------------------------------------------------------------------
	// Generate enough blocks that the treasury has funds. After
	// activation, the first block with funds will be at CoinbaseMaturity +
	// 1 blocks.
	//
	//   ... -> bva19 -> bpretf0 -> bpretf1
	//   ---------------------------------------------------------------------

	// Mine CoinbaseMaturity blocks
	outs := g.OldestCoinbaseOuts()
	for i := uint32(0); i < uint32(params.CoinbaseMaturity); i++ {
		name := fmt.Sprintf("bpretf%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase)
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
		tbaseBlocks++
	}

	// Assert the treasury is still empty.
	assertTipTreasuryBalance(0)

	// ---------------------------------------------------------------------
	// Generate a block that matures funds into the treasury.
	//
	// ... -> bpretf1 -> btfund
	// -------------------------------------------------------------------
	g.NextBlock("btfund", nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase)
	g.SaveTipCoinbaseOutsWithTreasury()
	g.AcceptTipBlock()
	outs = g.OldestCoinbaseOuts()
	tbaseBlocks++

	// The current treasury balance should equal the first treasurybase
	// subsidy.
	assertTipTreasuryBalance(devsub)

	// ---------------------------------------------------------------------
	// Generate enough blocks to get to the next TVI.
	//
	// ... -> btfund -> bpretvi0 -> .. -> bpretvin
	// ---------------------------------------------------------------------

	nextBlockHeight := g.Tip().Header.Height + 1
	expiry := standalone.CalcTSpendExpiry(int64(nextBlockHeight), tvi, mul)
	start, _, err := standalone.CalcTSpendWindow(expiry, tvi, mul)
	if err != nil {
		t.Fatal(err)
	}

	// Generate up to TVI blocks.
	for i := uint32(0); i < start-nextBlockHeight; i++ {
		name := fmt.Sprintf("bpretvi%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase)
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
		tbaseBlocks++
	}

	// Treasury balance should be the sum of the mature treasurybases.
	wantBalance := (int64(tbaseBlocks) - int64(params.CoinbaseMaturity)) * devsub
	assertTipTreasuryBalance(wantBalance)

	// Figure out the expiry for the next tspends.
	nextBlockHeight = g.Tip().Header.Height + 1 - uint32(tvi) // travel a bit back
	expiry = standalone.CalcTSpendExpiry(int64(nextBlockHeight), tvi, mul)

	// Each tspend will spend 1/4 of all the funds expendable within a
	// treasury expenditure policy window.
	nbTSpends := 4
	tspendAmount := expendBootstrap / int64(nbTSpends)
	tspendFee := uint64(0)
	tspends := make([]*wire.MsgTx, nbTSpends)
	tspendHashes := make([]*chainhash.Hash, nbTSpends)
	tspendVotes := make([]stake.TreasuryVoteT, nbTSpends)
	for i := 0; i < nbTSpends; i++ {
		tspends[i] = g.CreateTreasuryTSpend(privKey, []chaingen.AddressAmountTuple{
			{
				Amount: dcrutil.Amount(uint64(tspendAmount) - tspendFee),
			},
		},
			dcrutil.Amount(tspendFee), expiry)
		h := tspends[i].TxHash()
		tspendHashes[i] = &h
		tspendVotes[i] = stake.TreasuryVoteYes
	}

	// Create a TADD to ensure they *DO NOT* count towards the policy.
	taddAmount := int64(1701)
	taddFee := dcrutil.Amount(0)
	tadd := g.CreateTreasuryTAdd(&outs[0], dcrutil.Amount(taddAmount), taddFee)
	tadd.Version = wire.TxVersionTreasury

	// ---------------------------------------------------------------------
	// Generate enough blocks to approve the previously created tspends. A
	// tvi-worth of yes votes should be sufficient.
	//
	// ... -> bpretvin -> bv0 -> ... -> bvn
	// ---------------------------------------------------------------------
	voteCount := params.TicketsPerBlock
	for i := uint64(0); i < tvi*2; i++ {
		name := fmt.Sprintf("bv%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase,
			addTSpendVotes(t, tspendHashes, tspendVotes, voteCount,
				false))
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
		tbaseBlocks++
	}

	// ---------------------------------------------------------------------
	// Generate a block that includes the tspends and a tadd.
	//
	// ... -> bvn -> btspends
	// ---------------------------------------------------------------------
	g.NextBlock("btspends", nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase,
		func(b *wire.MsgBlock) {
			for _, tspend := range tspends {
				b.AddSTransaction(tspend)
			}
			b.AddSTransaction(tadd)
		})
	g.SaveTipCoinbaseOutsWithTreasury()
	g.AcceptTipBlock()
	outs = g.OldestCoinbaseOuts()
	tbaseBlocks++
	tspendsMinedHeight := g.Tip().Header.Height

	// ---------------------------------------------------------------------
	// Generate enough blocks that the tspends become mature and their
	// outputs are reflected in the treasury balance.
	//
	// ... -> btspends -> btsm0 -> ... -> btsmn
	// ---------------------------------------------------------------------

	// Mine CoinbaseMaturity+1 blocks
	for i := uint32(0); i < uint32(params.CoinbaseMaturity+1); i++ {
		name := fmt.Sprintf("btsm%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase)
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
		tbaseBlocks++
	}

	// Assert the balance equals everything received by the treasury minus
	// immature tbases and the just mined tspends.
	wantBalance = (int64(tbaseBlocks)-int64(params.CoinbaseMaturity))*devsub +
		taddAmount - tspendAmount*int64(nbTSpends)
	assertTipTreasuryBalance(wantBalance)

	// Expiry for the next set of tspends.
	nextBlockHeight = g.Tip().Header.Height + 1 - uint32(tvi)
	expiry = standalone.CalcTSpendExpiry(int64(nextBlockHeight), tvi, mul)

	// We have spent the entire possible amount for the most recent
	// expenditure window. To assert that is true, create, approve and
	// attempt to mine a very small tspend.
	smallTSpendAmount := int64(1)
	smallTSpendFee := int64(0)
	smallTSpend := g.CreateTreasuryTSpend(privKey, []chaingen.AddressAmountTuple{
		{
			Amount: dcrutil.Amount(uint64(smallTSpendAmount - smallTSpendFee)),
		},
	},
		dcrutil.Amount(smallTSpendFee), expiry)
	h := smallTSpend.TxHash()
	tspendHashes = []*chainhash.Hash{&h}
	tspendVotes = []stake.TreasuryVoteT{stake.TreasuryVoteYes}

	// ---------------------------------------------------------------------
	// Generate enough blocks to approve the previously created small
	// tspend.  A tvi-worth of yes votes should be sufficient.
	//
	// ... -> btsmn -> bvv0 -> ... -> bvvn
	// ---------------------------------------------------------------------
	for i := uint64(0); i < tvi*2; i++ {
		name := fmt.Sprintf("bvv%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase,
			addTSpendVotes(t, tspendHashes, tspendVotes, voteCount,
				false))
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
		tbaseBlocks++
	}

	// ---------------------------------------------------------------------
	// Attempt to mine a block to include the small tspend.
	//
	// ... -> bvvn -> bsmalltspendfail
	// ---------------------------------------------------------------------
	tipName := g.TipName()
	g.NextBlock("bsmalltspendfail", nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase,
		func(b *wire.MsgBlock) {
			b.AddSTransaction(smallTSpend)
		})
	g.RejectTipBlock(ErrInvalidExpenditure)
	g.SetTip(tipName)

	// The next part of the test will attempt to mine some tspends on the
	// first block after the expenditure window that includes the previous
	// tspends is no longer the current window but is rather used to
	// determine the average past expenditure.
	//
	// In order to do that we need to work backwards from the target test
	// height so that we can approve the test tspends at _exactly_ the
	// correct block.
	nextEWHeight := uint64(tspendsMinedHeight) + tvi*mul*tew
	currentHeight := uint64(g.Tip().Header.Height)
	nbBlocks := nextEWHeight - currentHeight - 1

	// ---------------------------------------------------------------------
	// Advance until the block we'll need to start voting on.
	//
	// ... -> bvvn -> bsmalltspendfail
	//            \-> bnextew0 -> ... -> bnextewn
	// ---------------------------------------------------------------------
	for i := uint64(0); i < nbBlocks; i++ {
		name := fmt.Sprintf("bnextew%d", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase,
			addTSpendVotes(t, tspendHashes, tspendVotes, voteCount,
				false))
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
		tbaseBlocks++
	}

	// The maximum we can now spend is 150% of the previous tspend sum.
	maxPolicySpend := expendBootstrap + expendBootstrap/2

	// Expiry for the next set of tspends.
	nextBlockHeight = g.Tip().Header.Height + 1 - uint32(tvi)
	expiry = standalone.CalcTSpendExpiry(int64(nextBlockHeight), tvi, mul)

	// Create a new set of tspends to test various policy scenarios. We
	// create and approve all in parallel to ease testing.
	testCases := []struct {
		name       string
		amount     int64
		wantAccept bool
	}{{
		// One more than the maximum allowed policy.
		name:       "max policy spend +1",
		amount:     maxPolicySpend + 1,
		wantAccept: false,
	}, {
		// Exactly the maximum allowed policy.
		name:       "max policy spend",
		amount:     maxPolicySpend,
		wantAccept: true,
	}}

	// Create the tspend txs, hashes and votes.
	nbTests := len(testCases)
	tspends = make([]*wire.MsgTx, nbTests)
	tspendHashes = make([]*chainhash.Hash, nbTests)
	tspendVotes = make([]stake.TreasuryVoteT, nbTests)
	for i := 0; i < nbTests; i++ {
		tspends[i] = g.CreateTreasuryTSpend(privKey, []chaingen.AddressAmountTuple{
			{
				Amount: dcrutil.Amount(uint64(testCases[i].amount) - tspendFee),
			},
		},
			dcrutil.Amount(tspendFee), expiry)
		h := tspends[i].TxHash()
		tspendHashes[i] = &h
		tspendVotes[i] = stake.TreasuryVoteYes
	}

	// ---------------------------------------------------------------------
	// Generate enough blocks to approve the previously created tspends. A
	// tvi-worth of yes votes should be sufficient.
	//
	// ... -> btsmn -> bvvv0 -> ... -> bvvvn
	// ---------------------------------------------------------------------
	for i := uint64(0); i < tvi*2; i++ {
		name := fmt.Sprintf("bvvv%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase,
			addTSpendVotes(t, tspendHashes, tspendVotes, voteCount,
				false))
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
		tbaseBlocks++
	}

	// ---------------------------------------------------------------------
	// Perform the previously setup test cases. We mine one block for each
	// tspend. Only the last one is a valid one.
	//
	// ... -> bvvn
	//           \-> btest0 (ErrInvalidExpenditure)
	//           \-> btest1 (ok)
	// ---------------------------------------------------------------------

	// We'll come back to this block to test the policy scenarios.
	preTspendsBlock := g.TipName()

	for i, tc := range testCases {
		t.Logf("Case %s", tc.name)
		name := fmt.Sprintf("btest%d", i)

		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase,
			func(b *wire.MsgBlock) {
				b.AddSTransaction(tspends[i])
			})
		if tc.wantAccept {
			g.SaveTipCoinbaseOutsWithTreasury()
			g.AcceptTipBlock()
			outs = g.OldestCoinbaseOuts()
			tbaseBlocks++
		} else {
			g.RejectTipBlock(ErrInvalidExpenditure)

			// Switch back to the pre-tspends block to execute the
			// next test case.
			g.SetTip(preTspendsBlock)
		}
	}

	// ---------------------------------------------------------------------
	// Generate enough blocks that the tspend become mature and its outputs
	// are reflected in the treasury balance.
	//
	// ... -> btest4 -> btstm0 -> ... -> btstmn
	// ---------------------------------------------------------------------

	// Mine CoinbaseMaturity+1 blocks
	for i := uint32(0); i < uint32(params.CoinbaseMaturity+1); i++ {
		name := fmt.Sprintf("btstm%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase)
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
		tbaseBlocks++
	}

	// Assert the balance equals everything received by the treasury minus
	// immature tbases and the just mined tspends.
	wantBalance = (int64(tbaseBlocks)-int64(params.CoinbaseMaturity))*devsub +
		taddAmount - tspendAmount*int64(nbTSpends) - testCases[nbTests-1].amount
	assertTipTreasuryBalance(wantBalance)

	// ---------------------------------------------------------------------
	// Generate enough blocks to advance until all previously mined tspends
	// have falled out of the policy check window and we revert back to the
	// bootstrap rate.
	//
	// ... -> btstmn -> ... -> btpolfinn
	// -------------------------------------------------------------------
	for i := uint32(0); i < uint32(tvi*mul*tew*(tep+1)); i++ {
		name := fmt.Sprintf("btpolfin%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase)
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
		tbaseBlocks++
	}

	// Create a final tspend that should be able to fetch the maximum
	// amount allowed by the bootstrap policy again.
	nextBlockHeight = g.Tip().Header.Height + 1 - uint32(tvi)
	expiry = standalone.CalcTSpendExpiry(int64(nextBlockHeight), tvi, mul)
	tspendHashes = make([]*chainhash.Hash, 1)
	tspendVotes = make([]stake.TreasuryVoteT, 1)
	tspend := g.CreateTreasuryTSpend(privKey, []chaingen.AddressAmountTuple{
		{
			Amount: dcrutil.Amount(uint64(expendBootstrap) - tspendFee),
		},
	},
		dcrutil.Amount(tspendFee), expiry)
	h = tspend.TxHash()
	tspendHashes[0] = &h
	tspendVotes[0] = stake.TreasuryVoteYes

	// ---------------------------------------------------------------------
	// Generate enough blocks to approve the previously created tspend. A
	// tvi-worth of yes votes should be sufficient.
	//
	// ... -> btpolfinn -> bvvvv0 -> ... -> bvvvvn
	// ---------------------------------------------------------------------
	for i := uint64(0); i < tvi*2; i++ {
		name := fmt.Sprintf("bvvvv%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase,
			addTSpendVotes(t, tspendHashes, tspendVotes, voteCount,
				false))
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
		tbaseBlocks++
	}

	// ---------------------------------------------------------------------
	// Generate a block that includes the final tspend
	//
	// ... -> bvvvn -> btfinaltspend
	// ---------------------------------------------------------------------
	g.NextBlock("btfinaltspend", nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase,
		func(b *wire.MsgBlock) {
			b.AddSTransaction(tspend)
		})
	g.AcceptTipBlock()
}

// TestExpendituresReorg tests that the correct treasury balance is tracked
// when reorgs remove tspends/tadds from the main chain. Test plan:
//
// - Approve and mine TSpend and TAdd
// - Reorg to chain without TSpend/Tadd
// - Mine until TSpend/TAdd would have been mature
// - Extend TSpend/TAdd chain and reorg back to it
func TestExpendituresReorg(t *testing.T) {
	// Use a set of test chain parameters which allow for quicker vote
	// activation as compared to various existing network params.
	params := quickVoteActivationParams()

	// Clone the parameters so they can be mutated, find the correct
	// deployment for the treasury agenda, and, finally, ensure it is
	// always available to vote by removing the time constraints to prevent
	// test failures when the real expiration time passes.
	const tVoteID = chaincfg.VoteIDTreasury
	params = cloneParams(params)
	tVersion, deployment, err := findDeployment(params, tVoteID)
	if err != nil {
		t.Fatal(err)
	}
	removeDeploymentTimeConstraints(deployment)

	// Shorter versions of useful params for convenience.
	tvi := params.TreasuryVoteInterval
	mul := params.TreasuryVoteIntervalMultiplier

	// Create a test harness initialized with the genesis block as the tip.
	g, teardownFunc := newChaingenHarness(t, params, "treasurytest")
	defer teardownFunc()

	// Helper to check the treasury balance at tip.
	assertTipTreasuryBalance := func(wantBalance int64) {
		t.Helper()
		ts, err := getTreasuryState(g, g.Tip().BlockHash())
		if err != nil {
			t.Fatal(err)
		}
		if ts.balance != wantBalance {
			t.Fatalf("unexpected treasury balance. want=%d got %d",
				wantBalance, ts.balance)
		}
	}

	// replaceTreasuryVersions is a munge function which modifies the
	// provided block by replacing the block, stake, and vote versions with
	// the treasury deployment version.
	replaceTreasuryVersions := func(b *wire.MsgBlock) {
		chaingen.ReplaceBlockVersion(int32(tVersion))(b)
		chaingen.ReplaceStakeVersion(tVersion)(b)
		chaingen.ReplaceVoteVersions(tVersion)(b)
	}

	// ---------------------------------------------------------------------
	// Generate and accept enough blocks with the appropriate vote bits set
	// to reach one block prior to the treasury agenda becoming active.
	// ---------------------------------------------------------------------

	g.AdvanceToStakeValidationHeight()
	g.AdvanceFromSVHToActiveAgendas(tVoteID)

	// Ensure treasury agenda is active.
	tipHash := &g.chain.BestSnapshot().Hash
	gotActive, err := g.chain.IsTreasuryAgendaActive(tipHash)
	if err != nil {
		t.Fatalf("IsTreasuryAgendaActive: %v", err)
	}
	if !gotActive {
		t.Fatalf("IsTreasuryAgendaActive: expected enabled treasury")
	}

	// tbaseBlocks will keep track of how many blocks with a treasury base
	// have been added to the chain.
	var tbaseBlocks int

	// ---------------------------------------------------------------------
	// Generate enough blocks to have spendable outputs during the reorg
	// stage of the test. Due to having lowered the coinbase maturity,
	// we'll need to manually generate and store these outputs until we
	// have enough to create two sidechains in the future.
	//
	//   ... -> bva19 -> bout0 -> .. boutn
	// ---------------------------------------------------------------------
	outs := g.OldestCoinbaseOuts()
	neededBlocks := (params.CoinbaseMaturity + 1) * 2
	neededOuts := neededBlocks * params.TicketsPerBlock
	oldOuts := make([][]chaingen.SpendableOut, 1)
	for i := uint32(0); i < uint32(neededOuts); i++ {
		name := fmt.Sprintf("bout%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase)
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
		lastOuts := &oldOuts[len(oldOuts)-1]
		*lastOuts = append(*lastOuts, outs[0])
		if len(*lastOuts) == int(params.TicketsPerBlock) && i < uint32(neededOuts-1) {
			oldOuts = append(oldOuts, make([]chaingen.SpendableOut, 0, int(params.TicketsPerBlock)))
		}
		tbaseBlocks++
	}

	// ---------------------------------------------------------------------
	// Generate enough blocks to get to TVI.
	//
	//   ... -> bva19 -> bpretvi0 -> bpretvi1
	// ---------------------------------------------------------------------

	nextBlockHeight := g.Tip().Header.Height + 1
	expiry := standalone.CalcTSpendExpiry(int64(nextBlockHeight), tvi, mul)
	start, _, err := standalone.CalcTSpendWindow(expiry, tvi, mul)
	if err != nil {
		t.Fatal(err)
	}

	// Generate up to TVI blocks.
	for i := uint32(0); i < start-nextBlockHeight; i++ {
		name := fmt.Sprintf("bpretvi%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase)
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
		tbaseBlocks++
	}

	// Generate a TSpend for some amount.
	tspendAmount := int64(1e7)
	tspendFee := uint64(0)
	tspend := g.CreateTreasuryTSpend(privKey, []chaingen.AddressAmountTuple{{
		Amount: dcrutil.Amount(uint64(tspendAmount) - tspendFee),
	}}, dcrutil.Amount(tspendFee), expiry)
	tspendHash := tspend.TxHash()

	// Generate a TAdd for some amount.
	taddAmount := int64(1701)
	taddFee := dcrutil.Amount(0)
	tadd := g.CreateTreasuryTAdd(&outs[0], dcrutil.Amount(taddAmount), taddFee)
	tadd.Version = wire.TxVersionTreasury

	// ---------------------------------------------------------------------
	// Generate enough blocks to approve the tspend.
	//
	// ... -> bpretvi1 -> bv0 -> ... -> bvn
	// ---------------------------------------------------------------------
	voteCount := params.TicketsPerBlock
	for i := uint64(0); i < tvi*mul; i++ {
		name := fmt.Sprintf("bv%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase,
			addTSpendVotes(t, []*chainhash.Hash{&tspendHash},
				[]stake.TreasuryVoteT{stake.TreasuryVoteYes},
				voteCount, false))
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
		tbaseBlocks++
	}

	// Remember the block immediately before the TSpend is mined so we can
	// create sidechains.
	preTSpendBlock := g.TipName()

	// ---------------------------------------------------------------------
	// Generate a block that includes the tspend and tadd.
	//
	// ... -> bvn -> btspend
	// ---------------------------------------------------------------------
	g.NextBlock("btspend", nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase,
		func(b *wire.MsgBlock) {
			b.AddSTransaction(tspend)
			b.AddSTransaction(tadd)
		})
	g.AcceptTipBlock()

	// Balance only reflects the tbase added so far. We add 1 to
	// tbaseBlocks to account for the `btspend` block.
	wantBalance := (int64(tbaseBlocks+1) - int64(params.CoinbaseMaturity)) * devsub
	assertTipTreasuryBalance(wantBalance)

	// ---------------------------------------------------------------------
	// Generate a sidechain that does _not_ include the TSpend and mine it
	// all the way to when the TSpend would have been mature and ensure the
	// treasury balance does _not_ reflect the reorged txs.
	//
	// ... -> bvn -> btspend
	//           \-> bnotxs0 -> ... -> bnotxsn
	// ---------------------------------------------------------------------
	g.SetTip(preTSpendBlock)
	blocksToTreasuryChange := uint64(params.CoinbaseMaturity + 1)
	for i := uint64(0); i < blocksToTreasuryChange; i++ {
		name := fmt.Sprintf("bnotxs%v", i)
		g.NextBlock(name, nil, oldOuts[0], replaceTreasuryVersions,
			replaceCoinbase,
			addTSpendVotes(t, []*chainhash.Hash{&tspendHash},
				[]stake.TreasuryVoteT{stake.TreasuryVoteYes},
				voteCount, false))
		switch i {
		case 0:
			// The first block creates a sidechain.
			g.AcceptedToSideChainWithExpectedTip("btspend")
		default:
			g.AcceptTipBlock()
		}
		oldOuts = oldOuts[1:]
		tbaseBlocks++
	}

	// Given we reorged to a side chain that does _not_ include the TSpend
	// and TAdd, we expect the current balance to have only tbases.
	wantBalance = (int64(tbaseBlocks) - int64(params.CoinbaseMaturity)) * devsub
	assertTipTreasuryBalance(wantBalance)

	// ---------------------------------------------------------------------
	// Extend the chain starting at btspend again, until it becomes the
	// main chain again.
	//
	// ... -> bvn -> btspend -> btspend0 -> ... btspendn
	//           \-> bnotxs0 -> ... -> bnotxsn
	// ---------------------------------------------------------------------
	tip := g.TipName()
	g.SetTip("btspend")
	for i := uint64(0); i < blocksToTreasuryChange; i++ {
		name := fmt.Sprintf("btspend%v", i)
		g.NextBlock(name, nil, oldOuts[0], replaceTreasuryVersions,
			replaceCoinbase,
			addTSpendVotes(t, []*chainhash.Hash{&tspendHash},
				[]stake.TreasuryVoteT{stake.TreasuryVoteYes},
				voteCount, false))

		switch {
		case i < blocksToTreasuryChange-1:
			// Only the last block changes tip.
			g.AcceptedToSideChainWithExpectedTip(tip)
		default:
			g.AcceptTipBlock()
		}
		oldOuts = oldOuts[1:]
	}

	// We mined one more block vs the previous chain.
	tbaseBlocks++

	// We reorged back to the chain that includes the mature TSpend/TAdd so
	// now ensure the treasury balance reflects their presence.
	wantBalance = (int64(tbaseBlocks)-int64(params.CoinbaseMaturity))*devsub -
		tspendAmount + taddAmount
	assertTipTreasuryBalance(wantBalance)
}

// TestSpendableTreasuryTxs tests that the outputs of mined TSpends and TAdds
// are actually spendable by transactions that can be mined.
//
// - Approve and mine TSpend and TAdd
// - Mine until TSpend/TAdd are mature
// - Create a tx that spends from the TSpend and TAdd change.
func TestSpendableTreasuryTxs(t *testing.T) {
	// Use a set of test chain parameters which allow for quicker vote
	// activation as compared to various existing network params.
	params := quickVoteActivationParams()

	// Clone the parameters so they can be mutated, find the correct
	// deployment for the treasury agenda, and, finally, ensure it is
	// always available to vote by removing the time constraints to prevent
	// test failures when the real expiration time passes.
	const tVoteID = chaincfg.VoteIDTreasury
	params = cloneParams(params)
	tVersion, deployment, err := findDeployment(params, tVoteID)
	if err != nil {
		t.Fatal(err)
	}
	removeDeploymentTimeConstraints(deployment)

	// Shorter versions of useful params for convenience.
	tvi := params.TreasuryVoteInterval
	mul := params.TreasuryVoteIntervalMultiplier

	// Create a test harness initialized with the genesis block as the tip.
	g, teardownFunc := newChaingenHarness(t, params, "treasurytest")
	defer teardownFunc()

	// replaceTreasuryVersions is a munge function which modifies the
	// provided block by replacing the block, stake, and vote versions with
	// the treasury deployment version.
	replaceTreasuryVersions := func(b *wire.MsgBlock) {
		chaingen.ReplaceBlockVersion(int32(tVersion))(b)
		chaingen.ReplaceStakeVersion(tVersion)(b)
		chaingen.ReplaceVoteVersions(tVersion)(b)
	}

	// ---------------------------------------------------------------------
	// Generate and accept enough blocks with the appropriate vote bits set
	// to reach one block prior to the treasury agenda becoming active.
	// ---------------------------------------------------------------------

	g.AdvanceToStakeValidationHeight()
	g.AdvanceFromSVHToActiveAgendas(tVoteID)

	// Ensure treasury agenda is active.
	tipHash := &g.chain.BestSnapshot().Hash
	gotActive, err := g.chain.IsTreasuryAgendaActive(tipHash)
	if err != nil {
		t.Fatalf("IsTreasuryAgendaActive: %v", err)
	}
	if !gotActive {
		t.Fatalf("IsTreasuryAgendaActive: expected enabled treasury")
	}

	// ---------------------------------------------------------------------
	// Generate enough blocks to get to TVI.
	//
	//   ... -> bva19 -> bpretvi0 -> bpretvi1
	// ---------------------------------------------------------------------

	nextBlockHeight := g.Tip().Header.Height + 1
	expiry := standalone.CalcTSpendExpiry(int64(nextBlockHeight), tvi, mul)
	start, _, err := standalone.CalcTSpendWindow(expiry, tvi, mul)
	if err != nil {
		t.Fatal(err)
	}

	// Generate up to TVI blocks.
	outs := g.OldestCoinbaseOuts()
	taddOut1 := outs[0] // Save this output for a tadd.
	for i := uint32(0); i < start-nextBlockHeight; i++ {
		name := fmt.Sprintf("bpretvi%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase)
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
	}

	// Create P2PKH and P2SH scripts to test spendability of TSpend and
	// TAdd outputs. Each one is unique so we can do a cfilter test after
	// mining these txs.
	spendPrivKey := secp256k1.NewPrivateKey(new(secp256k1.ModNScalar).SetInt(1))
	pubKey := spendPrivKey.PubKey().SerializeCompressed()
	pubKeyHash := stdaddr.Hash160(pubKey)
	spendP2pkhAddr, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(
		pubKeyHash, params)
	if err != nil {
		t.Fatal(err)
	}
	spendP2shScript := []byte{txscript.OP_NOP, txscript.OP_TRUE}
	spendP2shAddr, err := stdaddr.NewAddressScriptHashV0(spendP2shScript,
		params)
	if err != nil {
		t.Fatal(err)
	}

	addPrivKey := secp256k1.NewPrivateKey(new(secp256k1.ModNScalar).SetInt(2))
	pubKey = addPrivKey.PubKey().SerializeCompressed()
	pubKeyHash = stdaddr.Hash160(pubKey)
	addP2pkhAddr, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(
		pubKeyHash, params)
	if err != nil {
		t.Fatal(err)
	}
	addP2shScript := []byte{txscript.OP_NOP, txscript.OP_NOP, txscript.OP_TRUE}
	addP2shAddr, err := stdaddr.NewAddressScriptHashV0(addP2shScript, params)
	if err != nil {
		t.Fatal(err)
	}

	// Generate a TSpend for some amount.
	tspendAmount := int64(1e7)
	tspendFee := uint64(0)
	tspend := g.CreateTreasuryTSpend(privKey, []chaingen.AddressAmountTuple{
		{
			Amount:  dcrutil.Amount(uint64(tspendAmount) - tspendFee),
			Address: spendP2pkhAddr,
		},
		{
			Amount:  dcrutil.Amount(uint64(tspendAmount) - tspendFee),
			Address: spendP2shAddr,
		},
	},
		dcrutil.Amount(tspendFee), expiry)
	tspendHash := tspend.TxHash()

	// Generate a TAdd for some amount ensuring there's change and direct
	// the change to a P2PKH addr.
	taddAmount := int64(outs[0].Amount() / 2)
	taddChange := taddAmount
	taddFee := dcrutil.Amount(0)
	tadd1 := g.CreateTreasuryTAddChange(&taddOut1, dcrutil.Amount(taddAmount),
		taddFee, addP2pkhAddr)
	tadd1.Version = wire.TxVersionTreasury
	taddHash1 := tadd1.TxHash()

	// Generate a second TAdd that pays the change to a unique P2SH script.
	tadd2 := g.CreateTreasuryTAddChange(&outs[0], dcrutil.Amount(taddAmount),
		taddFee, addP2shAddr)
	tadd2.Version = wire.TxVersionTreasury
	taddHash2 := tadd2.TxHash()

	// ---------------------------------------------------------------------
	// Generate enough blocks to approve the tspend.
	//
	// ... -> bpretvi1 -> bv0 -> ... -> bvn
	// ---------------------------------------------------------------------
	voteCount := params.TicketsPerBlock
	for i := uint64(0); i < tvi*mul; i++ {
		name := fmt.Sprintf("bv%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase,
			addTSpendVotes(t, []*chainhash.Hash{&tspendHash},
				[]stake.TreasuryVoteT{stake.TreasuryVoteYes},
				voteCount, false))
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
	}

	// ---------------------------------------------------------------------
	// Generate a block that includes the tspend and tadd.
	//
	// ... -> bvn -> btspend
	// ---------------------------------------------------------------------
	var tspendHeight, tspendIndex uint32
	g.NextBlock("btspend", nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase,
		func(b *wire.MsgBlock) {
			tspendHeight = b.Header.Height
			tspendIndex = uint32(len(b.STransactions))
			b.AddSTransaction(tspend)
			b.AddSTransaction(tadd1)
			b.AddSTransaction(tadd2)
		})
	g.SaveTipCoinbaseOutsWithTreasury()
	g.AcceptTipBlock()
	outs = g.OldestCoinbaseOuts()

	// Ensure the CFilter committed to the outputs of the TSpend and TAdds.
	tipHash = &g.chain.BestSnapshot().Hash
	bcf, err := g.chain.FilterByBlockHash(tipHash)
	if err != nil {
		t.Fatal(err)
	}
	bcfKey := blockcf2.Key(&(g.Tip().Header.MerkleRoot))
	wantMatches := [][]byte{
		tspend.TxOut[1].PkScript[1:], // P2PKH without OP_TGEN
		tspend.TxOut[2].PkScript[1:], // P2SH without OP_TGEN
		tadd1.TxOut[1].PkScript[1:],  // P2PKH without OP_SSTxChange
		tadd2.TxOut[1].PkScript[1:],  // P2SH without OP_SSTxChange
	}
	for i, wantMatch := range wantMatches {
		if !bcf.Match(bcfKey, wantMatch) {
			t.Fatalf("bcf did not match script %d %x", i, wantMatch)
		}
	}

	// Create a tx that spends from the TSPend outputs and the TAdd change
	// output.
	tx := wire.NewMsgTx()
	tx.AddTxIn(&wire.TxIn{ // TSpend P2PKH output
		PreviousOutPoint: wire.OutPoint{
			Hash:  tspendHash,
			Index: 1,
			Tree:  1,
		},
		Sequence:    wire.MaxTxInSequenceNum,
		ValueIn:     tspendAmount,
		BlockHeight: tspendHeight,
		BlockIndex:  tspendIndex,
	})
	tx.AddTxIn(&wire.TxIn{ // TSPend P2SH output
		PreviousOutPoint: wire.OutPoint{
			Hash:  tspendHash,
			Index: 2,
			Tree:  1,
		},
		Sequence:        wire.MaxTxInSequenceNum,
		ValueIn:         tspendAmount,
		BlockHeight:     tspendHeight,
		BlockIndex:      tspendIndex,
		SignatureScript: append([]byte{txscript.OP_DATA_2}, spendP2shScript...),
	})
	tx.AddTxIn(&wire.TxIn{ // TAdd P2PKH output
		PreviousOutPoint: wire.OutPoint{
			Hash:  taddHash1,
			Index: 1,
			Tree:  1,
		},
		Sequence:    wire.MaxTxInSequenceNum,
		ValueIn:     taddChange,
		BlockHeight: tspendHeight,
		BlockIndex:  tspendIndex + 1,
	})
	tx.AddTxIn(&wire.TxIn{ // TAdd P2SH output
		PreviousOutPoint: wire.OutPoint{
			Hash:  taddHash2,
			Index: 1,
			Tree:  1,
		},
		Sequence:        wire.MaxTxInSequenceNum,
		ValueIn:         taddChange,
		BlockHeight:     tspendHeight,
		BlockIndex:      tspendIndex + 2,
		SignatureScript: append([]byte{txscript.OP_DATA_3}, addP2shScript...),
	})
	tx.AddTxOut(&wire.TxOut{
		Version: 0,
		Value:   tspendAmount*2 + taddChange,
	})

	// Generate the valid signature for the first input, which is a P2PKH.
	sig, err := sign.SignatureScript(tx, 0, tspend.TxOut[1].PkScript,
		txscript.SigHashAll, spendPrivKey.Serialize(), dcrec.STEcdsaSecp256k1,
		true)
	if err != nil {
		t.Fatalf("unable to generate sig: %v", err)
	}
	tx.TxIn[0].SignatureScript = sig

	// Generate the valid signature for the third input, which is a P2PKH.
	sig, err = sign.SignatureScript(tx, 2, tadd1.TxOut[1].PkScript,
		txscript.SigHashAll, addPrivKey.Serialize(), dcrec.STEcdsaSecp256k1,
		true)
	if err != nil {
		t.Fatalf("unable to generate sig: %v", err)
	}
	tx.TxIn[2].SignatureScript = sig

	// ---------------------------------------------------------------------
	// Generate up to the block where the tspend is spendable.
	//
	// ... -> btspend -> bpremat0 -> ... -> bprematn
	// ---------------------------------------------------------------------
	for i := uint32(0); i < uint32(params.CoinbaseMaturity-1); i++ {
		name := fmt.Sprintf("bpremat%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase)
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
	}

	// ---------------------------------------------------------------------
	// Generate a block that includes the transaction spending from the
	// TSpend and TAdd.
	//
	// ... -> btpremat -> btredeem
	// ---------------------------------------------------------------------
	g.NextBlock("btredeem", nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase,
		func(b *wire.MsgBlock) {
			b.AddTransaction(tx)
		})
	g.SaveTipCoinbaseOutsWithTreasury()
	g.AcceptTipBlock()
}

func TestTSpendDupVote(t *testing.T) {
	// Use a set of test chain parameters which allow for quicker vote
	// activation as compared to various existing network params.
	params := quickVoteActivationParams()

	// Clone the parameters so they can be mutated, find the correct
	// deployment for the treasury agenda, and, finally, ensure it is
	// always available to vote by removing the time constraints to prevent
	// test failures when the real expiration time passes.
	const tVoteID = chaincfg.VoteIDTreasury
	params = cloneParams(params)
	tVersion, deployment, err := findDeployment(params, tVoteID)
	if err != nil {
		t.Fatal(err)
	}
	removeDeploymentTimeConstraints(deployment)

	// Shorter versions of useful params for convenience.
	tvi := params.TreasuryVoteInterval
	mul := params.TreasuryVoteIntervalMultiplier

	// Create a test harness initialized with the genesis block as the tip.
	g, teardownFunc := newChaingenHarness(t, params, "treasurytest")
	defer teardownFunc()

	// replaceTreasuryVersions is a munge function which modifies the
	// provided block by replacing the block, stake, and vote versions with
	// the treasury deployment version.
	replaceTreasuryVersions := func(b *wire.MsgBlock) {
		chaingen.ReplaceBlockVersion(int32(tVersion))(b)
		chaingen.ReplaceStakeVersion(tVersion)(b)
		chaingen.ReplaceVoteVersions(tVersion)(b)
	}

	// ---------------------------------------------------------------------
	// Generate and accept enough blocks with the appropriate vote bits set
	// to reach one block prior to the treasury agenda becoming active.
	// ---------------------------------------------------------------------

	g.AdvanceToStakeValidationHeight()
	g.AdvanceFromSVHToActiveAgendas(tVoteID)

	// Ensure treasury agenda is active.
	tipHash := &g.chain.BestSnapshot().Hash
	gotActive, err := g.chain.IsTreasuryAgendaActive(tipHash)
	if err != nil {
		t.Fatalf("IsTreasuryAgendaActive: %v", err)
	}
	if !gotActive {
		t.Fatalf("IsTreasuryAgendaActive: expected enabled treasury")
	}

	// ---------------------------------------------------------------------
	// Create two TSPEND with invalid bits and duplicate votes.
	// ---------------------------------------------------------------------
	nextBlockHeight := g.Tip().Header.Height + 1
	expiry := standalone.CalcTSpendExpiry(int64(nextBlockHeight), tvi, mul)
	start, _, err := standalone.CalcTSpendWindow(expiry, tvi, mul)
	if err != nil {
		t.Fatal(err)
	}

	tspendAmount := devsub * (tvi*mul - uint64(params.CoinbaseMaturity) +
		uint64(start-nextBlockHeight))
	tspendFee := uint64(0)
	tspend := g.CreateTreasuryTSpend(privKey,
		[]chaingen.AddressAmountTuple{

			{
				Amount: dcrutil.Amount(tspendAmount - tspendFee),
			},
		},
		dcrutil.Amount(tspendFee), expiry)
	tspendHash := tspend.TxHash()
	tspend2 := g.CreateTreasuryTSpend(privKey,
		[]chaingen.AddressAmountTuple{
			{
				Amount: dcrutil.Amount(tspendAmount - tspendFee),
			},
		},
		dcrutil.Amount(tspendFee), expiry)
	tspendHash2 := tspend2.TxHash()

	// ---------------------------------------------------------------------
	// Generate enough blocks to get to TVI.
	//
	//   ... -> bva19 -> bpretvi0 -> bpretvi1
	// ---------------------------------------------------------------------

	// Generate votes up to TVI. This is legal however they should NOT be
	// counted in the totals since they are outside of the voting window.
	outs := g.OldestCoinbaseOuts()
	for i := uint32(0); i < start-nextBlockHeight; i++ {
		name := fmt.Sprintf("bpretvi%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase)
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
	}

	// ---------------------------------------------------------------------
	// Duplicate votes on the same treasury spend tx hash illegal and
	// therefore the tx is NOT recognized as a vote.
	//
	//   ... -> pretvi1
	//                 \-> bdv0
	// ---------------------------------------------------------------------

	startTip := g.TipName()
	voteCount := params.TicketsPerBlock
	g.NextBlock("bdv0", nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase,
		addTSpendVotes(t,
			[]*chainhash.Hash{
				&tspendHash,
				&tspendHash,
			},
			[]stake.TreasuryVoteT{
				stake.TreasuryVoteYes,
				stake.TreasuryVoteYes,
			},
			voteCount, true))
	g.RejectTipBlock(ErrBadTxInput)

	// ---------------------------------------------------------------------
	// Invalid treasury spend tx vote bits are illegal and therefore the tx
	// is NOT recognized as a vote.
	//
	//   ... -> pretvi1
	//                 \-> bdv1
	// ---------------------------------------------------------------------

	g.SetTip(startTip)
	g.NextBlock("bdv1", nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase,
		addTSpendVotes(t,
			[]*chainhash.Hash{
				&tspendHash2,
			},
			[]stake.TreasuryVoteT{
				0x04, // Invalid bits
			},
			voteCount, true))
	g.RejectTipBlock(ErrBadTxInput)
}

func TestTSpendTooManyTSpend(t *testing.T) {
	// Use a set of test chain parameters which allow for quicker vote
	// activation as compared to various existing network params.
	params := quickVoteActivationParams()

	// Clone the parameters so they can be mutated, find the correct
	// deployment for the treasury agenda, and, finally, ensure it is
	// always available to vote by removing the time constraints to prevent
	// test failures when the real expiration time passes.
	const tVoteID = chaincfg.VoteIDTreasury
	params = cloneParams(params)
	tVersion, deployment, err := findDeployment(params, tVoteID)
	if err != nil {
		t.Fatal(err)
	}
	removeDeploymentTimeConstraints(deployment)

	// Shorter versions of useful params for convenience.
	tvi := params.TreasuryVoteInterval
	mul := params.TreasuryVoteIntervalMultiplier

	// Create a test harness initialized with the genesis block as the tip.
	g, teardownFunc := newChaingenHarness(t, params, "treasurytest")
	defer teardownFunc()

	// replaceTreasuryVersions is a munge function which modifies the
	// provided block by replacing the block, stake, and vote versions with
	// the treasury deployment version.
	replaceTreasuryVersions := func(b *wire.MsgBlock) {
		chaingen.ReplaceBlockVersion(int32(tVersion))(b)
		chaingen.ReplaceStakeVersion(tVersion)(b)
		chaingen.ReplaceVoteVersions(tVersion)(b)
	}

	// ---------------------------------------------------------------------
	// Generate and accept enough blocks with the appropriate vote bits set
	// to reach one block prior to the treasury agenda becoming active.
	// ---------------------------------------------------------------------

	g.AdvanceToStakeValidationHeight()
	g.AdvanceFromSVHToActiveAgendas(tVoteID)

	// Ensure treasury agenda is active.
	tipHash := &g.chain.BestSnapshot().Hash
	gotActive, err := g.chain.IsTreasuryAgendaActive(tipHash)
	if err != nil {
		t.Fatalf("IsTreasuryAgendaActive: %v", err)
	}
	if !gotActive {
		t.Fatalf("IsTreasuryAgendaActive: expected enabled treasury")
	}

	// ---------------------------------------------------------------------
	// Create two TSPEND with invalid bits and duplicate votes.
	// ---------------------------------------------------------------------
	nextBlockHeight := g.Tip().Header.Height + 1
	expiry := standalone.CalcTSpendExpiry(int64(nextBlockHeight), tvi, mul)
	start, _, err := standalone.CalcTSpendWindow(expiry, tvi, mul)
	if err != nil {
		t.Fatal(err)
	}

	tspendAmount := devsub * (tvi*mul - uint64(params.CoinbaseMaturity) +
		uint64(start-nextBlockHeight))
	tspendFee := uint64(0)
	maxTspends := 7
	tspends := make([]*wire.MsgTx, maxTspends+1)
	tspendHashes := make([]*chainhash.Hash, maxTspends+1)
	tspendVotes := make([]stake.TreasuryVoteT, maxTspends+1)
	for i := 0; i < maxTspends+1; i++ {
		tspends[i] = g.CreateTreasuryTSpend(privKey,
			[]chaingen.AddressAmountTuple{
				{
					Amount: dcrutil.Amount(tspendAmount - tspendFee),
				},
			},
			dcrutil.Amount(tspendFee), expiry)
		hash := tspends[i].TxHash()
		tspendHashes[i] = &hash
		tspendVotes[i] = stake.TreasuryVoteYes
	}

	// ---------------------------------------------------------------------
	// Generate enough blocks to get to TVI.
	//
	//   ... -> bva19 -> bpretvi0 -> bpretvi1
	// ---------------------------------------------------------------------

	// Generate votes up to TVI. This is legal however they should NOT be
	// counted in the totals since they are outside of the voting window.
	outs := g.OldestCoinbaseOuts()
	for i := uint32(0); i < start-nextBlockHeight; i++ {
		name := fmt.Sprintf("bpretvi%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase)
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
	}

	// ---------------------------------------------------------------------
	// 8 votes is illegal and therefore the tx is NOT recognized as a vote.
	//
	//   ... -> pretvi1
	//                 \-> bdv0
	// ---------------------------------------------------------------------

	voteCount := params.TicketsPerBlock
	g.NextBlock("bdv0", nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase,
		addTSpendVotes(t, tspendHashes, tspendVotes, voteCount, true))
	g.RejectTipBlock(ErrBadTxInput)
}

func TestTSpendWindow(t *testing.T) {
	// Use a set of test chain parameters which allow for quicker vote
	// activation as compared to various existing network params.
	params := quickVoteActivationParams()

	// Clone the parameters so they can be mutated, find the correct
	// deployment for the treasury agenda, and, finally, ensure it is
	// always available to vote by removing the time constraints to prevent
	// test failures when the real expiration time passes.
	const tVoteID = chaincfg.VoteIDTreasury
	params = cloneParams(params)
	tVersion, deployment, err := findDeployment(params, tVoteID)
	if err != nil {
		t.Fatal(err)
	}
	removeDeploymentTimeConstraints(deployment)

	// Shorter versions of useful params for convenience.
	tvi := params.TreasuryVoteInterval
	mul := params.TreasuryVoteIntervalMultiplier

	// Create a test harness initialized with the genesis block as the tip.
	g, teardownFunc := newChaingenHarness(t, params, "treasurytest")
	defer teardownFunc()

	// replaceTreasuryVersions is a munge function which modifies the
	// provided block by replacing the block, stake, and vote versions with
	// the treasury deployment version.
	replaceTreasuryVersions := func(b *wire.MsgBlock) {
		chaingen.ReplaceBlockVersion(int32(tVersion))(b)
		chaingen.ReplaceStakeVersion(tVersion)(b)
		chaingen.ReplaceVoteVersions(tVersion)(b)
	}

	// ---------------------------------------------------------------------
	// Generate and accept enough blocks with the appropriate vote bits set
	// to reach one block prior to the treasury agenda becoming active.
	// ---------------------------------------------------------------------

	g.AdvanceToStakeValidationHeight()
	g.AdvanceFromSVHToActiveAgendas(tVoteID)

	// Ensure treasury agenda is active.
	tipHash := &g.chain.BestSnapshot().Hash
	gotActive, err := g.chain.IsTreasuryAgendaActive(tipHash)
	if err != nil {
		t.Fatalf("IsTreasuryAgendaActive: %v", err)
	}
	if !gotActive {
		t.Fatalf("IsTreasuryAgendaActive: expected enabled treasury")
	}

	// ---------------------------------------------------------------------
	// Create TSPEND in mempool
	// ---------------------------------------------------------------------
	nextBlockHeight := g.Tip().Header.Height + uint32(tvi*mul*4) + 1
	expiry := standalone.CalcTSpendExpiry(int64(nextBlockHeight), tvi, mul)
	start, _, err := standalone.CalcTSpendWindow(expiry, tvi, mul)
	if err != nil {
		t.Fatal(err)
	}

	tspendAmount := devsub * (tvi*mul - uint64(params.CoinbaseMaturity) +
		uint64(start-nextBlockHeight))
	tspendFee := uint64(0)
	tspend := g.CreateTreasuryTSpend(privKey, []chaingen.AddressAmountTuple{
		{
			Amount: dcrutil.Amount(tspendAmount - tspendFee),
		},
	},
		dcrutil.Amount(tspendFee), expiry)
	tspendHash := tspend.TxHash()

	// ---------------------------------------------------------------------
	// Generate enough blocks to get to TVI.
	//
	//   ... -> bva19 -> bpretvi0 -> bpretvi1
	// ---------------------------------------------------------------------

	// Generate votes up to TVI. This is legal however they should NOT be
	// counted in the totals since they are outside of the voting window.
	outs := g.OldestCoinbaseOuts()
	for i := uint32(0); i < start-nextBlockHeight; i++ {
		name := fmt.Sprintf("bpretvi%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase)
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
	}

	// ---------------------------------------------------------------------
	// Generate a TVI worth of rewards and try to spend more.
	//
	//   ... -> b0 ... -> b7
	//                 \-> bvidaltoosoon0
	// ---------------------------------------------------------------------

	voteCount := params.TicketsPerBlock
	for i := uint64(0); i < tvi*mul; i++ {
		name := fmt.Sprintf("b%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase,
			addTSpendVotes(t, []*chainhash.Hash{&tspendHash},
				[]stake.TreasuryVoteT{stake.TreasuryVoteYes},
				voteCount, false))
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
	}

	// Try accepting TSpend from the future.
	g.NextBlock("bvidaltoosoon0", nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase,
		func(b *wire.MsgBlock) {
			// Add TSpend
			b.AddSTransaction(tspend)
		})
	g.RejectTipBlock(ErrInvalidTSpendWindow)
}

// TestTSpendSignature verifies that both PI keys work and in addition that an
// invalid key is indeed rejected.
func TestTSpendSignature(t *testing.T) {
	// Use a set of test chain parameters which allow for quicker vote
	// activation as compared to various existing network params.
	params := quickVoteActivationParams()

	// Clone the parameters so they can be mutated, find the correct
	// deployment for the treasury agenda, and, finally, ensure it is
	// always available to vote by removing the time constraints to prevent
	// test failures when the real expiration time passes.
	const tVoteID = chaincfg.VoteIDTreasury
	params = cloneParams(params)
	tVersion, deployment, err := findDeployment(params, tVoteID)
	if err != nil {
		t.Fatal(err)
	}
	removeDeploymentTimeConstraints(deployment)

	// Shorter versions of useful params for convenience.
	tvi := params.TreasuryVoteInterval
	mul := params.TreasuryVoteIntervalMultiplier

	// Create a test harness initialized with the genesis block as the tip.
	g, teardownFunc := newChaingenHarness(t, params, "treasurytest")
	defer teardownFunc()

	// replaceTreasuryVersions is a munge function which modifies the
	// provided block by replacing the block, stake, and vote versions with
	// the treasury deployment version.
	replaceTreasuryVersions := func(b *wire.MsgBlock) {
		chaingen.ReplaceBlockVersion(int32(tVersion))(b)
		chaingen.ReplaceStakeVersion(tVersion)(b)
		chaingen.ReplaceVoteVersions(tVersion)(b)
	}

	// ---------------------------------------------------------------------
	// Generate and accept enough blocks with the appropriate vote bits set
	// to reach one block prior to the treasury agenda becoming active.
	// ---------------------------------------------------------------------

	g.AdvanceToStakeValidationHeight()
	g.AdvanceFromSVHToActiveAgendas(tVoteID)

	// Ensure treasury agenda is active.
	tipHash := &g.chain.BestSnapshot().Hash
	gotActive, err := g.chain.IsTreasuryAgendaActive(tipHash)
	if err != nil {
		t.Fatalf("IsTreasuryAgendaActive: %v", err)
	}
	if !gotActive {
		t.Fatalf("IsTreasuryAgendaActive: expected enabled treasury")
	}

	// ---------------------------------------------------------------------
	// Create TSPEND in mempool with key 1 and 2
	// ---------------------------------------------------------------------
	nextBlockHeight := g.Tip().Header.Height //+ uint32(tvi*mul*4) + 1
	expiry := standalone.CalcTSpendExpiry(int64(nextBlockHeight), tvi, mul)
	start, _, err := standalone.CalcTSpendWindow(expiry, tvi, mul)
	if err != nil {
		t.Fatal(err)
	}

	tspendAmount1 := uint64(devsub / 3)
	tspendFee := uint64(0)
	tspend1 := g.CreateTreasuryTSpend(privKey, []chaingen.AddressAmountTuple{
		{
			Amount: dcrutil.Amount(tspendAmount1 - tspendFee),
		},
	},
		dcrutil.Amount(tspendFee), expiry)
	tspend1Hash := tspend1.TxHash()

	// tspend 2.
	tspendAmount2 := uint64(devsub / 5)
	tspend2 := g.CreateTreasuryTSpend(privKey2, []chaingen.AddressAmountTuple{
		{
			Amount: dcrutil.Amount(tspendAmount2 - tspendFee),
		},
	},
		dcrutil.Amount(tspendFee), expiry)
	tspend2Hash := tspend2.TxHash()

	// ---------------------------------------------------------------------
	// Generate enough blocks to get to TVI.
	//
	//   ... -> bva19 -> bpretvi0 -> bpretvi1
	// ---------------------------------------------------------------------
	outs := g.OldestCoinbaseOuts()
	for i := uint32(0); i < start-nextBlockHeight-1; i++ {
		name := fmt.Sprintf("bpretvi%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase)
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
	}

	// ---------------------------------------------------------------------
	// Generate TVI*MUL of yes votes for both TSpends,
	//
	//   ... -> bpretvi1 -> btvi0 -> ... -> btvi7
	// ---------------------------------------------------------------------

	voteCount := params.TicketsPerBlock
	for i := uint64(0); i < tvi*mul; i++ {
		name := fmt.Sprintf("btvi%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase,
			addTSpendVotes(t,
				[]*chainhash.Hash{
					&tspend1Hash,
					&tspend2Hash,
				},
				[]stake.TreasuryVoteT{
					stake.TreasuryVoteYes,
					stake.TreasuryVoteYes,
				},
				voteCount, false))
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
	}

	// Assert that we are on a TVI.
	if standalone.IsTreasuryVoteInterval(uint64(g.Tip().Header.Height), tvi) {
		t.Fatalf("expected !TVI %v", g.Tip().Header.Height)
	}

	// Assert treasury balance
	ts, err := getTreasuryState(g, g.Tip().BlockHash())
	if err != nil {
		t.Fatal(err)
	}
	if ts.balance != int64(devsub*tvi*mul) {
		t.Fatalf("assert balance got %v want devsub %v", ts.balance,
			devsub*tvi*mul)
	}

	// ---------------------------------------------------------------------
	// Add tspend1 twice
	//
	//   ... -> btvi7 ->
	//                \-> double0
	// ---------------------------------------------------------------------

	startTip := g.TipName()
	g.NextBlock("double0", nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase,
		func(b *wire.MsgBlock) {
			// Add TSpends
			b.AddSTransaction(tspend1)
			b.AddSTransaction(tspend2)
			b.AddSTransaction(tspend1)
		})
	g.RejectTipBlock(ErrDuplicateTx)

	// ---------------------------------------------------------------------
	// Add tspend1 and tspend2
	//
	//   ... -> btvi7 -> doubleok0
	//                \-> double0
	// ---------------------------------------------------------------------

	g.SetTip(startTip)
	g.NextBlock("doubleok0", nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase,
		func(b *wire.MsgBlock) {
			// Add TSpends
			b.AddSTransaction(tspend1)
			b.AddSTransaction(tspend2)
		})
	g.SaveTipCoinbaseOutsWithTreasury()
	g.AcceptTipBlock()
	outs = g.OldestCoinbaseOuts()

	// Assert treasury balance
	ts, err = getTreasuryState(g, g.Tip().BlockHash())
	if err != nil {
		t.Fatal(err)
	}
	if ts.balance != int64(devsub*tvi*mul)+devsub {
		t.Fatalf("assert balance got %v want devsub %v", ts.balance,
			devsub*tvi*mul+devsub)
	}

	// ---------------------------------------------------------------------
	// Add Coinbase maturity blocks and assert treasury balance.
	//
	//   ... -> btvi7 -> doubleok0 -> cbm0 -> cbm1
	//                \-> double0
	// ---------------------------------------------------------------------

	for i := uint32(0); i < uint32(params.CoinbaseMaturity); i++ {
		name := fmt.Sprintf("cbm%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase)
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
	}

	// Assert treasury balance
	ts, err = getTreasuryState(g, g.Tip().BlockHash())
	if err != nil {
		t.Fatal(err)
	}
	expectedBalance := int64(devsub*tvi*mul) +
		(int64(devsub) * int64(params.CoinbaseMaturity+1)) // doubleok0+cbm0+cbm1
	expectedBalance -= int64(tspendAmount1)
	expectedBalance -= int64(tspendAmount2)
	if ts.balance != expectedBalance {
		t.Fatalf("assert balance got %v want devsub %v", ts.balance,
			expectedBalance)
	}
}

// TestTSpendSignatureInvalid verifies that a tspend is disallowed with an
// invalid key.
func TestTSpendSignatureInvalid(t *testing.T) {
	// Use a set of test chain parameters which allow for quicker vote
	// activation as compared to various existing network params.
	params := quickVoteActivationParams()

	// Clone the parameters so they can be mutated, find the correct
	// deployment for the treasury agenda, and, finally, ensure it is
	// always available to vote by removing the time constraints to prevent
	// test failures when the real expiration time passes.
	const tVoteID = chaincfg.VoteIDTreasury
	params = cloneParams(params)
	tVersion, deployment, err := findDeployment(params, tVoteID)
	if err != nil {
		t.Fatal(err)
	}
	removeDeploymentTimeConstraints(deployment)

	// Shorter versions of useful params for convenience.
	tvi := params.TreasuryVoteInterval
	mul := params.TreasuryVoteIntervalMultiplier

	// Create a test harness initialized with the genesis block as the tip.
	g, teardownFunc := newChaingenHarness(t, params, "treasurytest")
	defer teardownFunc()

	// replaceTreasuryVersions is a munge function which modifies the
	// provided block by replacing the block, stake, and vote versions with
	// the treasury deployment version.
	replaceTreasuryVersions := func(b *wire.MsgBlock) {
		chaingen.ReplaceBlockVersion(int32(tVersion))(b)
		chaingen.ReplaceStakeVersion(tVersion)(b)
		chaingen.ReplaceVoteVersions(tVersion)(b)
	}

	// ---------------------------------------------------------------------
	// Generate and accept enough blocks with the appropriate vote bits set
	// to reach one block prior to the treasury agenda becoming active.
	// ---------------------------------------------------------------------

	g.AdvanceToStakeValidationHeight()
	g.AdvanceFromSVHToActiveAgendas(tVoteID)

	// Ensure treasury agenda is active.
	tipHash := &g.chain.BestSnapshot().Hash
	gotActive, err := g.chain.IsTreasuryAgendaActive(tipHash)
	if err != nil {
		t.Fatalf("IsTreasuryAgendaActive: %v", err)
	}
	if !gotActive {
		t.Fatalf("IsTreasuryAgendaActive: expected enabled treasury")
	}

	// ---------------------------------------------------------------------
	// Create TSPEND in mempool.
	// ---------------------------------------------------------------------
	nextBlockHeight := g.Tip().Header.Height //+ uint32(tvi*mul*4) + 1
	expiry := standalone.CalcTSpendExpiry(int64(nextBlockHeight), tvi, mul)
	start, _, err := standalone.CalcTSpendWindow(expiry, tvi, mul)
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt key for test.
	wrongKey := make([]byte, len(privKey))
	copy(wrongKey, privKey)
	wrongKey[len(wrongKey)-1] = ^wrongKey[len(wrongKey)-1]

	tspendAmount1 := uint64(devsub / 3)
	tspendFee := uint64(0)
	tspend1 := g.CreateTreasuryTSpend(wrongKey, []chaingen.AddressAmountTuple{
		{
			Amount: dcrutil.Amount(tspendAmount1 - tspendFee),
		},
	},
		dcrutil.Amount(tspendFee), expiry)
	tspend1Hash := tspend1.TxHash()

	// ---------------------------------------------------------------------
	// Generate enough blocks to get to TVI.
	//
	//   ... -> bva19 -> bpretvi0 -> bpretvi1
	// ---------------------------------------------------------------------
	outs := g.OldestCoinbaseOuts()
	for i := uint32(0); i < start-nextBlockHeight-1; i++ {
		name := fmt.Sprintf("bpretvi%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase)
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
	}

	// ---------------------------------------------------------------------
	// Generate TVI*MUL of yes votes for TSpend,
	//
	//   ... -> bpretvi1 -> btvi0 -> ... -> btvi7
	// ---------------------------------------------------------------------

	voteCount := params.TicketsPerBlock
	for i := uint64(0); i < tvi*mul; i++ {
		name := fmt.Sprintf("btvi%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase,
			addTSpendVotes(t,
				[]*chainhash.Hash{
					&tspend1Hash,
				},
				[]stake.TreasuryVoteT{
					stake.TreasuryVoteYes,
				},
				voteCount, false))
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
	}

	// Assert that we are on a TVI.
	if standalone.IsTreasuryVoteInterval(uint64(g.Tip().Header.Height), tvi) {
		t.Fatalf("expected !TVI %v", g.Tip().Header.Height)
	}

	// Assert treasury balance
	ts, err := getTreasuryState(g, g.Tip().BlockHash())
	if err != nil {
		t.Fatal(err)
	}
	if ts.balance != int64(devsub*tvi*mul) {
		t.Fatalf("assert balance got %v want devsub %v", ts.balance,
			devsub*tvi*mul)
	}

	// ---------------------------------------------------------------------
	// Add tspend with invalid signature
	//
	//   ... -> btvi7 ->
	//                \-> double0
	// ---------------------------------------------------------------------

	g.NextBlock("invalidsig0", nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase,
		func(b *wire.MsgBlock) {
			// Add TSpend
			b.AddSTransaction(tspend1)
		})
	g.RejectTipBlock(ErrUnknownPiKey)
}

func TestTSpendExists(t *testing.T) {
	// Use a set of test chain parameters which allow for quicker vote
	// activation as compared to various existing network params.
	params := quickVoteActivationParams()

	// Clone the parameters so they can be mutated, find the correct
	// deployment for the treasury agenda, and, finally, ensure it is
	// always available to vote by removing the time constraints to prevent
	// test failures when the real expiration time passes.
	const tVoteID = chaincfg.VoteIDTreasury
	params = cloneParams(params)
	tVersion, deployment, err := findDeployment(params, tVoteID)
	if err != nil {
		t.Fatal(err)
	}
	removeDeploymentTimeConstraints(deployment)

	// Shorter versions of useful params for convenience.
	cbm := params.CoinbaseMaturity
	tvi := params.TreasuryVoteInterval
	mul := params.TreasuryVoteIntervalMultiplier

	// Create a test harness initialized with the genesis block as the tip.
	g, teardownFunc := newChaingenHarness(t, params, "treasurytest")
	defer teardownFunc()

	// replaceTreasuryVersions is a munge function which modifies the
	// provided block by replacing the block, stake, and vote versions with
	// the treasury deployment version.
	replaceTreasuryVersions := func(b *wire.MsgBlock) {
		chaingen.ReplaceBlockVersion(int32(tVersion))(b)
		chaingen.ReplaceStakeVersion(tVersion)(b)
		chaingen.ReplaceVoteVersions(tVersion)(b)
	}

	// ---------------------------------------------------------------------
	// Generate and accept enough blocks with the appropriate vote bits set
	// to reach one block prior to the treasury agenda becoming active.
	// ---------------------------------------------------------------------

	g.AdvanceToStakeValidationHeight()
	g.AdvanceFromSVHToActiveAgendas(tVoteID)

	// Ensure treasury agenda is active.
	tipHash := &g.chain.BestSnapshot().Hash
	gotActive, err := g.chain.IsTreasuryAgendaActive(tipHash)
	if err != nil {
		t.Fatalf("IsTreasuryAgendaActive: %v", err)
	}
	if !gotActive {
		t.Fatalf("IsTreasuryAgendaActive: expected enabled treasury")
	}

	// splitSecondRegularTxOutputs is a munge function which modifies the
	// provided block by replacing its second regular transaction with one
	// that creates several utxos.
	const splitTxNumOutputs = 6
	splitSecondRegularTxOutputs := func(b *wire.MsgBlock) {
		// Remove the current outputs of the second transaction while
		// saving the relevant public key script, input amount, and fee
		// for below.
		tx := b.Transactions[1]
		inputAmount := tx.TxIn[0].ValueIn
		pkScript := tx.TxOut[0].PkScript
		fee := inputAmount - tx.TxOut[0].Value
		tx.TxOut = tx.TxOut[:0]

		// Final outputs are the input amount minus the fee split into
		// more than one output.  These are intended to provide
		// additional utxos for testing.
		outputAmount := inputAmount - fee
		splitAmount := outputAmount / splitTxNumOutputs
		for i := 0; i < splitTxNumOutputs; i++ {
			if i == splitTxNumOutputs-1 {
				splitAmount = outputAmount -
					splitAmount*(splitTxNumOutputs-1)
			}
			tx.AddTxOut(wire.NewTxOut(splitAmount, pkScript))
		}
	}

	// Generate spendable outputs to do fork tests with.
	var txOuts [][]chaingen.SpendableOut
	genBlocks := cbm * 8
	for i := uint16(0); i < genBlocks; i++ {
		outs := g.OldestCoinbaseOuts()
		name := fmt.Sprintf("bouts%v", i)
		g.NextBlock(name, &outs[0], outs[1:], replaceTreasuryVersions,
			replaceCoinbase, splitSecondRegularTxOutputs)
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()

		souts := make([]chaingen.SpendableOut, 0, splitTxNumOutputs)
		for j := 0; j < splitTxNumOutputs; j++ {
			spendableOut := chaingen.MakeSpendableOut(g.Tip(), 1,
				uint32(j))
			souts = append(souts, spendableOut)
		}
		txOuts = append(txOuts, souts)
	}

	// ---------------------------------------------------------------------
	// Create TSPEND in mempool
	// ---------------------------------------------------------------------
	nextBlockHeight := g.Tip().Header.Height + 1
	expiry := standalone.CalcTSpendExpiry(int64(nextBlockHeight), tvi, mul)
	start, _, err := standalone.CalcTSpendWindow(expiry, tvi, mul)
	if err != nil {
		t.Fatal(err)
	}

	tspendAmount := uint64(devsub)
	tspendFee := uint64(0)
	tspend := g.CreateTreasuryTSpend(privKey, []chaingen.AddressAmountTuple{{
		Amount: dcrutil.Amount(tspendAmount - tspendFee),
	}}, dcrutil.Amount(tspendFee), expiry)
	tspendHash := tspend.TxHash()

	// ---------------------------------------------------------------------
	// Generate enough blocks to get to TVI.
	//
	//   ... -> bouts -> bpretvi0 -> bpretvi1
	// ---------------------------------------------------------------------

	outs := g.OldestCoinbaseOuts()
	for i := uint32(0); i < start-nextBlockHeight; i++ {
		name := fmt.Sprintf("bpretvi%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase)
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
	}

	// ---------------------------------------------------------------------
	// Generate two TVI with votes.
	//
	//   ... -> b0 ... -> b7
	// ---------------------------------------------------------------------

	voteCount := params.TicketsPerBlock
	for i := uint64(0); i < tvi*2; i++ {
		name := fmt.Sprintf("b%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase,
			addTSpendVotes(t, []*chainhash.Hash{&tspendHash},
				[]stake.TreasuryVoteT{stake.TreasuryVoteYes},
				voteCount, false))
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
	}

	// ---------------------------------------------------------------------
	// Generate a TVI and mine same TSpend, which has to be rejected.
	//
	//   ... -> be0 ... -> be3 ->
	//                         \-> bexists0
	// ---------------------------------------------------------------------

	startTip := g.TipName()
	for i := uint64(0); i < tvi; i++ {
		name := fmt.Sprintf("be%v", i)
		if i == 0 {
			// Mine tspend.
			g.NextBlock(name, nil, txOuts[i][1:],
				replaceTreasuryVersions,
				replaceCoinbase, func(b *wire.MsgBlock) {
					// Add TSpend
					b.AddSTransaction(tspend)
				})
		} else {
			g.NextBlock(name, nil, txOuts[i][1:],
				replaceTreasuryVersions,
				replaceCoinbase)
		}
		g.AcceptTipBlock()
	}
	oldTip := g.TipName()

	// Mine tspend again.
	g.NextBlock("bexists0", nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase,
		func(b *wire.MsgBlock) {
			// Add TSpend
			b.AddSTransaction(tspend)
		})
	g.RejectTipBlock(ErrTSpendExists)

	// ---------------------------------------------------------------------
	// Generate a TVI and mine same TSpend, should not exist since it is a
	// fork.
	//
	//      /-> be0 ... -> be3 -> bexists0
	// ... -> b3
	//      \-> bep0 ... -> bep3 -> bexists1
	// ---------------------------------------------------------------------

	g.SetTip(startTip)
	var nextFork uint64
	for i := uint64(0); i < tvi; i++ {
		name := fmt.Sprintf("bep%v", i)
		g.NextBlock(name, nil, txOuts[i][1:], replaceTreasuryVersions,
			replaceCoinbase)
		g.AcceptedToSideChainWithExpectedTip(oldTip)
		nextFork = i + 1
	}

	// Mine tspend again.
	g.NextBlock("bexists1", nil, txOuts[nextFork][1:], replaceTreasuryVersions,
		replaceCoinbase,
		func(b *wire.MsgBlock) {
			// Add TSpend
			b.AddSTransaction(tspend)
		})
	g.AcceptTipBlock()

	// ---------------------------------------------------------------------
	// Generate a TVI and mine same TSpend, should not exist since it is a
	// fork.
	//
	//      /-> be0 ... -> be3 -> bexists0
	// ... -> b3
	//      \-> bep0 ... -> bep3 -> bexists1 ->bep4
	//       \-> bepp0 ... -> bepp3 -> bexists2 -> bxxx0 .. bxxx3
	// ---------------------------------------------------------------------

	// Generate one more block to extend current best chain.
	name := fmt.Sprintf("bep%v", nextFork)
	g.NextBlock(name, nil, txOuts[nextFork+1][1:], replaceTreasuryVersions,
		replaceCoinbase)
	g.AcceptTipBlock()
	oldTip = g.TipName()
	oldHeight := g.Tip().Header.Height

	// Create bepp fork
	g.SetTip(startTip)
	txIdx := uint64(0)
	for i := uint64(0); i < tvi; i++ {
		name := fmt.Sprintf("bepp%v", i)
		g.NextBlock(name, nil, txOuts[i][1:],
			replaceTreasuryVersions, replaceCoinbase)
		g.AcceptedToSideChainWithExpectedTip(oldTip)
		txIdx = i + 1
	}

	// Mine tspend yet again.
	g.NextBlock("bexists2", nil, txOuts[txIdx][1:],
		replaceTreasuryVersions, replaceCoinbase,
		func(b *wire.MsgBlock) {
			// Add TSpend
			b.AddSTransaction(tspend)
		})
	g.AcceptedToSideChainWithExpectedTip(oldTip)
	txIdx++

	// Force reorg
	for i := uint64(0); i < tvi; i++ {
		name := fmt.Sprintf("bxxx%v", i)
		b := g.NextBlock(name, nil, txOuts[txIdx][1:],
			replaceTreasuryVersions, replaceCoinbase)
		if b.Header.Height <= oldHeight {
			g.AcceptedToSideChainWithExpectedTip(oldTip)
		} else {
			g.AcceptTipBlock()
		}
		txIdx++
	}
}

func TestTreasuryBalance(t *testing.T) {
	// Use a set of test chain parameters which allow for quicker vote
	// activation as compared to various existing network params.
	params := quickVoteActivationParams()

	// Clone the parameters so they can be mutated, find the correct
	// deployment for the treasury agenda, and, finally, ensure it is
	// always available to vote by removing the time constraints to prevent
	// test failures when the real expiration time passes.
	const tVoteID = chaincfg.VoteIDTreasury
	params = cloneParams(params)
	tVersion, deployment, err := findDeployment(params, tVoteID)
	if err != nil {
		t.Fatal(err)
	}
	removeDeploymentTimeConstraints(deployment)

	// Create a test harness initialized with the genesis block as the tip.
	g, teardownFunc := newChaingenHarness(t, params, "treasurytest")
	defer teardownFunc()

	// replaceTreasuryVersions is a munge function which modifies the
	// provided block by replacing the block, stake, and vote versions with
	// the treasury deployment version.
	replaceTreasuryVersions := func(b *wire.MsgBlock) {
		chaingen.ReplaceBlockVersion(int32(tVersion))(b)
		chaingen.ReplaceStakeVersion(tVersion)(b)
		chaingen.ReplaceVoteVersions(tVersion)(b)
	}

	// ---------------------------------------------------------------------
	// Generate and accept enough blocks with the appropriate vote bits set
	// to reach one block prior to the treasury agenda becoming active.
	// ---------------------------------------------------------------------

	g.AdvanceToStakeValidationHeight()
	g.AdvanceFromSVHToActiveAgendas(tVoteID)

	// Ensure treasury agenda is active.
	tipHash := &g.chain.BestSnapshot().Hash
	gotActive, err := g.chain.IsTreasuryAgendaActive(tipHash)
	if err != nil {
		t.Fatalf("IsTreasuryAgendaActive: %v", err)
	}
	if !gotActive {
		t.Fatalf("IsTreasuryAgendaActive: expected enabled treasury")
	}

	// ---------------------------------------------------------------------
	// Create 10 blocks that has a tadd without change.
	//
	//   ... -> b0
	// ---------------------------------------------------------------------

	blockCount := 10
	expectedTotal := devsub *
		(blockCount - int(params.CoinbaseMaturity)) // dev subsidy
	skippedTotal := 0
	for i := 0; i < blockCount; i++ {
		amount := i + 1
		if i < blockCount-int(params.CoinbaseMaturity) {
			expectedTotal += amount
		} else {
			skippedTotal += amount
		}
		outs := g.OldestCoinbaseOuts()
		name := fmt.Sprintf("b%v", i)
		_ = g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase,
			func(b *wire.MsgBlock) {
				// Add TADD
				tx := g.CreateTreasuryTAdd(&outs[0],
					dcrutil.Amount(amount),
					dcrutil.Amount(0))
				tx.Version = wire.TxVersionTreasury
				b.AddSTransaction(tx)
			})
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
	}
	iterations := 1

	ts, err := getTreasuryState(g, g.Tip().BlockHash())
	if err != nil {
		t.Fatal(err)
	}

	if ts.balance != int64(expectedTotal) {
		t.Fatalf("invalid balance: total %v expected %v",
			ts.balance, expectedTotal)
	}
	if ts.values[1].amount != int64(blockCount) {
		t.Fatalf("invalid Value: total %v expected %v",
			ts.values[0], int64(blockCount))
	}

	// ---------------------------------------------------------------------
	// Create 10 blocks that has a tadd with change. Pretend that the TSpend
	// transaction is in the mempool and vote on it.
	//
	//   ... -> b10
	// ---------------------------------------------------------------------

	// This looks a little funky but it was coppied from the prior TSPEND
	// test that created this many tspends. Since that is no longer
	// possible use the for loop to get to the same totals.
	var tspendAmount, tspendFee int
	nextTipHeight := int64(g.Tip().Header.Height + 1)
	expiry := standalone.CalcTSpendExpiry(nextTipHeight,
		params.TreasuryVoteInterval,
		params.TreasuryVoteIntervalMultiplier)
	for i := 0; i < blockCount*2+int(params.CoinbaseMaturity); i++ {
		if i > (blockCount * 2) {
			// Skip last CoinbaseMaturity blocks.
			break
		}
		tspendAmount += i + 1
		tspendFee++
	}
	tspend := g.CreateTreasuryTSpend(privKey, []chaingen.AddressAmountTuple{
		{
			Amount: dcrutil.Amount(tspendAmount - tspendFee),
		},
	},
		dcrutil.Amount(tspendFee), expiry)
	tspendHash := tspend.TxHash()

	// Treasury votes munger.
	addTSpendVotes := func(b *wire.MsgBlock) {
		// Find SSGEN and append Yes vote.
		for k, v := range b.STransactions {
			if !stake.IsSSGen(v, yesTreasury) {
				continue
			}
			if len(v.TxOut) != 3 {
				t.Fatalf("expected SSGEN.TxOut len 3 got %v",
					len(v.TxOut))
			}

			// Append vote: OP_RET OP_DATA <TV> <tspend hash> <vote bits>
			vote := make([]byte, 2+chainhash.HashSize+1)
			vote[0] = 'T'
			vote[1] = 'V'
			copy(vote[2:], tspendHash[:])
			vote[len(vote)-1] = 0x01 // Yes
			s, err := txscript.NewScriptBuilder().AddOp(txscript.OP_RETURN).
				AddData(vote).Script()
			if err != nil {
				t.Fatal(err)
			}
			b.STransactions[k].TxOut = append(b.STransactions[k].TxOut,
				&wire.TxOut{
					PkScript: s,
				})
			b.STransactions[k].Version = wire.TxVersionTreasury

			// Assert vote insertion worked.
			_, err = stake.GetSSGenTreasuryVotes(s)
			if err != nil {
				t.Fatalf("expected treasury vote: %v", err)
			}

			// Assert this remains a valid SSGEN.
			err = stake.CheckSSGen(b.STransactions[k], yesTreasury)
			if err != nil {
				t.Fatalf("expected SSGen: %v", err)
			}
		}
	}

	expectedTotal += skippedTotal
	expectedTotal += devsub * blockCount // dev subsidy
	for i := blockCount; i < blockCount*2; i++ {
		amount := i + 1
		if i < (blockCount*2)-int(params.CoinbaseMaturity) {
			expectedTotal += amount
		}
		outs := g.OldestCoinbaseOuts()
		name := fmt.Sprintf("b%v", i)
		_ = g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase,
			addTSpendVotes,
			func(b *wire.MsgBlock) {
				tx := g.CreateTreasuryTAdd(&outs[0],
					dcrutil.Amount(amount),
					dcrutil.Amount(1))
				tx.Version = wire.TxVersionTreasury
				b.AddSTransaction(tx)
			})
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
	}
	iterations += 1

	ts, err = getTreasuryState(g, g.Tip().BlockHash())
	if err != nil {
		t.Fatal(err)
	}

	if ts.balance != int64(expectedTotal) {
		t.Fatalf("invalid balance: total %v expected %v",
			ts.balance, expectedTotal)
	}
	if ts.values[1].amount != int64(blockCount*2) {
		t.Fatalf("invalid Value: total %v expected %v",
			ts.values[0], int64(blockCount)*2)
	}

	// ---------------------------------------------------------------------
	// Create 20 blocks that has a tspend and params.CoinbaseMaturity more
	// to bring treasury balance back to 0.
	//
	//   ... -> b20
	// ---------------------------------------------------------------------

	var doneTSpend bool
	for i := 0; i < blockCount*2+int(params.CoinbaseMaturity); i++ {
		outs := g.OldestCoinbaseOuts()
		name := fmt.Sprintf("b%v", i+blockCount*2)
		if (g.Tip().Header.Height+1)%4 == 0 && !doneTSpend {
			// Insert TSPEND
			g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
				replaceCoinbase,
				func(b *wire.MsgBlock) {
					// Add TSpend
					b.AddSTransaction(tspend)
				})
			doneTSpend = true
		} else {
			g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
				replaceCoinbase)
		}
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
	}
	iterations += 2 // We generate 2*blockCount

	ts, err = getTreasuryState(g, g.Tip().BlockHash())
	if err != nil {
		t.Fatal(err)
	}

	expected := int64(devsub*blockCount*iterations - tspendFee) // Expected devsub
	if ts.balance != expected {
		t.Fatalf("invalid balance: total %v expected %v",
			ts.balance, expected)
	}
}

// newTxOut returns a new transaction output with the given parameters.
func newTxOut(amount int64, pkScriptVer uint16, pkScript []byte) *wire.TxOut {
	return &wire.TxOut{
		Value:    amount,
		Version:  pkScriptVer,
		PkScript: pkScript,
	}
}

func createTAdd(spend chaingen.SpendableOut, changeDivisor dcrutil.Amount, params *chaincfg.Params) func(b *wire.MsgBlock) {
	redeemScript := []byte{txscript.OP_TRUE}
	p2shOpTrueAddr, err := stdaddr.NewAddressScriptHashV0(redeemScript, params)
	if err != nil {
		panic(err)
	}

	return func(b *wire.MsgBlock) {
		amount := spend.Amount()
		tx := wire.NewMsgTx()
		tx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: spend.PrevOut(),
			Sequence:         wire.MaxTxInSequenceNum,
			ValueIn:          int64(amount),
			BlockHeight:      spend.BlockHeight(),
			BlockIndex:       spend.BlockIndex(),
			SignatureScript:  []byte{txscript.OP_DATA_1, txscript.OP_TRUE},
		})

		// Add negative change.
		trsyAddScript := []byte{txscript.OP_TADD}
		if changeDivisor != 0 {
			changeScriptVer, changeScript := p2shOpTrueAddr.StakeChangeScript()

			change := spend.Amount() / changeDivisor
			amount := spend.Amount() - change
			tx.AddTxOut(wire.NewTxOut(int64(amount), trsyAddScript))
			tx.AddTxOut(newTxOut(int64(change), changeScriptVer, changeScript))
		} else {
			tx.AddTxOut(wire.NewTxOut(int64(amount), trsyAddScript))
		}
		tx.Version = wire.TxVersionTreasury
		b.AddSTransaction(tx)
	}
}

func TestTAddCorners(t *testing.T) {
	// Use a set of test chain parameters which allow for quicker vote
	// activation as compared to various existing network params.
	params := quickVoteActivationParams()

	// Shorter versions of useful params for convenience.
	tvi := params.TreasuryVoteInterval
	mul := params.TreasuryVoteIntervalMultiplier
	cbm := params.CoinbaseMaturity

	// Clone the parameters so they can be mutated, find the correct
	// deployment for the treasury agenda, and, finally, ensure it is
	// always available to vote by removing the time constraints to prevent
	// test failures when the real expiration time passes.
	const tVoteID = chaincfg.VoteIDTreasury
	params = cloneParams(params)
	tVersion, deployment, err := findDeployment(params, tVoteID)
	if err != nil {
		t.Fatal(err)
	}
	removeDeploymentTimeConstraints(deployment)

	// Create a test harness initialized with the genesis block as the tip.
	g, teardownFunc := newChaingenHarness(t, params, "treasurytest")
	defer teardownFunc()

	// replaceTreasuryVersions is a munge function which modifies the
	// provided block by replacing the block, stake, and vote versions with the
	// treasury agenda version.
	replaceTreasuryVersions := func(b *wire.MsgBlock) {
		chaingen.ReplaceBlockVersion(int32(tVersion))(b)
		chaingen.ReplaceStakeVersion(tVersion)(b)
		chaingen.ReplaceVoteVersions(tVersion)(b)
	}

	// ---------------------------------------------------------------------
	// Generate and accept enough blocks with the appropriate vote bits set
	// to reach one block prior to the treasury agenda becoming active.
	// ---------------------------------------------------------------------

	g.AdvanceToStakeValidationHeight()
	g.AdvanceFromSVHToActiveAgendas(tVoteID)

	// Ensure treasury agenda is active.
	tipHash := &g.chain.BestSnapshot().Hash
	gotActive, err := g.chain.IsTreasuryAgendaActive(tipHash)
	if err != nil {
		t.Fatalf("IsTreasuryAgendaActive: %v", err)
	}
	if !gotActive {
		t.Fatalf("IsTreasuryAgendaActive: expected enabled treasury")
	}

	// splitSecondRegularTxOutputs is a munge function which modifies the
	// provided block by replacing its second regular transaction with one
	// that creates several utxos.
	const splitTxNumOutputs = 6
	splitSecondRegularTxOutputs := func(b *wire.MsgBlock) {
		// Remove the current outputs of the second transaction while
		// saving the relevant public key script, input amount, and fee
		// for below.
		tx := b.Transactions[1]
		inputAmount := tx.TxIn[0].ValueIn
		pkScript := tx.TxOut[0].PkScript
		fee := inputAmount - tx.TxOut[0].Value
		tx.TxOut = tx.TxOut[:0]

		// Final outputs are the input amount minus the fee split into
		// more than one output.  These are intended to provide
		// additional utxos for testing.
		outputAmount := inputAmount - fee
		splitAmount := outputAmount / splitTxNumOutputs
		for i := 0; i < splitTxNumOutputs; i++ {
			if i == splitTxNumOutputs-1 {
				splitAmount = outputAmount -
					splitAmount*(splitTxNumOutputs-1)
			}
			tx.AddTxOut(wire.NewTxOut(splitAmount, pkScript))
		}
	}

	// Generate spendable outputs to do fork tests with.
	var txOuts [][]chaingen.SpendableOut
	genBlocks := cbm * 8
	for i := uint16(0); i < genBlocks; i++ {
		outs := g.OldestCoinbaseOuts()
		name := fmt.Sprintf("bouts%v", i)
		g.NextBlock(name, &outs[0], outs[1:], replaceTreasuryVersions,
			replaceCoinbase, splitSecondRegularTxOutputs)
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()

		souts := make([]chaingen.SpendableOut, 0, splitTxNumOutputs)
		for j := 0; j < splitTxNumOutputs; j++ {
			spendableOut := chaingen.MakeSpendableOut(g.Tip(), 1,
				uint32(j))
			souts = append(souts, spendableOut)
		}
		txOuts = append(txOuts, souts)
	}

	// ---------------------------------------------------------------------
	// Create TAdd with negative change.
	//
	//   ... -> bn0
	// ---------------------------------------------------------------------
	mungeValueChange := func(b *wire.MsgBlock) {
		for k := range b.STransactions {
			if !stake.IsTAdd(b.STransactions[k]) {
				continue
			}
			b.STransactions[k].TxOut[1].Value =
				-b.STransactions[k].TxOut[1].Value
			break
		}
	}

	startTip := g.TipName()
	g.NextBlock("bn0", nil, txOuts[0][1:], replaceTreasuryVersions,
		replaceCoinbase,
		createTAdd(txOuts[0][0], 10, params),
		mungeValueChange)
	g.RejectTipBlock(ErrBadTxOutValue)

	// ---------------------------------------------------------------------
	// Create TAdd with negative in amount.
	//
	//   ... -> bn1
	// ---------------------------------------------------------------------

	mungeValueIn := func(b *wire.MsgBlock) {
		for k := range b.STransactions {
			if !stake.IsTAdd(b.STransactions[k]) {
				continue
			}
			b.STransactions[k].TxIn[0].ValueIn =
				-b.STransactions[k].TxIn[0].ValueIn
			break
		}
	}

	g.SetTip(startTip)
	g.NextBlock("bn1", nil, txOuts[0][1:], replaceTreasuryVersions,
		replaceCoinbase,
		createTAdd(txOuts[0][0], 10, params),
		mungeValueIn)
	g.RejectTipBlock(ErrFraudAmountIn)

	// ---------------------------------------------------------------------
	// Create TAdd with negative out amount.
	//
	//   ... -> bn2
	// ---------------------------------------------------------------------

	mungeValueOut := func(b *wire.MsgBlock) {
		for k := range b.STransactions {
			if !stake.IsTAdd(b.STransactions[k]) {
				continue
			}
			b.STransactions[k].TxOut[0].Value =
				-b.STransactions[k].TxOut[0].Value
			break
		}
	}

	g.SetTip(startTip)
	g.NextBlock("bn2", nil, txOuts[0][1:], replaceTreasuryVersions,
		replaceCoinbase,
		createTAdd(txOuts[0][0], 10, params),
		mungeValueOut)
	g.RejectTipBlock(ErrBadTxOutValue)

	// ---------------------------------------------------------------------
	// Create TAdd with 0 change.
	//
	//   ... -> bn3
	// ---------------------------------------------------------------------

	mungeChangeValue := func(b *wire.MsgBlock) {
		for k := range b.STransactions {
			if !stake.IsTAdd(b.STransactions[k]) {
				continue
			}
			b.STransactions[k].TxOut[1].Value = 0
			break
		}
	}

	g.SetTip(startTip)
	g.NextBlock("bn3", nil, txOuts[0][1:], replaceTreasuryVersions,
		replaceCoinbase,
		createTAdd(txOuts[0][0], 10, params),
		mungeChangeValue)
	g.RejectTipBlock(ErrInvalidTAddChange)

	_ = tvi
	_ = mul
}

func TestTreasuryBaseCorners(t *testing.T) {
	// Use a set of test chain parameters which allow for quicker vote
	// activation as compared to various existing network params.
	params := quickVoteActivationParams()

	// Clone the parameters so they can be mutated, find the correct
	// deployment for the treasury agenda, and, finally, ensure it is
	// always available to vote by removing the time constraints to prevent
	// test failures when the real expiration time passes.
	const tVoteID = chaincfg.VoteIDTreasury
	params = cloneParams(params)
	tVersion, deployment, err := findDeployment(params, tVoteID)
	if err != nil {
		t.Fatal(err)
	}
	removeDeploymentTimeConstraints(deployment)

	// Create a test harness initialized with the genesis block as the tip.
	g, teardownFunc := newChaingenHarness(t, params, "treasurytest")
	defer teardownFunc()

	// replaceTreasuryVersions is a munge function which modifies the provided
	// block by replacing the block, stake, and vote versions with the treasury
	// deployment version.
	replaceTreasuryVersions := func(b *wire.MsgBlock) {
		chaingen.ReplaceBlockVersion(int32(tVersion))(b)
		chaingen.ReplaceStakeVersion(tVersion)(b)
		chaingen.ReplaceVoteVersions(tVersion)(b)
	}

	// removeAllButTreasurybase is a munge function which modifies the provided
	// block by removing all stake transactions other than the treasurybase.
	removeAllButTreasurybase := func(b *wire.MsgBlock) {
		b.Header.FreshStake = 0
		b.STransactions = b.STransactions[:1]
	}

	// removeStakeTxns is a munge function which modifies the provided block by
	// removing all stake transactions other than votes.
	removeStakeTxns := func(b *wire.MsgBlock) {
		b.Header.FreshStake = 0
		b.Header.Revocations = 0
		b.STransactions = b.STransactions[1:6]
	}

	// dupTreasurybase is a munge function which modifies the provided block by
	// adding a duplicate treasurybase at the end of the stake tree.
	dupTreasurybase := func(b *wire.MsgBlock) {
		txCopy := b.STransactions[0].Copy()
		txCopy.TxOut[1].PkScript[len(txCopy.TxOut[1].PkScript)-1] ^= 0x55
		b.AddSTransaction(txCopy)
	}

	// flipTreasurybase is a munge function which modifies the provided block by
	// swapping the treasurybase with the second transaction in the stake tree.
	flipTreasurybase := func(b *wire.MsgBlock) {
		stakeTxns := b.STransactions
		stakeTxns[0], stakeTxns[1] = stakeTxns[1], stakeTxns[0]
	}

	// removeTreasurybase is a munge function which modifies the provided block
	// by removing the treasurybase from the stake tree.
	removeTreasurybase := func(b *wire.MsgBlock) {
		b.STransactions = b.STransactions[1:]
	}

	// changeHeightTreasurybase is a munge function which modifies the provided
	// block by adding one to the height encoded in the treasurybase.
	changeHeightTreasurybase := func(b *wire.MsgBlock) {
		b.STransactions[0].TxOut[1].PkScript[2]++
	}

	// corruptLengthTreasurybase is a munge function which modifies the provided
	// block by mutating the treasurybase script to corrupt it.
	corruptLengthTreasurybase := func(b *wire.MsgBlock) {
		s := b.STransactions[0].TxOut[1].PkScript
		b.STransactions[0].TxOut[1].PkScript = s[:len(s)-1]
	}

	// corruptTreasurybaseValueIn is a munge function which modifies the
	// provided block by mutating the treasurybase in value.
	corruptTreasurybaseValueIn := func(b *wire.MsgBlock) {
		b.STransactions[0].TxIn[0].ValueIn -= 1
	}

	// corruptTreasurybaseValueOut is a munge function which modifies the
	// provided block by mutating the treasurybase out value.
	corruptTreasurybaseValueOut := func(b *wire.MsgBlock) {
		b.STransactions[0].TxOut[0].Value -= 1
	}

	// ---------------------------------------------------------------------
	// Generate and accept enough blocks with the appropriate vote bits set
	// to reach one block prior to the treasury agenda becoming active.
	// ---------------------------------------------------------------------

	g.AdvanceToStakeValidationHeight()
	g.AdvanceFromSVHToActiveAgendas(tVoteID)

	// Ensure treasury agenda is active.
	tipHash := &g.chain.BestSnapshot().Hash
	gotActive, err := g.chain.IsTreasuryAgendaActive(tipHash)
	if err != nil {
		t.Fatalf("IsTreasuryAgendaActive: %v", err)
	}
	if !gotActive {
		t.Fatalf("IsTreasuryAgendaActive: expected enabled treasury")
	}

	// ---------------------------------------------------------------------
	// Append a treasurybase to STransactions.
	// ---------------------------------------------------------------------

	outs := g.OldestCoinbaseOuts()
	startTip := g.TipName()
	g.NextBlock("twotb0", nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase, dupTreasurybase)
	g.RejectTipBlock(ErrMultipleTreasurybases)

	// ---------------------------------------------------------------------
	// Flip STransactions 0 and 1.
	// ---------------------------------------------------------------------

	g.SetTip(startTip)
	g.NextBlock("notbon0", nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase, flipTreasurybase)
	g.RejectTipBlock(ErrFirstTxNotTreasurybase)

	// ---------------------------------------------------------------------
	// No treasurybase.
	// ---------------------------------------------------------------------

	g.SetTip(startTip)
	g.NextBlock("notb0", nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase, removeTreasurybase)
	g.RejectTipBlock(ErrFirstTxNotTreasurybase)

	// ---------------------------------------------------------------------
	// No treasurybase and no tickets.
	// ---------------------------------------------------------------------

	g.SetTip(startTip)
	g.NextBlock("nothing0", nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase, removeStakeTxns)
	g.RejectTipBlock(ErrFirstTxNotTreasurybase)

	// ---------------------------------------------------------------------
	// Treasury base invalid height
	// ---------------------------------------------------------------------
	g.SetTip(startTip)
	g.NextBlock("height0", nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase, changeHeightTreasurybase)
	g.RejectTipBlock(ErrTreasurybaseHeight)

	// ---------------------------------------------------------------------
	// Treasury base invalid OP_RETURN script length.
	// ---------------------------------------------------------------------
	g.SetTip(startTip)
	g.NextBlock("length0", nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase, corruptLengthTreasurybase)
	g.RejectTipBlock(ErrFirstTxNotTreasurybase)

	// ---------------------------------------------------------------------
	// Only treasury base.
	// ---------------------------------------------------------------------
	g.SetTip(startTip)
	g.NextBlock("novotes0", nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase, removeAllButTreasurybase)
	g.RejectTipBlock(ErrVotesMismatch)

	// ---------------------------------------------------------------------
	// Treasury base invalid TxIn[0].Value
	// ---------------------------------------------------------------------
	g.SetTip(startTip)
	g.NextBlock("invalidin0", nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase, corruptTreasurybaseValueIn)
	g.RejectTipBlock(ErrBadTreasurybaseAmountIn)

	// ---------------------------------------------------------------------
	// Treasury base invalid TxOut[0].Value
	// ---------------------------------------------------------------------
	g.SetTip(startTip)
	g.NextBlock("invalidout0", nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase, corruptTreasurybaseValueOut)
	g.RejectTipBlock(ErrTreasurybaseOutValue)

	// Note we can't hit the following errors in consensus:
	// * ErrFirstTxNotTreasurybase (missing OP_RETURN)
	// * ErrFirstTxNotTreasurybase (version)
	// * ErrTreasurybaseTxNotOpReturn
	// * ErrInvalidTreasurybaseTxOutputs
	// * ErrInvalidTreasurybaseVersion
	// * ErrInvalidTreasurybaseScript
}

func TestTSpendCorners(t *testing.T) {
	// Use a set of test chain parameters which allow for quicker vote
	// activation as compared to various existing network params.
	params := quickVoteActivationParams()

	// Shorter versions of useful params for convenience.
	tvi := params.TreasuryVoteInterval
	mul := params.TreasuryVoteIntervalMultiplier

	// Clone the parameters so they can be mutated, find the correct
	// deployment for the treasury agenda, and, finally, ensure it is
	// always available to vote by removing the time constraints to prevent
	// test failures when the real expiration time passes.
	const tVoteID = chaincfg.VoteIDTreasury
	params = cloneParams(params)
	tVersion, deployment, err := findDeployment(params, tVoteID)
	if err != nil {
		t.Fatal(err)
	}
	removeDeploymentTimeConstraints(deployment)

	// Create a test harness initialized with the genesis block as the tip.
	g, teardownFunc := newChaingenHarness(t, params, "treasurytest")
	defer teardownFunc()

	// replaceTreasuryVersions is a munge function which modifies the provided
	// block by replacing the block, stake, and vote versions with the treasury
	// deployment version.
	replaceTreasuryVersions := func(b *wire.MsgBlock) {
		chaingen.ReplaceBlockVersion(int32(tVersion))(b)
		chaingen.ReplaceStakeVersion(tVersion)(b)
		chaingen.ReplaceVoteVersions(tVersion)(b)
	}

	// ---------------------------------------------------------------------
	// Generate and accept enough blocks with the appropriate vote bits set
	// to reach one block prior to the treasury agenda becoming active.
	// ---------------------------------------------------------------------

	g.AdvanceToStakeValidationHeight()
	g.AdvanceFromSVHToActiveAgendas(tVoteID)

	// Ensure treasury agenda is active.
	tipHash := &g.chain.BestSnapshot().Hash
	gotActive, err := g.chain.IsTreasuryAgendaActive(tipHash)
	if err != nil {
		t.Fatalf("IsTreasuryAgendaActive: %v", err)
	}
	if !gotActive {
		t.Fatalf("IsTreasuryAgendaActive: expected enabled treasury")
	}

	// ---------------------------------------------------------------------
	// Create TSpend in mempool
	// ---------------------------------------------------------------------
	nextBlockHeight := g.Tip().Header.Height + 1
	tspendAmount := devsub
	tspendFee := 100
	expiry := standalone.CalcTSpendExpiry(int64(nextBlockHeight), tvi, mul)
	start, _, err := standalone.CalcTSpendWindow(expiry, tvi, mul)
	if err != nil {
		t.Fatal(err)
	}
	tspend := g.CreateTreasuryTSpend(privKey, []chaingen.AddressAmountTuple{{
		Amount: dcrutil.Amount(tspendAmount - tspendFee),
	}}, dcrutil.Amount(tspendFee), expiry)
	tspendHash := tspend.TxHash()

	// ---------------------------------------------------------------------
	// Get to TVI
	//   ... -> pretvi1
	// ---------------------------------------------------------------------

	outs := g.OldestCoinbaseOuts()
	for i := uint32(0); i < start-nextBlockHeight; i++ {
		name := fmt.Sprintf("bpretvi%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase)
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
	}

	// ---------------------------------------------------------------------
	// Vote on TSpend
	//   pretvi1 -> btvi0 -> ... -> btvi7
	// ---------------------------------------------------------------------

	voteCount := params.TicketsPerBlock
	for i := uint64(0); i < tvi*mul; i++ {
		name := fmt.Sprintf("btvi%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase,
			addTSpendVotes(t, []*chainhash.Hash{&tspendHash},
				[]stake.TreasuryVoteT{stake.TreasuryVoteYes},
				voteCount, false))
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
	}

	// ---------------------------------------------------------------------
	// Mine TSpend with improperly encoded ValueIn.
	// -> btvi7
	// \-> btspend0
	// ---------------------------------------------------------------------

	tspend.TxIn[0].ValueIn++
	g.NextBlock("btspend0", nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase,
		func(b *wire.MsgBlock) {
			// Add TSpend
			b.AddSTransaction(tspend)
		})
	g.RejectTipBlock(ErrInvalidTSpendValueIn)
}

func TestTSpendFirstTVICorner(t *testing.T) {
	// Clone the parameters so they can be mutated and remove the deployment
	// for the treasury agenda to activate it.
	const tVoteID = chaincfg.VoteIDTreasury
	params := chaincfg.RegNetParams()
	params = cloneParams(params)
	removeDeployment(params, tVoteID)

	// Change params to hit corner case.
	params.StakeValidationHeight = 144
	params.TicketPoolSize = 144
	params.TreasuryVoteInterval = 11
	params.TreasuryVoteIntervalMultiplier = 1

	// Shorter versions of useful params for convenience.
	tvi := params.TreasuryVoteInterval
	mul := params.TreasuryVoteIntervalMultiplier
	svh := params.StakeValidationHeight
	t.Logf("svh: %v tvi %v mul %v", svh, tvi, mul)

	// Create a test harness initialized with the genesis block as the tip.
	g, teardownFunc := newChaingenHarness(t, params, "treasurytest")
	defer teardownFunc()

	// With an SVH of 144 and a TVI of 11 and a MUL of 1 create a tspend
	// that expires on block 156 (voting interval [143,154]). Start voting
	// on block 144 (SVH) up to 153 (inclusive) which is 10*5 votes of the
	// total of 55 possible.  That easily is voted in since 60% is 33 yes
	// votes.
	expiry := standalone.CalcTSpendExpiry(140, tvi, mul)
	start, end, err := standalone.CalcTSpendWindow(expiry, tvi, mul)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("tspend expiry %v start %v end %v", expiry, start, end)
	tspend := newFakeCreateTSpend(privKey, []dcrutil.Amount{100000000}, 1,
		expiry)
	tspendHash := tspend.TxHash()
	_, _, err = stake.CheckTSpend(tspend)
	if err != nil {
		t.Fatal(err)
	}

	// ---------------------------------------------------------------------
	// Block One.
	// ---------------------------------------------------------------------

	// Add the required first block.
	//
	//   genesis -> bfb
	g.CreateBlockOne("bfb", 0)
	g.AssertTipHeight(1)
	g.AcceptTipBlock()

	// Assert treasury agenda is indeed active.
	tipHash := &g.chain.BestSnapshot().Hash
	gotActive, err := g.chain.IsTreasuryAgendaActive(tipHash)
	if err != nil {
		t.Fatalf("IsTreasuryAgendaActive: %v", err)
	}
	if !gotActive {
		t.Fatalf("IsTreasuryAgendaActive: expected enabled treasury")
	}

	// ---------------------------------------------------------------------
	// Generate enough blocks to have mature coinbase outputs to work with.
	// Note that going forward all coinbase is munged to also output
	// treasurybase.
	//
	//   genesis -> bfb -> bm0 -> bm1 -> ... -> bm#
	// ---------------------------------------------------------------------

	ticketsPerBlock := params.TicketsPerBlock
	coinbaseMaturity := params.CoinbaseMaturity
	stakeEnabledHeight := params.StakeEnabledHeight
	stakeValidationHeight := params.StakeValidationHeight
	for i := uint16(0); i < coinbaseMaturity; i++ {
		blockName := fmt.Sprintf("bm%d", i)
		g.NextBlock(blockName, nil, nil, replaceCoinbase)
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
	}
	g.AssertTipHeight(uint32(coinbaseMaturity) + 1)

	// ---------------------------------------------------------------------
	// Generate enough blocks to reach the stake enabled height while
	// creating ticket purchases that spend from the coinbases matured
	// above.  This will also populate the pool of immature tickets.
	//
	//   ... -> bm# ... -> bse0 -> bse1 -> ... -> bse#
	// ---------------------------------------------------------------------

	var ticketsPurchased int
	for i := int64(0); int64(g.Tip().Header.Height) < stakeEnabledHeight; i++ {
		outs := g.OldestCoinbaseOuts()
		ticketOuts := outs[1:]
		ticketsPurchased += len(ticketOuts)
		blockName := fmt.Sprintf("bse%d", i)
		g.NextBlock(blockName, nil, ticketOuts, replaceCoinbase)
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
	}
	g.AssertTipHeight(uint32(stakeEnabledHeight))

	// ---------------------------------------------------------------------
	// Generate enough blocks to reach the stake validation height while
	// continuing to purchase tickets using the coinbases matured above and
	// allowing the immature tickets to mature and thus become live.
	//
	//   ... -> bse# -> bsv0 -> bsv1 -> ... -> bsv#
	// ---------------------------------------------------------------------

	targetPoolSize := g.Params().TicketPoolSize * ticketsPerBlock
	for i := int64(0); int64(g.Tip().Header.Height) < stakeValidationHeight-1; i++ {
		// Only purchase tickets until the target ticket pool size is
		// reached.
		outs := g.OldestCoinbaseOuts()
		ticketOuts := outs[1:]
		if ticketsPurchased+len(ticketOuts) > int(targetPoolSize) {
			ticketsNeeded := int(targetPoolSize) - ticketsPurchased
			if ticketsNeeded > 0 {
				ticketOuts = ticketOuts[1 : ticketsNeeded+1]
			} else {
				ticketOuts = nil
			}
		}
		ticketsPurchased += len(ticketOuts)

		blockName := fmt.Sprintf("bsv%d", i)
		g.NextBlock(blockName, nil, ticketOuts, replaceCoinbase)
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
	}

	g.AssertTipHeight(uint32(stakeValidationHeight - 1))

	// ---------------------------------------------------------------------
	// Test adding a tspend on the first possible height despite not being
	// on a TVI.
	//
	//   ... -> bse# -> bsv0 -> bsv1 -> ... -> bsv#
	//                                      \-> boink0
	// ---------------------------------------------------------------------

	startTip := g.TipName()
	g.NextBlock("boink0", nil, nil, replaceCoinbase,
		func(b *wire.MsgBlock) {
			// Add TSpend
			b.AddSTransaction(tspend)
		})
	g.RejectTipBlock(ErrNotTVI)

	// ---------------------------------------------------------------------
	// Start TSpend 'yes' voting here.
	//
	//   ... -> bse# -> bsv0 -> bsv1 -> ... -> bsv# -> bsvv#
	//                                      \-> boink0
	// ---------------------------------------------------------------------

	// Full voting window -1 for block that contained no votes and another
	// -1 because the TSpend can only be mined on a TVI.
	numVotingBlocks := int64(tvi*mul - 2)

	g.SetTip(startTip)
	targetPoolSize = g.Params().TicketPoolSize * ticketsPerBlock
	voteCount := params.TicketsPerBlock
	for i := int64(0); int64(g.Tip().Header.Height) <
		stakeValidationHeight+numVotingBlocks; i++ {

		// Only purchase tickets until the target ticket pool size is
		// reached.
		outs := g.OldestCoinbaseOuts()
		ticketOuts := outs[1:]
		if ticketsPurchased+len(ticketOuts) > int(targetPoolSize) {
			ticketsNeeded := int(targetPoolSize) - ticketsPurchased
			if ticketsNeeded > 0 {
				ticketOuts = ticketOuts[1 : ticketsNeeded+1]
			} else {
				ticketOuts = nil
			}
		}
		ticketsPurchased += len(ticketOuts)

		blockName := fmt.Sprintf("bsvv%d", i)
		g.NextBlock(blockName, nil, ticketOuts, replaceCoinbase,
			addTSpendVotes(t, []*chainhash.Hash{&tspendHash},
				[]stake.TreasuryVoteT{stake.TreasuryVoteYes},
				voteCount, false))
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
	}
	g.AssertTipHeight(uint32(stakeValidationHeight + numVotingBlocks))

	// ---------------------------------------------------------------------
	// Mine TSpend on TVI.
	//
	//   ... -> bse# -> bsv0 -> bsv1 -> ... -> bsv# -> bsvv# ->
	//                                      \-> boink0       \-> boink1
	// ---------------------------------------------------------------------

	g.NextBlock("boink1", nil, nil,
		replaceCoinbase,
		func(b *wire.MsgBlock) {
			// Add TSpend
			b.AddSTransaction(tspend)
		})
	g.RejectTipBlock(ErrInvalidTVoteWindow)
}

func TestTreasuryInRegularTree(t *testing.T) {
	// Use a set of test chain parameters which allow for quicker vote
	// activation as compared to various existing network params.
	params := quickVoteActivationParams()

	// Clone the parameters so they can be mutated, find the correct
	// deployment for the treasury agenda, and, finally, ensure it is
	// always available to vote by removing the time constraints to prevent
	// test failures when the real expiration time passes.
	const tVoteID = chaincfg.VoteIDTreasury
	params = cloneParams(params)
	tVersion, deployment, err := findDeployment(params, tVoteID)
	if err != nil {
		t.Fatal(err)
	}
	removeDeploymentTimeConstraints(deployment)

	// Create a test harness initialized with the genesis block as the tip.
	g, teardownFunc := newChaingenHarness(t, params, "treasurytest")
	defer teardownFunc()

	// replaceTreasuryVersions is a munge function which modifies the provided
	// block by replacing the block, stake, and vote versions with the treasury
	// deployment version.
	replaceTreasuryVersions := func(b *wire.MsgBlock) {
		chaingen.ReplaceBlockVersion(int32(tVersion))(b)
		chaingen.ReplaceStakeVersion(tVersion)(b)
		chaingen.ReplaceVoteVersions(tVersion)(b)
	}

	// addTreasuryBaseRegular is a munge function which modifies the provided
	// block to add a treasurybase to the regular transaction tree.
	addTreasuryBaseRegular := func(b *wire.MsgBlock) {
		txCopy := b.STransactions[0].Copy()
		txCopy.TxOut[1].PkScript[len(txCopy.TxOut[1].PkScript)-1] ^= 0x55
		b.AddTransaction(txCopy)
	}

	// moveTAddRegular is a munge function which modifies the provided block by
	// moving a treasury add transaction from the stake transaction tree to the
	// regular transaction tree.
	moveTAddRegular := func(b *wire.MsgBlock) {
		// Move TAdd to regular tree
		tAddIdx := len(b.STransactions) - 1
		b.Transactions = append(b.Transactions, b.STransactions[tAddIdx])
		b.STransactions = b.STransactions[:tAddIdx]
	}

	// ---------------------------------------------------------------------
	// Generate and accept enough blocks with the appropriate vote bits set
	// to reach one block prior to the treasury agenda becoming active.
	// ---------------------------------------------------------------------

	g.AdvanceToStakeValidationHeight()
	g.AdvanceFromSVHToActiveAgendas(tVoteID)

	// Ensure treasury agenda is active.
	tipHash := &g.chain.BestSnapshot().Hash
	gotActive, err := g.chain.IsTreasuryAgendaActive(tipHash)
	if err != nil {
		t.Fatalf("IsTreasuryAgendaActive: %v", err)
	}
	if !gotActive {
		t.Fatalf("IsTreasuryAgendaActive: expected enabled treasury")
	}

	// ---------------------------------------------------------------------
	// Append a treasurybase to transactions.
	// ---------------------------------------------------------------------

	outs := g.OldestCoinbaseOuts()
	startTip := g.TipName()
	g.NextBlock("tb0", nil, outs[1:], replaceTreasuryVersions, replaceCoinbase,
		addTreasuryBaseRegular)
	g.RejectTipBlock(ErrMultipleCoinbases)

	// ---------------------------------------------------------------------
	// Append tadd to transactions
	// ---------------------------------------------------------------------

	g.SetTip(startTip)
	g.NextBlock("tadd0", nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase, createTAdd(outs[0], 15, params), moveTAddRegular)
	g.RejectTipBlock(ErrStakeTxInRegularTree)

	// ---------------------------------------------------------------------
	// Append TSpend to transactions.
	// ---------------------------------------------------------------------

	tspendAmount := uint64(devsub)
	tspendFee := uint64(0)
	tspend := g.CreateTreasuryTSpend(privKey, []chaingen.AddressAmountTuple{{
		Amount: dcrutil.Amount(tspendAmount - tspendFee),
	}}, dcrutil.Amount(tspendFee), 78) // Expiry check not hit.

	g.SetTip(startTip)
	g.NextBlock("tspend0", nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase, func(b *wire.MsgBlock) {
			b.AddTransaction(tspend)
		})
	g.RejectTipBlock(ErrStakeTxInRegularTree)
}

func TestTSpendVoteCountSynthetic(t *testing.T) {
	params := chaincfg.RegNetParams()
	tmh := params.TicketMaturity + 2 + 2 // Genesis + block 1 + 2 to reach tvi
	tvi := params.TreasuryVoteInterval
	mul := params.TreasuryVoteIntervalMultiplier
	tpb := params.TicketsPerBlock

	expiry := standalone.CalcTSpendExpiry(int64(tmh), tvi, mul)
	start, end, err := standalone.CalcTSpendWindow(expiry, tvi, mul)
	if err != nil {
		t.Fatal(err)
	}
	maxVotes := uint32(tpb) * (end - start)
	quorum := uint64(maxVotes) * params.TreasuryVoteQuorumMultiplier /
		params.TreasuryVoteQuorumDivisor
	requiredVotes := uint64(maxVotes) *
		params.TreasuryVoteRequiredMultiplier /
		params.TreasuryVoteRequiredDivisor

	// Create tspend.
	tspend := newFakeCreateTSpend(privKey, []dcrutil.Amount{100000000}, 1,
		expiry)
	tspendHash := tspend.TxHash()
	_, _, err = stake.CheckTSpend(tspend)
	if err != nil {
		t.Fatal(err)
	}

	// Create yes vote
	yesVote := newFakeCreateVoteTx([]treasuryVoteTuple{{
		tspendHash: tspendHash,
		vote:       0x01, // Yes
	}})
	_, err = stake.CheckSSGenVotes(yesVote, yesTreasury)
	if err != nil {
		t.Fatal(err)
	}

	// Create no vote
	noVote := newFakeCreateVoteTx([]treasuryVoteTuple{{
		tspendHash: tspendHash,
		vote:       0x02, // No
	}})
	_, err = stake.CheckSSGenVotes(noVote, yesTreasury)
	if err != nil {
		t.Fatal(err)
	}

	fakeTreasuryBase := &wire.MsgTx{}

	var ticketCount int // Overall ticket counter if needed in tests

	tests := []struct {
		name             string
		numNodes         int64
		set              func(*BlockChain, *blockNode)
		blockVersion     int32
		expectedYesVotes int
		expectedNoVotes  int
		failure          bool
	}{{
		name:             "All yes",
		numNodes:         int64(end),
		expectedYesVotes: int(tpb) * int(tvi*mul),
		expectedNoVotes:  0,
		failure:          false,
		set: func(bc *BlockChain, node *blockNode) {
			// Create block.
			bh := node.Header()
			mblk := wire.NewMsgBlock(&bh)

			// Append SSGen
			if node.height >= int64(start) &&
				node.height < int64(end) {
				mblk.STransactions = []*wire.MsgTx{
					fakeTreasuryBase,
					yesVote,
					yesVote,
					yesVote,
					yesVote,
					yesVote,
				}
			}

			// Insert block into the cache.
			bc.addRecentBlock(dcrutil.NewBlock(mblk))
		},
	}, {
		name:             "All no",
		numNodes:         int64(end),
		expectedYesVotes: 0,
		expectedNoVotes:  int(tpb) * int(tvi*mul),
		failure:          true,
		set: func(bc *BlockChain, node *blockNode) {
			// Create block.
			bh := node.Header()
			mblk := wire.NewMsgBlock(&bh)

			// Append SSGen
			if node.height >= int64(start) &&
				node.height < int64(end) {
				mblk.STransactions = []*wire.MsgTx{
					fakeTreasuryBase,
					noVote,
					noVote,
					noVote,
					noVote,
					noVote,
				}
			}

			// Insert block into the cache.
			bc.addRecentBlock(dcrutil.NewBlock(mblk))
		},
	}, {
		name:             "All abstain",
		numNodes:         int64(end),
		expectedYesVotes: 0,
		expectedNoVotes:  0,
		failure:          true,
		set: func(bc *BlockChain, node *blockNode) {
			// Create block.
			bh := node.Header()
			mblk := wire.NewMsgBlock(&bh)

			// Append SSGen
			if node.height >= int64(start) && node.height < int64(end) {
				mblk.STransactions = []*wire.MsgTx{
					fakeTreasuryBase,
				}
			}

			// Insert block into the cache.
			bc.addRecentBlock(dcrutil.NewBlock(mblk))
		},
	}, {
		name:             "Undervote one tvi",
		numNodes:         int64(end),
		expectedYesVotes: 0,
		expectedNoVotes:  0,
		failure:          true,
		set: func(bc *BlockChain, node *blockNode) {
			// Create block.
			bh := node.Header()
			mblk := wire.NewMsgBlock(&bh)

			// Append SSGen
			x := uint32(tvi) // subtract one tvi
			if node.height >= int64(start-x) &&
				node.height < int64(end-x) {
				mblk.STransactions = []*wire.MsgTx{
					fakeTreasuryBase,
				}
			}

			// Insert block into the cache.
			bc.addRecentBlock(dcrutil.NewBlock(mblk))
		},
	}, {
		name:             "Overvote",
		numNodes:         int64(end),
		expectedYesVotes: 0,
		expectedNoVotes:  0,
		failure:          true,
		set: func(bc *BlockChain, node *blockNode) {
			// Create block.
			bh := node.Header()
			mblk := wire.NewMsgBlock(&bh)

			// Append SSGen
			x := uint32(tvi) // add one tvi
			if node.height >= int64(start+x) {
				mblk.STransactions = []*wire.MsgTx{
					fakeTreasuryBase,
				}
			}

			// Insert block into the cache.
			bc.addRecentBlock(dcrutil.NewBlock(mblk))
		},
	}, {
		name:             "All yes quorum",
		numNodes:         int64(end),
		expectedYesVotes: int(quorum),
		expectedNoVotes:  0,
		failure:          false,
		set: func(bc *BlockChain, node *blockNode) {
			// Create block.
			bh := node.Header()
			mblk := wire.NewMsgBlock(&bh)

			// Append SSGen
			if node.height >= int64(start) &&
				node.height < int64(end) {
				mblk.STransactions = []*wire.MsgTx{
					fakeTreasuryBase,
				}

				for i := 0; i < int(tpb); i++ {
					if ticketCount >= int(quorum) {
						break
					}
					mblk.STransactions = append(mblk.STransactions,
						yesVote)
					ticketCount++
				}
			}

			// Insert block into the cache.
			bc.addRecentBlock(dcrutil.NewBlock(mblk))
		},
	}, {
		name:             "All yes quorum - 1",
		numNodes:         int64(end),
		expectedYesVotes: int(quorum - 1),
		expectedNoVotes:  0,
		failure:          true,
		set: func(bc *BlockChain, node *blockNode) {
			// Create block.
			bh := node.Header()
			mblk := wire.NewMsgBlock(&bh)

			// Append SSGen
			if node.height >= int64(start) &&
				node.height < int64(end) {
				mblk.STransactions = []*wire.MsgTx{
					fakeTreasuryBase,
				}

				for i := 0; i < int(tpb); i++ {
					if ticketCount >= int(quorum-1) {
						break
					}
					mblk.STransactions = append(mblk.STransactions,
						yesVote)
					ticketCount++
				}
			}

			// Insert block into the cache.
			bc.addRecentBlock(dcrutil.NewBlock(mblk))
		},
	}, {
		name:             "All yes quorum + 1",
		numNodes:         int64(end),
		expectedYesVotes: int(quorum + 1),
		expectedNoVotes:  0,
		failure:          false,
		set: func(bc *BlockChain, node *blockNode) {
			// Create block.
			bh := node.Header()
			mblk := wire.NewMsgBlock(&bh)

			// Append SSGen
			if node.height >= int64(start) &&
				node.height < int64(end) {
				mblk.STransactions = []*wire.MsgTx{
					fakeTreasuryBase,
				}

				for i := 0; i < int(tpb); i++ {
					if ticketCount >= int(quorum+1) {
						break
					}
					mblk.STransactions = append(mblk.STransactions,
						yesVote)
					ticketCount++
				}
			}

			// Insert block into the cache.
			bc.addRecentBlock(dcrutil.NewBlock(mblk))
		},
	}, {
		name:             "Exactly yes required",
		numNodes:         int64(end),
		expectedYesVotes: int(requiredVotes),
		expectedNoVotes:  int(maxVotes) - int(requiredVotes),
		failure:          false,
		set: func(bc *BlockChain, node *blockNode) {
			// Create block.
			bh := node.Header()
			mblk := wire.NewMsgBlock(&bh)

			// Append SSGen
			if node.height >= int64(start) &&
				node.height < int64(end) {
				mblk.STransactions = []*wire.MsgTx{
					fakeTreasuryBase,
				}

				for i := 0; i < int(tpb); i++ {
					if ticketCount >= int(requiredVotes) {
						mblk.STransactions = append(mblk.STransactions,
							noVote)
					} else {
						mblk.STransactions = append(mblk.STransactions,
							yesVote)
					}
					ticketCount++
				}
			}

			// Insert block into the cache.
			bc.addRecentBlock(dcrutil.NewBlock(mblk))
		},
	}, {
		name:             "Yes required - 1",
		numNodes:         int64(end),
		expectedYesVotes: int(requiredVotes - 1),
		expectedNoVotes:  int(maxVotes) - int(requiredVotes-1),
		failure:          true,
		set: func(bc *BlockChain, node *blockNode) {
			// Create block.
			bh := node.Header()
			mblk := wire.NewMsgBlock(&bh)

			// Append SSGen
			if node.height >= int64(start) &&
				node.height < int64(end) {
				mblk.STransactions = []*wire.MsgTx{
					fakeTreasuryBase,
				}

				for i := 0; i < int(tpb); i++ {
					if ticketCount < int(requiredVotes-1) {
						mblk.STransactions = append(mblk.STransactions,
							yesVote)
					} else {
						mblk.STransactions = append(mblk.STransactions,
							noVote)
					}
					ticketCount++
				}
			}

			// Insert block into the cache.
			bc.addRecentBlock(dcrutil.NewBlock(mblk))
		},
	}, {
		name:             "Yes required + 1",
		numNodes:         int64(end),
		expectedYesVotes: int(requiredVotes + 1),
		expectedNoVotes:  int(maxVotes) - int(requiredVotes+1),
		failure:          false,
		set: func(bc *BlockChain, node *blockNode) {
			// Create block.
			bh := node.Header()
			mblk := wire.NewMsgBlock(&bh)

			// Append SSGen
			if node.height >= int64(start) &&
				node.height < int64(end) {
				mblk.STransactions = []*wire.MsgTx{
					fakeTreasuryBase,
				}

				for i := 0; i < int(tpb); i++ {
					if ticketCount < int(requiredVotes+1) {
						mblk.STransactions = append(mblk.STransactions,
							yesVote)
					} else {
						mblk.STransactions = append(mblk.STransactions,
							noVote)
					}
					ticketCount++
				}
			}

			// Insert block into the cache.
			bc.addRecentBlock(dcrutil.NewBlock(mblk))
		},
	}, {
		name:             "Exactly yes required with abstain",
		numNodes:         int64(end),
		expectedYesVotes: int(requiredVotes),
		expectedNoVotes:  0,
		failure:          false,
		set: func(bc *BlockChain, node *blockNode) {
			// Create block.
			bh := node.Header()
			mblk := wire.NewMsgBlock(&bh)

			// Append SSGen
			if node.height >= int64(start) &&
				node.height < int64(end) {
				mblk.STransactions = []*wire.MsgTx{
					fakeTreasuryBase,
				}

				for i := 0; i < int(tpb); i++ {
					if ticketCount >= int(requiredVotes) {
						// Do nothing.
					} else {
						mblk.STransactions = append(mblk.STransactions,
							yesVote)
					}
					ticketCount++
				}
			}

			// Insert block into the cache.
			bc.addRecentBlock(dcrutil.NewBlock(mblk))
		},
	}}

	for _, test := range tests {
		// Create new BlockChain in order to blow away cache.  Also notice the
		// cache needs to be large enough to hold all of the blocks for these
		// tests without eviction.
		bc := newFakeChain(params)
		node := bc.bestChain.Tip()
		bc.recentBlocks = lru.NewKVCache(uint(test.numNodes))

		ticketCount = 0
		for i := int64(0); i < test.numNodes; i++ {
			// Version 9 is regnet decentralized treasury agenda.
			node = newFakeNode(node, test.blockVersion,
				9, 0, time.Now())

			// Override version.
			if test.set != nil {
				test.set(bc, node)
			}

			bc.index.AddNode(node)
			bc.bestChain.SetTip(node)
		}

		if !standalone.IsTreasuryVoteInterval(uint64(node.height), tvi) {
			t.Fatalf("Not a TVI: %v", node.height)
		}

		tv, err := bc.tSpendCountVotes(node.parent, dcrutil.NewTx(tspend))
		if err != nil {
			t.Fatal(err)
		}
		if tv.start != start {
			t.Fatalf("invalid start want %v got %v", start, start)
		}
		if tv.end != end {
			t.Fatalf("invalid end want %v got %v", end, end)
		}
		if tv.yes != test.expectedYesVotes {
			t.Fatalf("invalid yes want %v got %v",
				test.expectedYesVotes, tv.yes)
		}
		if tv.no != test.expectedNoVotes {
			t.Fatalf("invalid no want %v got %v",
				test.expectedNoVotes, tv.no)
		}

		// Check error
		err = bc.checkTSpendHasVotes(node.parent, dcrutil.NewTx(tspend))
		if test.failure {
			if err == nil {
				t.Fatalf("expected failure")
			}
		} else {
			if err != nil {
				t.Fatalf("%v: %v", test.name, err)
			}
		}
	}
}

// TestTSpendTooManyTAdds tests that a block that contains more TAdds than
// allowed by consensus rules is rejected while a block containing exactly the
// maximum amount is accepted.
func TestTSpendTooManyTAdds(t *testing.T) {
	// Use a set of test chain parameters which allow for quicker vote
	// activation as compared to various existing network params.
	params := quickVoteActivationParams()

	// Clone the parameters so they can be mutated, find the correct
	// deployment for the treasury agenda, and, finally, ensure it is
	// always available to vote by removing the time constraints to prevent
	// test failures when the real expiration time passes.
	const tVoteID = chaincfg.VoteIDTreasury
	params = cloneParams(params)
	tVersion, deployment, err := findDeployment(params, tVoteID)
	if err != nil {
		t.Fatal(err)
	}
	removeDeploymentTimeConstraints(deployment)

	// Create a test harness initialized with the genesis block as the tip.
	g, teardownFunc := newChaingenHarness(t, params, "treasurytest")
	defer teardownFunc()

	// replaceTreasuryVersions is a munge function which modifies the
	// provided block by replacing the block, stake, and vote versions with
	// the treasury deployment version.
	replaceTreasuryVersions := func(b *wire.MsgBlock) {
		chaingen.ReplaceBlockVersion(int32(tVersion))(b)
		chaingen.ReplaceStakeVersion(tVersion)(b)
		chaingen.ReplaceVoteVersions(tVersion)(b)
	}

	// addTAdds is a helper function that returns a munge function that
	// includes the specified tadds in the stake tree of a block.
	addTAdds := func(tadds []*wire.MsgTx) func(b *wire.MsgBlock) {
		return func(b *wire.MsgBlock) {
			for _, tx := range tadds {
				b.AddSTransaction(tx)
			}
		}
	}

	// ---------------------------------------------------------------------
	// Generate and accept enough blocks with the appropriate vote bits set
	// to reach one block prior to the treasury agenda becoming active.
	// ---------------------------------------------------------------------

	g.AdvanceToStakeValidationHeight()
	g.AdvanceFromSVHToActiveAgendas(tVoteID)

	// Ensure treasury agenda is active.
	tipHash := &g.chain.BestSnapshot().Hash
	gotActive, err := g.chain.IsTreasuryAgendaActive(tipHash)
	if err != nil {
		t.Fatalf("IsTreasuryAgendaActive: %v", err)
	}
	if !gotActive {
		t.Fatalf("IsTreasuryAgendaActive: expected enabled treasury")
	}

	// The maximum number of tadds is hardcoded here instead of using a
	// global const so that any code changes that unintentionally cause
	// this maximum to change in blockchain code are flagged by this test.
	maxNbTadds := 20

	// ---------------------------------------------------------------------
	// Generate enough blocks to have spendable outputs to create the
	// required number of tadds. Due to having lowered the coinbase
	// maturity, we'll need to manually generate and store these outputs
	// until we have enough.
	//
	//   ... -> bout0 -> .. boutn
	// ---------------------------------------------------------------------
	neededOuts := maxNbTadds + 1
	var oldOuts []chaingen.SpendableOut
	outs := g.OldestCoinbaseOuts()
	for i := uint32(0); i < uint32(neededOuts); i++ {
		name := fmt.Sprintf("bout%v", i)
		g.NextBlock(name, nil, outs[1:], replaceTreasuryVersions,
			replaceCoinbase)
		g.SaveTipCoinbaseOutsWithTreasury()
		g.AcceptTipBlock()
		outs = g.OldestCoinbaseOuts()
		oldOuts = append(oldOuts, outs[0])
	}

	// Create more than the maximum allowed number of TAdds.
	taddAmount := int64(1701)
	taddFee := dcrutil.Amount(0)
	tadds := make([]*wire.MsgTx, 0, maxNbTadds+1)
	for i := 0; i < maxNbTadds+1; i++ {
		tadd := g.CreateTreasuryTAdd(&oldOuts[i], dcrutil.Amount(taddAmount), taddFee)
		tadd.Version = wire.TxVersionTreasury
		tadds = append(tadds, tadd)
	}

	// ---------------------------------------------------------------------
	// Attempt to mine a block with an invalid number of tadds.
	//
	// ... -> boutn -> btoomanytadds
	// ---------------------------------------------------------------------
	tipName := g.TipName()
	g.NextBlock("btoomanytadds", nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase, addTAdds(tadds))
	g.SaveTipCoinbaseOutsWithTreasury()
	g.RejectTipBlock(ErrTooManyTAdds)

	// ---------------------------------------------------------------------
	// Mine a block with the maximum number of tadds.
	//
	// ... -> boutn -> btoomanytadds
	//             \-> bmaxtadds
	// ---------------------------------------------------------------------
	g.SetTip(tipName)
	g.NextBlock("bmaxtadds", nil, outs[1:], replaceTreasuryVersions,
		replaceCoinbase, addTAdds(tadds[1:]))
	g.SaveTipCoinbaseOutsWithTreasury()
	g.AcceptTipBlock()
}
