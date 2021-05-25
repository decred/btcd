// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2015-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	mrand "math/rand"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/decred/dcrd/blockchain/stake/v4"
	"github.com/decred/dcrd/blockchain/v4/chaingen"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/database/v2"
	_ "github.com/decred/dcrd/database/v2/ffldb"
	"github.com/decred/dcrd/dcrutil/v4"
	"github.com/decred/dcrd/lru"
	"github.com/decred/dcrd/txscript/v4"
	"github.com/decred/dcrd/txscript/v4/sign"
	"github.com/decred/dcrd/wire"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/filter"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

const (
	// testDbType is the database backend type to use for the tests.
	testDbType = "ffldb"

	// blockDataNet is the expected network in the test block data.
	blockDataNet = wire.MainNet
)

// isSupportedDbType returns whether or not the passed database type is
// currently supported.
func isSupportedDbType(dbType string) bool {
	supportedDrivers := database.SupportedDrivers()
	for _, driver := range supportedDrivers {
		if dbType == driver {
			return true
		}
	}

	return false
}

// createTestDatabase creates a test database with the provided database name
// and database type for the given network.
func createTestDatabase(dbName string, dbType string, net wire.CurrencyNet) (database.DB, func(), error) {
	// Handle memory database specially since it doesn't need the disk specific
	// handling.
	var db database.DB
	var teardown func()
	if dbType == "memdb" {
		ndb, err := database.Create(dbType)
		if err != nil {
			return nil, nil, fmt.Errorf("error creating db: %w", err)
		}
		db = ndb

		// Setup a teardown function for cleaning up.  This function is returned to
		// the caller to be invoked when it is done testing.
		teardown = func() {
			db.Close()
		}
	} else {
		// Create the directory for the test database.
		dbPath, err := ioutil.TempDir("", dbName)
		if err != nil {
			err := fmt.Errorf("unable to create test db path: %w",
				err)
			return nil, nil, err
		}

		// Create the test database.
		ndb, err := database.Create(dbType, dbPath, net)
		if err != nil {
			os.RemoveAll(dbPath)
			return nil, nil, fmt.Errorf("error creating db: %w", err)
		}
		db = ndb

		// Setup a teardown function for cleaning up.  This function is returned to
		// the caller to be invoked when it is done testing.
		teardown = func() {
			db.Close()
			os.RemoveAll(dbPath)
		}
	}

	return db, teardown, nil
}

// createTestUtxoDatabase creates a test UTXO database with the provided
// database name.
func createTestUtxoDatabase(dbName string) (*leveldb.DB, func(), error) {
	// Construct the database filepath and remove all from that path.
	dbPath := filepath.Join(os.TempDir(), dbName)
	_ = os.RemoveAll(dbPath)

	// Open the database (will create it if needed).
	opts := opt.Options{
		Strict:      opt.DefaultStrict,
		Compression: opt.NoCompression,
		Filter:      filter.NewBloomFilter(10),
	}
	db, err := leveldb.OpenFile(dbPath, &opts)
	if err != nil {
		return nil, nil, err
	}

	// Setup a teardown function for cleaning up.  This function is returned to
	// the caller to be invoked when it is done testing.
	teardown := func() {
		_ = db.Close()
		_ = os.RemoveAll(dbPath)
	}

	return db, teardown, nil
}

// chainSetup is used to create a new db and chain instance with the genesis
// block already inserted.  In addition to the new chain instance, it returns
// a teardown function the caller should invoke when done testing to clean up.
func chainSetup(dbName string, params *chaincfg.Params) (*BlockChain, func(), error) {
	if !isSupportedDbType(testDbType) {
		return nil, nil, fmt.Errorf("unsupported db type %v", testDbType)
	}

	// Create a test block database.
	db, teardownDb, err := createTestDatabase(dbName, testDbType, blockDataNet)
	if err != nil {
		return nil, nil, err
	}

	// Create a test UTXO database.
	utxoDb, teardownUtxoDb, err := createTestUtxoDatabase(dbName + "_utxo")
	if err != nil {
		teardownDb()
		return nil, nil, err
	}
	teardown := func() {
		teardownUtxoDb()
		teardownDb()
	}

	// Copy the chain params to ensure any modifications the tests do to
	// the chain parameters do not affect the global instance.
	paramsCopy := *params

	// Create a SigCache instance.
	sigCache, err := txscript.NewSigCache(1000)
	if err != nil {
		return nil, nil, err
	}

	// Create the main chain instance.
	utxoBackend := NewLevelDbUtxoBackend(utxoDb)
	chain, err := New(context.Background(),
		&Config{
			DB:          db,
			UtxoBackend: utxoBackend,
			ChainParams: &paramsCopy,
			TimeSource:  NewMedianTime(),
			SigCache:    sigCache,
			UtxoCache: NewUtxoCache(&UtxoCacheConfig{
				Backend: utxoBackend,
				FlushBlockDB: func() error {
					// Don't flush to disk since it is slow and this is used in a lot of
					// tests.
					return nil
				},
				MaxSize: 100 * 1024 * 1024, // 100 MiB
			}),
		})

	if err != nil {
		teardown()
		err := fmt.Errorf("failed to create chain instance: %w", err)
		return nil, nil, err
	}

	return chain, teardown, nil
}

// newFakeChain returns a chain that is usable for synthetic tests.  It is
// important to note that this chain has no database associated with it, so
// it is not usable with all functions and the tests must take care when making
// use of it.
func newFakeChain(params *chaincfg.Params) *BlockChain {
	// Create a genesis block node and block index populated with it for use
	// when creating the fake chain below.
	node := newBlockNode(&params.GenesisBlock.Header, nil)
	node.status = statusDataStored | statusValidated
	node.isFullyLinked = true
	index := newBlockIndex(nil)
	index.bestHeader = node
	index.AddNode(node)

	// Generate a deployment ID to version map from the provided params.
	deploymentVers, err := extractDeploymentIDVersions(params)
	if err != nil {
		panic(err)
	}

	return &BlockChain{
		deploymentVers:                deploymentVers,
		chainParams:                   params,
		deploymentCaches:              newThresholdCaches(params),
		index:                         index,
		bestChain:                     newChainView(node),
		recentBlocks:                  lru.NewKVCache(recentBlockCacheSize),
		isVoterMajorityVersionCache:   make(map[[stakeMajorityCacheKeySize]byte]bool),
		isStakeMajorityVersionCache:   make(map[[stakeMajorityCacheKeySize]byte]bool),
		calcPriorStakeVersionCache:    make(map[[chainhash.HashSize]byte]uint32),
		calcVoterVersionIntervalCache: make(map[[chainhash.HashSize]byte]uint32),
		calcStakeVersionCache:         make(map[[chainhash.HashSize]byte]uint32),
	}
}

// testNoncePrng provides a deterministic prng for the nonce in generated fake
// nodes.  The ensures that the nodes have unique hashes.
var testNoncePrng = mrand.New(mrand.NewSource(0))

// newFakeNode creates a block node connected to the passed parent with the
// provided fields populated and fake values for the other fields.
func newFakeNode(parent *blockNode, blockVersion int32, stakeVersion uint32, bits uint32, timestamp time.Time) *blockNode {
	// Make up a header and create a block node from it.
	var prevHash chainhash.Hash
	var height uint32
	if parent != nil {
		prevHash = parent.hash
		height = uint32(parent.height + 1)
	}
	header := &wire.BlockHeader{
		Version:      blockVersion,
		PrevBlock:    prevHash,
		VoteBits:     0x01,
		Bits:         bits,
		Height:       height,
		Timestamp:    timestamp,
		Nonce:        testNoncePrng.Uint32(),
		StakeVersion: stakeVersion,
	}
	node := newBlockNode(header, parent)
	node.status = statusDataStored | statusValidated
	node.isFullyLinked = parent == nil || parent.isFullyLinked
	return node
}

type treasuryVoteTuple struct {
	tspendHash chainhash.Hash
	vote       byte
}

// newFakeCreateVoteTx creates a fake vote transaction and appends treasury
// votes if provided.
func newFakeCreateVoteTx(tspendVotes []treasuryVoteTuple) *wire.MsgTx {
	var (
		voteSubsidy        = 5000000000
		ticketPrice        = 100000000
		opTrueRedeemScript = []byte{txscript.OP_DATA_1, txscript.OP_TRUE}
		stakeGenScript     = [26]byte{txscript.OP_SSGEN}
		blockScript        = [38]byte{txscript.OP_RETURN, txscript.OP_DATA_36}
		voteScript         = [4]byte{txscript.OP_RETURN, txscript.OP_DATA_2}
	)
	// Fake out stakeGenScript.
	tagOffset := 1 // Prefixed with OP_SSGEN
	stakeGenScript[tagOffset+0] = txscript.OP_DUP
	stakeGenScript[tagOffset+1] = txscript.OP_HASH160
	stakeGenScript[tagOffset+2] = txscript.OP_DATA_20
	stakeGenScript[tagOffset+23] = txscript.OP_EQUALVERIFY
	stakeGenScript[tagOffset+24] = txscript.OP_CHECKSIG

	// Generate and return the transaction with the proof-of-stake subsidy
	// coinbase and spending from the provided ticket along with the
	// previously described outputs.
	ticketHash := &chainhash.Hash{}
	tx := wire.NewMsgTx()
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: *wire.NewOutPoint(&chainhash.Hash{},
			wire.MaxPrevOutIndex, wire.TxTreeRegular),
		Sequence:    wire.MaxTxInSequenceNum,
		ValueIn:     int64(voteSubsidy),
		BlockHeight: wire.NullBlockHeight,
		BlockIndex:  wire.NullBlockIndex,
	})
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: *wire.NewOutPoint(ticketHash, 0,
			wire.TxTreeStake),
		Sequence:        wire.MaxTxInSequenceNum,
		ValueIn:         int64(ticketPrice),
		SignatureScript: opTrueRedeemScript,
	})
	tx.AddTxOut(wire.NewTxOut(0, blockScript[:]))
	tx.AddTxOut(wire.NewTxOut(0, voteScript[:]))
	tx.AddTxOut(wire.NewTxOut(int64(voteSubsidy+ticketPrice),
		stakeGenScript[:]))

	// Append tspend votes if set.
	if tspendVotes != nil {
		tx.Version = wire.TxVersionTreasury
		tspendScript := make([]byte, 0, 256)
		tspendScript = append(tspendScript, txscript.OP_RETURN,
			byte(len(tspendVotes)*33+2), 'T', 'V')
		for _, v := range tspendVotes {
			tspendScript = append(tspendScript, v.tspendHash[:]...)
			tspendScript = append(tspendScript, v.vote)
		}
		tx.AddTxOut(wire.NewTxOut(0, tspendScript))
	}
	return tx
}

// newFakeCreateTSpend creates a fake tspend transaction.
func newFakeCreateTSpend(privKey []byte, payouts []dcrutil.Amount, fee dcrutil.Amount, expiry uint32) *wire.MsgTx {
	// Calculate total payout.
	totalPayout := int64(0)
	for _, amount := range payouts {
		totalPayout += int64(amount)
	}
	valueIn := int64(fee) + totalPayout

	// OP_RETURN <8 byte LE ValueIn><24 byte random>
	// The TSpend TxIn ValueIn is encoded in the first 8 bytes to ensure
	// that it becomes signed. This is consensus enforced.
	var payload [32]byte
	binary.LittleEndian.PutUint64(payload[0:8], uint64(valueIn))
	_, err := mrand.Read(payload[8:])
	if err != nil {
		panic(err)
	}
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_RETURN)
	builder.AddData(payload[:])
	opretScript, err := builder.Script()
	if err != nil {
		panic(err)
	}
	msgTx := wire.NewMsgTx()
	msgTx.Version = wire.TxVersionTreasury
	msgTx.Expiry = expiry
	msgTx.AddTxOut(wire.NewTxOut(0, opretScript))

	// OP_TGEN
	for _, amount := range payouts {
		// Generate valid script. This is a hex encdoded blob from
		// generator.go.
		p2shOpTrueScript, err := hex.DecodeString("a914f5a8302ee8695bf836258b8f2b57b38a0be14e4787")
		if err != nil {
			panic(err)
		}
		script := make([]byte, len(p2shOpTrueScript)+1)
		script[0] = txscript.OP_TGEN
		copy(script[1:], p2shOpTrueScript[:])
		msgTx.AddTxOut(wire.NewTxOut(int64(amount), script))
	}

	// Treasury spend transactions have no inputs since the funds are
	// sourced from a special account, so previous outpoint is zero hash
	// and max index.
	msgTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: *wire.NewOutPoint(&chainhash.Hash{},
			wire.MaxPrevOutIndex, wire.TxTreeRegular),
		Sequence:        wire.MaxTxInSequenceNum,
		ValueIn:         valueIn,
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

// chainedFakeNodes returns the specified number of nodes constructed such that
// each subsequent node points to the previous one to create a chain.  The first
// node will point to the passed parent which can be nil if desired.
func chainedFakeNodes(parent *blockNode, numNodes int) []*blockNode {
	nodes := make([]*blockNode, numNodes)
	tip := parent
	blockTime := time.Now()
	if tip != nil {
		blockTime = time.Unix(tip.timestamp, 0)
	}
	for i := 0; i < numNodes; i++ {
		blockTime = blockTime.Add(time.Second)
		node := newFakeNode(tip, 1, 1, 0, blockTime)
		tip = node

		nodes[i] = node
	}
	return nodes
}

// chainedFakeSkipListNodes returns the specified number of nodes populated with
// only the fields specifically needed to test the skip list functionality and
// constructed such that each subsequent node points to the previous one to
// create a chain.  The first node will point to the passed parent which can be
// nil if desired.
//
// This is used over the chainedFakeNodes function for skip list testing because
// the skip list tests involve large numbers of nodes which take much longer to
// create with all of the other fields populated by said function.
func chainedFakeSkipListNodes(parent *blockNode, numNodes int) []*blockNode {
	nodes := make([]*blockNode, numNodes)
	for i := 0; i < numNodes; i++ {
		node := &blockNode{parent: parent, height: int64(i)}
		if parent != nil {
			node.skipToAncestor = nodes[calcSkipListHeight(int64(i))]
		}
		parent = node

		nodes[i] = node
	}
	return nodes
}

// branchTip is a convenience function to grab the tip of a chain of block nodes
// created via chainedFakeNodes.
func branchTip(nodes []*blockNode) *blockNode {
	return nodes[len(nodes)-1]
}

// appendFakeVotes appends the passed number of votes to the node with the
// provided version and vote bits.
func appendFakeVotes(node *blockNode, numVotes uint16, voteVersion uint32, voteBits uint16) {
	for i := uint16(0); i < numVotes; i++ {
		node.votes = append(node.votes, stake.VoteVersionTuple{
			Version: voteVersion,
			Bits:    voteBits,
		})
	}
}

// findDeployment finds the provided vote ID within the deployments of the
// provided parameters and either returns the deployment version it was found in
// along with a pointer to the deployment or an error when not found.
func findDeployment(params *chaincfg.Params, voteID string) (uint32, *chaincfg.ConsensusDeployment, error) {
	// Find the correct deployment for the passed vote ID.
	for version, deployments := range params.Deployments {
		for i, deployment := range deployments {
			if deployment.Vote.Id == voteID {
				return version, &deployments[i], nil
			}
		}
	}

	return 0, nil, fmt.Errorf("unable to find deployment for id %q", voteID)
}

// findDeploymentChoice finds the provided choice ID within the given
// deployment params and either returns a pointer to the found choice or an
// error when not found.
func findDeploymentChoice(deployment *chaincfg.ConsensusDeployment, choiceID string) (*chaincfg.Choice, error) {
	// Find the correct choice for the passed choice ID.
	for i, choice := range deployment.Vote.Choices {
		if choice.Id == choiceID {
			return &deployment.Vote.Choices[i], nil
		}
	}

	return nil, fmt.Errorf("unable to find vote choice for id %q", choiceID)
}

// removeDeployment modifies the passed parameters to remove all deployments for
// the provided vote ID.  An error is returned when not found.
func removeDeployment(params *chaincfg.Params, voteID string) error {
	// Remove the deployment(s) for the passed vote ID.
	var found bool
	for version, deployments := range params.Deployments {
		for i, deployment := range deployments {
			if deployment.Vote.Id == voteID {
				copy(deployments[i:], deployments[i+1:])
				deployments[len(deployments)-1] = chaincfg.ConsensusDeployment{}
				deployments = deployments[:len(deployments)-1]
				params.Deployments[version] = deployments
				found = true
			}
		}
	}
	if found {
		return nil
	}

	return fmt.Errorf("unable to find deployment for id %q", voteID)
}

// removeDeploymentTimeConstraints modifies the passed deployment to remove the
// voting time constraints by making it always available to vote and to never
// expire.
//
// NOTE: This will mutate the passed deployment, so ensure this function is
// only called with parameters that are not globally available.
func removeDeploymentTimeConstraints(deployment *chaincfg.ConsensusDeployment) {
	deployment.StartTime = 0               // Always available for vote.
	deployment.ExpireTime = math.MaxUint64 // Never expires.
}

// chaingenHarness provides a test harness which encapsulates a test instance, a
// chaingen generator instance, and a block chain instance to provide all of the
// functionality of the aforementioned types as well as several convenience
// functions such as block acceptance and rejection, expected tip checking, and
// threshold state checking.
//
// The chaingen generator is embedded in the struct so callers can directly
// access its method the same as if they were directly working with the
// underlying generator.
//
// Since chaingen involves creating fully valid and solved blocks, which is
// relatively expensive, only tests which actually require that functionality
// should make use of this harness.  In many cases, a much faster synthetic
// chain instance created by newFakeChain will suffice.
type chaingenHarness struct {
	*chaingen.Generator

	t                  *testing.T
	chain              *BlockChain
	deploymentVersions map[string]uint32
}

// newChaingenHarnessWithGen creates and returns a new instance of a chaingen
// harness that encapsulates the provided test instance and existing chaingen
// generator along with a teardown function the caller should invoke when done
// testing to clean up.
//
// This differs from newChaingenHarness in that it allows the caller to provide
// a chaingen generator to use instead of creating a new one.
//
// See the documentation for the chaingenHarness type for more details.
func newChaingenHarnessWithGen(t *testing.T, dbName string, g *chaingen.Generator) (*chaingenHarness, func()) {
	t.Helper()

	// Create a new database and chain instance to run tests against.
	chain, teardownFunc, err := chainSetup(dbName, g.Params())
	if err != nil {
		t.Fatalf("Failed to setup chain instance: %v", err)
	}

	harness := chaingenHarness{
		Generator:          g,
		t:                  t,
		chain:              chain,
		deploymentVersions: make(map[string]uint32),
	}
	return &harness, teardownFunc
}

// newChaingenHarness creates and returns a new instance of a chaingen harness
// that encapsulates the provided test instance along with a teardown function
// the caller should invoke when done testing to clean up.
//
// This differs from newChaingenHarnessWithGen in that it creates a new chaingen
// generator to use instead of allowing the caller to provide one.
//
// See the documentation for the chaingenHarness type for more details.
func newChaingenHarness(t *testing.T, params *chaincfg.Params, dbName string) (*chaingenHarness, func()) {
	t.Helper()

	// Create a test generator instance initialized with the genesis block as
	// the tip.
	g, err := chaingen.MakeGenerator(params)
	if err != nil {
		t.Fatalf("Failed to create generator: %v", err)
	}

	return newChaingenHarnessWithGen(t, dbName, &g)
}

// AcceptHeader processes the block header associated with the given name in the
// harness generator and expects it to be accepted, but not necessarily to the
// main chain.  It also ensures the underlying block index is consistent with
// the result.
func (g *chaingenHarness) AcceptHeader(blockName string) {
	g.t.Helper()

	header := &g.BlockByName(blockName).Header
	blockHash := header.BlockHash()
	blockHeight := header.Height
	g.t.Logf("Testing accept block header %q (hash %s, height %d)", blockName,
		blockHash, blockHeight)

	// Determine if the header is already known before attempting to process it.
	alreadyHaveHeader := g.chain.index.LookupNode(&blockHash) != nil

	err := g.chain.ProcessBlockHeader(header, BFNone)
	if err != nil {
		g.t.Fatalf("block header %q (hash %s, height %d) should have been "+
			"accepted: %v", blockName, blockHash, blockHeight, err)
	}

	// Ensure the accepted header now exists in the block index.
	node := g.chain.index.LookupNode(&blockHash)
	if node == nil {
		g.t.Fatalf("accepted block header %q (hash %s, height %d) should have "+
			"been added to the block index", blockName, blockHash, blockHeight)
	}

	// Ensure the accepted header is not marked as known valid when it was not
	// previously known since that implies the block data is not yet available
	// and therefore it can't possibly be known to be valid.
	//
	// Also, ensure the accepted header is not marked as known invalid, as
	// having known invalid ancestors, or as known to have failed validation.
	status := g.chain.index.NodeStatus(node)
	if !alreadyHaveHeader && status.HasValidated() {
		g.t.Fatalf("accepted block header %q (hash %s, height %d) was not "+
			"already known, but is marked as known valid", blockName, blockHash,
			blockHeight)
	}
	if status.KnownInvalid() {
		g.t.Fatalf("accepted block header %q (hash %s, height %d) is marked "+
			"as known invalid", blockName, blockHash, blockHeight)
	}
	if status.KnownInvalidAncestor() {
		g.t.Fatalf("accepted block header %q (hash %s, height %d) is marked "+
			"as having a known invalid ancestor", blockName, blockHash,
			blockHeight)
	}
	if status.KnownValidateFailed() {
		g.t.Fatalf("accepted block header %q (hash %s, height %d) is marked "+
			"as having known to fail validation", blockName, blockHash,
			blockHeight)
	}
}

// AcceptBlockData processes the block associated with the given name in the
// harness generator and expects it to be accepted, but not necessarily to the
// main chain.
func (g *chaingenHarness) AcceptBlockData(blockName string) {
	g.t.Helper()

	msgBlock := g.BlockByName(blockName)
	blockHeight := msgBlock.Header.Height
	block := dcrutil.NewBlock(msgBlock)
	blockHash := block.Hash()
	g.t.Logf("Testing block %q (hash %s, height %d)", blockName, blockHash,
		blockHeight)

	_, err := g.chain.ProcessBlock(block, BFNone)
	if err != nil {
		g.t.Fatalf("block %q (hash %s, height %d) should have been accepted: %v",
			blockName, blockHash, blockHeight, err)
	}
}

// AcceptBlockDataWithExpectedTip processes the block associated with the given
// name in the harness generator and expects it to be accepted, but not
// necessarily to the main chain and for the current best chain tip to be the
// provided value.
func (g *chaingenHarness) AcceptBlockDataWithExpectedTip(blockName, tipName string) {
	g.t.Helper()

	g.AcceptBlockData(blockName)
	g.ExpectTip(tipName)
}

// AcceptBlock processes the block associated with the given name in the
// harness generator and expects it to be accepted to the main chain.
func (g *chaingenHarness) AcceptBlock(blockName string) {
	g.t.Helper()

	msgBlock := g.BlockByName(blockName)
	blockHeight := msgBlock.Header.Height
	block := dcrutil.NewBlock(msgBlock)
	g.t.Logf("Testing block %q (hash %s, height %d)", blockName, block.Hash(),
		blockHeight)

	forkLen, err := g.chain.ProcessBlock(block, BFNone)
	if err != nil {
		g.t.Fatalf("block %q (hash %s, height %d) should have been accepted: %v",
			blockName, block.Hash(), blockHeight, err)
	}

	// Ensure the block was accepted to the main chain as indicated by a fork
	// length of zero.
	isMainChain := forkLen == 0
	if !isMainChain {
		g.t.Fatalf("block %q (hash %s, height %d) unexpected main chain flag "+
			"-- got %v, want true", blockName, block.Hash(), blockHeight,
			isMainChain)
	}
}

// AcceptTipBlock processes the current tip block associated with the harness
// generator and expects it to be accepted to the main chain.
func (g *chaingenHarness) AcceptTipBlock() {
	g.t.Helper()

	g.AcceptBlock(g.TipName())
}

// RejectHeader expects the block header associated with the given name in the
// harness generator to be rejected with the provided error kind and also
// ensures the underlying block index is consistent with the result.
func (g *chaingenHarness) RejectHeader(blockName string, kind ErrorKind) {
	g.t.Helper()

	header := &g.BlockByName(blockName).Header
	blockHash := header.BlockHash()
	blockHeight := header.Height
	g.t.Logf("Testing reject block header %q (hash %s, height %d, reason %v)",
		blockName, blockHash, blockHeight, kind)

	// Determine if the header is already known before attempting to process it.
	alreadyHaveHeader := g.chain.index.LookupNode(&blockHash) != nil

	err := g.chain.ProcessBlockHeader(header, BFNone)
	if err == nil {
		g.t.Fatalf("block header %q (hash %s, height %d) should not have been "+
			"accepted", blockName, blockHash, blockHeight)
	}

	// Ensure the error matches the value specified in the test instance.
	if !errors.Is(err, kind) {
		g.t.Fatalf("block header %q (hash %s, height %d) does not have "+
			"expected reject code -- got %v, want %v", blockName, blockHash,
			blockHeight, err, kind)
	}

	// Ensure the rejected header was not added to the block index when it was
	// not already previously successfully added and that it was not removed if
	// it was already previously added.
	node := g.chain.index.LookupNode(&blockHash)
	switch {
	case !alreadyHaveHeader && node == nil:
		// Header was not added as expected.
		return

	case !alreadyHaveHeader && node != nil:
		g.t.Fatalf("rejected block header %q (hash %s, height %d) was added "+
			"to the block index", blockName, blockHash, blockHeight)

	case alreadyHaveHeader && node == nil:
		g.t.Fatalf("rejected block header %q (hash %s, height %d) was removed "+
			"from the block index", blockName, blockHash, blockHeight)
	}

	// The header was previously added, so ensure it is not reported as having
	// been validated and that it is now known invalid.
	status := g.chain.index.NodeStatus(node)
	if status.HasValidated() {
		g.t.Fatalf("rejected block header %q (hash %s, height %d) is marked "+
			"as known valid", blockName, blockHash, blockHeight)
	}
	if !status.KnownInvalid() {
		g.t.Fatalf("rejected block header %q (hash %s, height %d) is NOT "+
			"marked as known invalid", blockName, blockHash, blockHeight)
	}
}

// RejectBlock expects the block associated with the given name in the harness
// generator to be rejected with the provided error kind.
func (g *chaingenHarness) RejectBlock(blockName string, kind ErrorKind) {
	g.t.Helper()

	msgBlock := g.BlockByName(blockName)
	blockHeight := msgBlock.Header.Height
	block := dcrutil.NewBlock(msgBlock)
	g.t.Logf("Testing reject block %q (hash %s, height %d, reason %v)",
		blockName, block.Hash(), blockHeight, kind)

	_, err := g.chain.ProcessBlock(block, BFNone)
	if err == nil {
		g.t.Fatalf("block %q (hash %s, height %d) should not have been accepted",
			blockName, block.Hash(), blockHeight)
	}

	// Ensure the error matches the value specified in the test instance.
	if !errors.Is(err, kind) {
		g.t.Fatalf("block %q (hash %s, height %d) does not have expected reject "+
			"code -- got %v, want %v", blockName, block.Hash(), blockHeight,
			err, kind)
	}
}

// RejectTipBlock expects the current tip block associated with the harness
// generator to be rejected with the provided error kind.
func (g *chaingenHarness) RejectTipBlock(kind ErrorKind) {
	g.t.Helper()

	g.RejectBlock(g.TipName(), kind)
}

// ExpectTip expects the provided block to be the current tip of the main chain
// associated with the harness generator.
func (g *chaingenHarness) ExpectTip(tipName string) {
	g.t.Helper()

	// Ensure hash and height match.
	wantTip := g.BlockByName(tipName)
	best := g.chain.BestSnapshot()
	if best.Hash != wantTip.BlockHash() ||
		best.Height != int64(wantTip.Header.Height) {
		g.t.Fatalf("block %q (hash %s, height %d) should be the current tip "+
			"-- got %q (hash %s, height %d)", tipName, wantTip.BlockHash(),
			wantTip.Header.Height, g.BlockName(&best.Hash), best.Hash,
			best.Height)
	}
}

// ExpectUtxoSetState expects the provided block to be the last flushed block in
// the utxo set state in the utxo backend.
func (g *chaingenHarness) ExpectUtxoSetState(blockName string) {
	g.t.Helper()

	// Fetch the utxo set state from the utxo backend.
	gotState, err := g.chain.utxoCache.FetchBackendState()
	if err != nil {
		g.t.Fatalf("unexpected error fetching utxo set state: %v", err)
	}

	// Validate that the state matches the expected state.
	block := g.BlockByName(blockName)
	wantState := &UtxoSetState{
		lastFlushHeight: block.Header.Height,
		lastFlushHash:   block.BlockHash(),
	}
	if !reflect.DeepEqual(gotState, wantState) {
		g.t.Fatalf("mismatched utxo set state:\nwant: %+v\n got: %+v\n", wantState,
			gotState)
	}
}

// AcceptedToSideChainWithExpectedTip expects the tip block associated with the
// generator to be accepted to a side chain, but the current best chain tip to
// be the provided value.
func (g *chaingenHarness) AcceptedToSideChainWithExpectedTip(tipName string) {
	g.t.Helper()

	msgBlock := g.Tip()
	blockHeight := msgBlock.Header.Height
	block := dcrutil.NewBlock(msgBlock)
	g.t.Logf("Testing block %q (hash %s, height %d)", g.TipName(), block.Hash(),
		blockHeight)

	forkLen, err := g.chain.ProcessBlock(block, BFNone)
	if err != nil {
		g.t.Fatalf("block %q (hash %s, height %d) should have been accepted: %v",
			g.TipName(), block.Hash(), blockHeight, err)
	}

	// Ensure the block was accepted to a side chain as indicated by a non-zero
	// fork length.
	isMainChain := forkLen == 0
	if isMainChain {
		g.t.Fatalf("block %q (hash %s, height %d) unexpected main chain flag "+
			"-- got %v, want false", g.TipName(), block.Hash(), blockHeight,
			isMainChain)
	}

	g.ExpectTip(tipName)
}

// ExpectBestHeader expects the provided block header associated with the given
// name to be the one identified as the header of the chain associated with the
// harness generator with the most cumulative work that is NOT known to be
// invalid.
func (g *chaingenHarness) ExpectBestHeader(blockName string) {
	g.t.Helper()

	// Ensure hash and height match.
	want := g.BlockByName(blockName).Header
	bestHash, bestHeight := g.chain.BestHeader()
	if bestHash != want.BlockHash() || bestHeight != int64(want.Height) {
		g.t.Fatalf("block header %q (hash %s, height %d) should be the best "+
			"known header -- got %q (hash %s, height %d)", blockName,
			want.BlockHash(), want.Height, g.BlockName(&bestHash),
			bestHash, bestHeight)
	}
}

// ExpectBestInvalidHeader expects the provided block header associated with the
// given name to be the one identified as the header of the chain associated
// with the harness generator with the most cumulative work that is known to be
// invalid.  Note that the provided block name can be an empty string to
// indicate no such header should exist.
func (g *chaingenHarness) ExpectBestInvalidHeader(blockName string) {
	g.t.Helper()

	bestHash := g.chain.BestInvalidHeader()
	switch {
	case blockName != "" && bestHash != *zeroHash:
		want := g.BlockByName(blockName).Header
		bestHeader := g.BlockByHash(&bestHash).Header
		if bestHash != want.BlockHash() || bestHeader.Height != want.Height {
			g.t.Fatalf("block header %q (hash %s, height %d) should be the "+
				"best known invalid header -- got %q (hash %s, height %d)",
				blockName, want.BlockHash(), want.Height, g.BlockName(&bestHash),
				bestHash, bestHeader.Height)
		}

	case blockName != "" && bestHash == *zeroHash:
		want := g.BlockByName(blockName).Header
		g.t.Fatalf("block header %q (hash %s, height %d) should be the best "+
			"known invalid header -- got none", blockName, want.BlockHash(),
			want.Height)

	case blockName == "" && bestHash != *zeroHash:
		bestHeight := g.BlockByHash(&bestHash).Header.Height
		g.t.Fatalf("there should not be a best known invalid header -- got %q "+
			"(hash %s, height %d)", g.BlockName(&bestHash), bestHash,
			bestHeight)
	}
}

// ExpectIsCurrent expects the chain associated with the harness generator to
// report the given is current status.
func (g *chaingenHarness) ExpectIsCurrent(expected bool) {
	g.t.Helper()

	best := g.chain.BestSnapshot()
	isCurrent := g.chain.IsCurrent()
	if isCurrent != expected {
		g.t.Fatalf("mismatched is current status for block %q (hash %s, "+
			"height %d) -- got %v, want %v", g.BlockName(&best.Hash), best.Hash,
			best.Height, isCurrent, expected)
	}
}

// lookupDeploymentVersion returns the version of the deployment with the
// provided ID and caches the result for future invocations.  An error is
// returned if the ID is not found.
func (g *chaingenHarness) lookupDeploymentVersion(voteID string) (uint32, error) {
	if version, ok := g.deploymentVersions[voteID]; ok {
		return version, nil
	}

	version, _, err := findDeployment(g.Params(), voteID)
	if err != nil {
		return 0, err
	}

	g.deploymentVersions[voteID] = version
	return version, nil
}

// TestThresholdState queries the threshold state from the current tip block
// associated with the harness generator and expects the returned state to match
// the provided value.
func (g *chaingenHarness) TestThresholdState(id string, state ThresholdState) {
	g.t.Helper()

	tipHash := g.Tip().BlockHash()
	tipHeight := g.Tip().Header.Height
	deploymentVer, err := g.lookupDeploymentVersion(id)
	if err != nil {
		g.t.Fatalf("block %q (hash %s, height %d) unexpected error when "+
			"retrieving threshold state: %v", g.TipName(), tipHash, tipHeight,
			err)
	}

	s, err := g.chain.NextThresholdState(&tipHash, deploymentVer, id)
	if err != nil {
		g.t.Fatalf("block %q (hash %s, height %d) unexpected error when "+
			"retrieving threshold state: %v", g.TipName(), tipHash, tipHeight,
			err)
	}

	if s.State != state {
		g.t.Fatalf("block %q (hash %s, height %d) unexpected threshold "+
			"state for %s -- got %v, want %v", g.TipName(), tipHash, tipHeight,
			id, s.State, state)
	}
}

// TestThresholdStateChoice queries the threshold state from the current tip
// block associated with the harness generator and expects the returned state
// and choice to match the provided value.
func (g *chaingenHarness) TestThresholdStateChoice(id string, state ThresholdState, choice uint32) {
	g.t.Helper()

	tipHash := g.Tip().BlockHash()
	tipHeight := g.Tip().Header.Height
	deploymentVer, err := g.lookupDeploymentVersion(id)
	if err != nil {
		g.t.Fatalf("block %q (hash %s, height %d) unexpected error when "+
			"retrieving threshold state: %v", g.TipName(), tipHash, tipHeight,
			err)
	}

	s, err := g.chain.NextThresholdState(&tipHash, deploymentVer, id)
	if err != nil {
		g.t.Fatalf("block %q (hash %s, height %d) unexpected error when "+
			"retrieving threshold state: %v", g.TipName(), tipHash, tipHeight,
			err)
	}

	if s.State != state {
		g.t.Fatalf("block %q (hash %s, height %d) unexpected threshold "+
			"state for %s -- got %v, want %v", g.TipName(), tipHash, tipHeight,
			id, s.State, state)
	}
	if s.Choice != choice {
		g.t.Fatalf("block %q (hash %s, height %d) unexpected choice for %s -- "+
			"got %v, want %v", g.TipName(), tipHash, tipHeight, id, s.Choice,
			choice)
	}
}

// ForceTipReorg forces the chain instance associated with the generator to
// reorganize the current tip of the main chain from the given block to the
// given block.  An error will result if the provided from block is not actually
// the current tip.
func (g *chaingenHarness) ForceTipReorg(fromTipName, toTipName string) {
	g.t.Helper()

	from := g.BlockByName(fromTipName)
	to := g.BlockByName(toTipName)
	g.t.Logf("Testing forced reorg from %q (hash %s, height %d) to %q (hash "+
		"%s, height %d)", fromTipName, from.BlockHash(), from.Header.Height,
		toTipName, to.BlockHash(), to.Header.Height)

	err := g.chain.ForceHeadReorganization(from.BlockHash(), to.BlockHash())
	if err != nil {
		g.t.Fatalf("failed to force header reorg from block %q (hash %s, "+
			"height %d) to block %q (hash %s, height %d): %v", fromTipName,
			from.BlockHash(), from.Header.Height, toTipName, to.BlockHash(),
			to.Header.Height, err)
	}
}

// InvalidateBlockAndExpectTip marks the block associated with the given name in
// the harness generator as invalid and expects the provided error along with
// the resulting current best chain tip to be the block associated with the
// given tip name.
func (g *chaingenHarness) InvalidateBlockAndExpectTip(blockName string, wantErr error, tipName string) {
	g.t.Helper()

	msgBlock := g.BlockByName(blockName)
	blockHeight := msgBlock.Header.Height
	block := dcrutil.NewBlock(msgBlock)
	g.t.Logf("Testing invalidate block %q (hash %s, height %d) with expected "+
		"error %v", blockName, block.Hash(), blockHeight, wantErr)

	err := g.chain.InvalidateBlock(block.Hash())
	if !errors.Is(err, wantErr) {
		g.t.Fatalf("invalidate block %q (hash %s, height %d) does not have "+
			"expected error -- got %q, want %v", blockName, block.Hash(),
			blockHeight, err, wantErr)
	}

	g.ExpectTip(tipName)
}

// ReconsiderBlockAndExpectTip reconsiders the block associated with the given
// name in the harness generator and expects the provided error along with the
// resulting current best chain tip to be the block associated with the given
// tip name.
func (g *chaingenHarness) ReconsiderBlockAndExpectTip(blockName string, wantErr error, tipName string) {
	g.t.Helper()

	msgBlock := g.BlockByName(blockName)
	blockHeight := msgBlock.Header.Height
	block := dcrutil.NewBlock(msgBlock)

	g.t.Logf("Testing reconsider block %q (hash %s, height %d) with expected "+
		"error %v", blockName, block.Hash(), blockHeight, wantErr)

	err := g.chain.ReconsiderBlock((block.Hash()))
	if !errors.Is(err, wantErr) {
		g.t.Fatalf("reconsider block %q (hash %s, height %d) does not have "+
			"expected error -- got %q, want %v", blockName, block.Hash(),
			blockHeight, err, wantErr)
	}

	g.ExpectTip(tipName)
}

// minUint32 is a helper function to return the minimum of two uint32s.
// This avoids a math import and the need to cast to floats.
func minUint32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

// generateToHeight generates enough blocks in the generator associated with the
// harness to reach the provided height assuming the blocks up to and including
// the provided from height have already been generated.  It also purchases the
// provided number of tickets per block after coinbase maturity.
//
// The accept flag specifies whether or not to accept the blocks to the chain
// instance associated with the harness as well.
//
// The function will fail with a fatal test error if it is called with a from
// height that is greater than or equal to the to height or a number of tickets
// that exceeds the max allowed for a block.
func (g *chaingenHarness) generateToHeight(fromHeight, toHeight uint32, buyTicketsPerBlock uint32, accept bool) {
	g.t.Helper()

	// Only allow this to be called with sane heights.
	tipHeight := fromHeight
	if toHeight <= tipHeight {
		g.t.Fatalf("not possible to generate to height %d when the current "+
			"height is already %d", toHeight, tipHeight)
	}

	// Only allow this to be called with a sane number of tickets to buy per
	// block.
	params := g.Params()
	maxOutsForTickets := uint32(params.TicketsPerBlock)
	if buyTicketsPerBlock > maxOutsForTickets {
		g.t.Fatalf("a max of %v outputs are available for ticket purchases "+
			"per block", maxOutsForTickets)
	}

	// Shorter versions of useful params for convenience.
	coinbaseMaturity := uint32(params.CoinbaseMaturity)
	stakeEnabledHeight := uint32(params.StakeEnabledHeight)

	// Add the required first block as needed.
	//
	//   genesis -> bfb
	if tipHeight == 0 {
		g.CreateBlockOne("bfb", 0)
		g.AssertTipHeight(1)
		if accept {
			g.AcceptTipBlock()
		}
		tipHeight++
	}
	intermediateHeight := uint32(1)

	// Generate enough blocks to have mature coinbase outputs to work with as
	// needed.
	//
	//   genesis -> bfb -> bm2 -> bm3 -> ... -> bm#
	alreadyAsserted := tipHeight >= coinbaseMaturity+1
	targetHeight := minUint32(coinbaseMaturity+1, toHeight)
	for ; tipHeight < targetHeight; tipHeight++ {
		blockName := fmt.Sprintf("bm%d", tipHeight-intermediateHeight)
		g.NextBlock(blockName, nil, nil)
		g.SaveTipCoinbaseOuts()
		if accept {
			g.AcceptTipBlock()
		}
	}
	intermediateHeight = targetHeight
	if !alreadyAsserted {
		g.AssertTipHeight(intermediateHeight)
	}

	// Generate enough blocks to reach the stake enabled height while creating
	// ticket purchases that spend from the coinbases matured above as needed.
	// This will also populate the pool of immature tickets.
	//
	//   ... -> bm# ... -> bse18 -> bse19 -> ... -> bse#
	var ticketsPurchased uint32
	alreadyAsserted = tipHeight >= stakeEnabledHeight
	targetHeight = minUint32(stakeEnabledHeight, toHeight)
	for ; tipHeight < targetHeight; tipHeight++ {
		var ticketOuts []chaingen.SpendableOut
		if buyTicketsPerBlock > 0 {
			// Purchase the specified number of tickets per block.
			outs := g.OldestCoinbaseOuts()
			ticketOuts = outs[1 : buyTicketsPerBlock+1]
			ticketsPurchased += buyTicketsPerBlock
		}

		blockName := fmt.Sprintf("bse%d", tipHeight-intermediateHeight)
		g.NextBlock(blockName, nil, ticketOuts)
		g.SaveTipCoinbaseOuts()
		if accept {
			g.AcceptTipBlock()
		}
	}
	intermediateHeight = targetHeight
	if !alreadyAsserted {
		g.AssertTipHeight(intermediateHeight)
	}

	targetPoolSize := uint32(g.Params().TicketPoolSize) * buyTicketsPerBlock
	for ; tipHeight < toHeight; tipHeight++ {
		var ticketOuts []chaingen.SpendableOut
		// Only purchase tickets until the target ticket pool size is reached.
		ticketsNeeded := targetPoolSize - ticketsPurchased
		ticketsNeeded = minUint32(ticketsNeeded, buyTicketsPerBlock)
		if ticketsNeeded > 0 {
			outs := g.OldestCoinbaseOuts()
			ticketOuts = outs[1 : ticketsNeeded+1]
			ticketsPurchased += ticketsNeeded
		}

		blockName := fmt.Sprintf("bsv%d", tipHeight-intermediateHeight)
		g.NextBlock(blockName, nil, ticketOuts)
		g.SaveTipCoinbaseOuts()
		if accept {
			g.AcceptTipBlock()
		}
	}
	g.AssertTipHeight(toHeight)
}

// AdvanceToHeight generates and accepts enough blocks to the chain instance
// associated with the harness to reach the provided height while purchasing the
// provided tickets per block after coinbase maturity.
func (g *chaingenHarness) AdvanceToHeight(height uint32, buyTicketsPerBlock uint32) {
	g.t.Helper()

	// Only allow this to be called with a sane height.
	tipHeight := g.Tip().Header.Height
	if height <= tipHeight {
		g.t.Fatalf("not possible to advance to height %d when the current "+
			"height is already %d", height, tipHeight)
	}

	const accept = true
	g.generateToHeight(tipHeight, height, buyTicketsPerBlock, accept)
}

// generateToStakeValidationHeight generates enough blocks in the generator
// associated with the harness to reach stake validation height.
//
// The accept flag specifies whether or not to accept the blocks to the chain
// instance associated with the harness as well.
//
// The function will fail with a fatal test error if it is not called with the
// harness at the genesis block which is the case when it is first created.
func (g *chaingenHarness) generateToStakeValidationHeight(accept bool) {
	g.t.Helper()

	// Only allow this to be called on a newly created harness.
	if g.Tip().Header.Height != 0 {
		g.t.Fatalf("chaingen harness instance must be at the genesis block " +
			"to generate to stake validation height")
	}

	// Shorter versions of useful params for convenience.
	params := g.Params()
	ticketsPerBlock := uint32(params.TicketsPerBlock)
	stakeValidationHeight := uint32(params.StakeValidationHeight)

	// Generate enough blocks in the associated harness generator to reach stake
	// validation height.
	g.generateToHeight(0, stakeValidationHeight, ticketsPerBlock, accept)
}

// GenerateToStakeValidationHeight generates enough blocks in the generator
// associated with the harness to reach stake validation height without
// accepting them to the chain instance associated with the harness.
//
// The function will fail with a fatal test error if it is not called with the
// harness at the genesis block which is the case when it is first created.
func (g *chaingenHarness) GenerateToStakeValidationHeight() {
	g.t.Helper()

	const accept = false
	g.generateToStakeValidationHeight(accept)
}

// AdvanceToStakeValidationHeight generates and accepts enough blocks to the
// chain instance associated with the harness to reach stake validation height.
//
// The function will fail with a fatal test error if it is not called with the
// harness at the genesis block which is the case when it is first created.
func (g *chaingenHarness) AdvanceToStakeValidationHeight() {
	g.t.Helper()

	const accept = true
	g.generateToStakeValidationHeight(accept)
}

// AdvanceFromSVHToActiveAgenda generates and accepts enough blocks with the
// appropriate vote bits set to reach one block prior to the specified agenda
// becoming active.
//
// The function will fail with a fatal test error if it is called when the
// harness is not at stake validation height.
//
// WARNING: This function currently assumes the chain parameters were created
// via the quickVoteActivationParams.  It should be updated in the future to
// work with arbitrary params.
func (g *chaingenHarness) AdvanceFromSVHToActiveAgenda(voteID string) {
	g.t.Helper()

	// Find the correct deployment for the provided ID along with the yes
	// vote choice within it.
	params := g.Params()
	deploymentVer, deployment, err := findDeployment(params, voteID)
	if err != nil {
		g.t.Fatal(err)
	}
	yesChoice, err := findDeploymentChoice(deployment, "yes")
	if err != nil {
		g.t.Fatal(err)
	}

	// Shorter versions of useful params for convenience.
	stakeValidationHeight := params.StakeValidationHeight
	stakeVerInterval := params.StakeVersionInterval
	ruleChangeInterval := int64(params.RuleChangeActivationInterval)

	// Only allow this to be called on a harness at SVH.
	if g.Tip().Header.Height != uint32(stakeValidationHeight) {
		g.t.Fatalf("chaingen harness instance must be at the genesis block " +
			"to advance to stake validation height")
	}

	// ---------------------------------------------------------------------
	// Generate enough blocks to reach one block before the next two stake
	// version intervals with block and vote versions for the agenda and
	// stake version 0.
	//
	// This will result in triggering enforcement of the stake version and
	// that the stake version is the deployment version.  The threshold
	// state for deployment will move to started since the next block also
	// coincides with the start of a new rule change activation interval for
	// the chosen parameters.
	//
	//   ... -> bsv# -> bvu0 -> bvu1 -> ... -> bvu#
	// ---------------------------------------------------------------------

	blocksNeeded := stakeValidationHeight + stakeVerInterval*2 - 1 -
		int64(g.Tip().Header.Height)
	for i := int64(0); i < blocksNeeded; i++ {
		outs := g.OldestCoinbaseOuts()
		blockName := fmt.Sprintf("bvu%d", i)
		g.NextBlock(blockName, nil, outs[1:],
			chaingen.ReplaceBlockVersion(int32(deploymentVer)),
			chaingen.ReplaceVoteVersions(deploymentVer))
		g.SaveTipCoinbaseOuts()
		g.AcceptTipBlock()
	}
	g.TestThresholdState(voteID, ThresholdStarted)

	// ---------------------------------------------------------------------
	// Generate enough blocks to reach the next rule change interval with
	// block, stake, and vote versions for the agenda.  Also, set the vote
	// bits to include yes votes for the agenda.
	//
	// This will result in moving the threshold state for the agenda to
	// locked in.
	//
	//   ... -> bvu# -> bvli0 -> bvli1 -> ... -> bvli#
	// ---------------------------------------------------------------------

	blocksNeeded = stakeValidationHeight + ruleChangeInterval*2 - 1 -
		int64(g.Tip().Header.Height)
	for i := int64(0); i < blocksNeeded; i++ {
		outs := g.OldestCoinbaseOuts()
		blockName := fmt.Sprintf("bvli%d", i)
		g.NextBlock(blockName, nil, outs[1:],
			chaingen.ReplaceBlockVersion(int32(deploymentVer)),
			chaingen.ReplaceStakeVersion(deploymentVer),
			chaingen.ReplaceVotes(vbPrevBlockValid|yesChoice.Bits, deploymentVer))
		g.SaveTipCoinbaseOuts()
		g.AcceptTipBlock()
	}
	g.AssertTipHeight(uint32(stakeValidationHeight + ruleChangeInterval*2 - 1))
	g.AssertBlockVersion(int32(deploymentVer))
	g.AssertStakeVersion(deploymentVer)
	g.TestThresholdState(voteID, ThresholdLockedIn)

	// ---------------------------------------------------------------------
	// Generate enough blocks to reach the next rule change interval with
	// block, stake, and vote versions for the agenda.
	//
	// This will result in moving the threshold state for the agenda to
	// active thereby activating it.
	//
	//   ... -> bvli# -> bva0 -> bva1 -> ... -> bva#
	// ---------------------------------------------------------------------

	blocksNeeded = stakeValidationHeight + ruleChangeInterval*3 - 1 -
		int64(g.Tip().Header.Height)
	for i := int64(0); i < blocksNeeded; i++ {
		outs := g.OldestCoinbaseOuts()
		blockName := fmt.Sprintf("bva%d", i)
		g.NextBlock(blockName, nil, outs[1:],
			chaingen.ReplaceBlockVersion(int32(deploymentVer)),
			chaingen.ReplaceStakeVersion(deploymentVer),
			chaingen.ReplaceVoteVersions(deploymentVer),
		)
		g.SaveTipCoinbaseOuts()
		g.AcceptTipBlock()
	}
	g.AssertTipHeight(uint32(stakeValidationHeight + ruleChangeInterval*3 - 1))
	g.AssertBlockVersion(int32(deploymentVer))
	g.AssertStakeVersion(deploymentVer)
	g.TestThresholdState(voteID, ThresholdActive)
}
