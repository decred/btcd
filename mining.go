// Copyright (c) 2014 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"container/heap"
	"container/list"
	"encoding/binary"
	"fmt"
	"math"
	"time"

	"github.com/decred/dcrd/blockchain"
	"github.com/decred/dcrd/blockchain/stake"
	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/database"
	"github.com/decred/dcrd/txscript"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrutil"
)

const (
	// minHighPriority is the minimum priority value that allows a
	// transaction to be considered high priority.
	minHighPriority = dcrutil.AtomsPerCoin * 144.0 / 250

	// blockHeaderOverhead is the max number of bytes it takes to serialize
	// a block header and max possible transaction count.
	blockHeaderOverhead = wire.MaxBlockHeaderPayload + wire.MaxVarIntPayload

	// coinbaseFlags is some extra data appended to the coinbase script
	// sig.
	coinbaseFlags = "/dcrd/"

	// kilobyte is the size of a kilobyte.
	kilobyte = 1000
)

// txPrioItem houses a transaction along with extra information that allows the
// transaction to be prioritized and track dependencies on other transactions
// which have not been mined into a block yet.
type txPrioItem struct {
	tx       *dcrutil.Tx
	txType   stake.TxType
	fee      int64
	priority float64
	feePerKB float64

	// dependsOn holds a map of transaction hashes which this one depends
	// on.  It will only be set when the transaction references other
	// transactions in the memory pool and hence must come after them in
	// a block.
	dependsOn map[chainhash.Hash]struct{}
}

// txPriorityQueueLessFunc describes a function that can be used as a compare
// function for a transation priority queue (txPriorityQueue).
type txPriorityQueueLessFunc func(*txPriorityQueue, int, int) bool

// txPriorityQueue implements a priority queue of txPrioItem elements that
// supports an arbitrary compare function as defined by txPriorityQueueLessFunc.
type txPriorityQueue struct {
	lessFunc txPriorityQueueLessFunc
	items    []*txPrioItem
}

// Len returns the number of items in the priority queue.  It is part of the
// heap.Interface implementation.
func (pq *txPriorityQueue) Len() int {
	return len(pq.items)
}

// Less returns whether the item in the priority queue with index i should sort
// before the item with index j by deferring to the assigned less function.  It
// is part of the heap.Interface implementation.
func (pq *txPriorityQueue) Less(i, j int) bool {
	return pq.lessFunc(pq, i, j)
}

// Swap swaps the items at the passed indices in the priority queue.  It is
// part of the heap.Interface implementation.
func (pq *txPriorityQueue) Swap(i, j int) {
	pq.items[i], pq.items[j] = pq.items[j], pq.items[i]
}

// Push pushes the passed item onto the priority queue.  It is part of the
// heap.Interface implementation.
func (pq *txPriorityQueue) Push(x interface{}) {
	pq.items = append(pq.items, x.(*txPrioItem))
}

// Pop removes the highest priority item (according to Less) from the priority
// queue and returns it.  It is part of the heap.Interface implementation.
func (pq *txPriorityQueue) Pop() interface{} {
	n := len(pq.items)
	item := pq.items[n-1]
	pq.items[n-1] = nil
	pq.items = pq.items[0 : n-1]
	return item
}

// SetLessFunc sets the compare function for the priority queue to the provided
// function.  It also invokes heap.Init on the priority queue using the new
// function so it can immediately be used with heap.Push/Pop.
func (pq *txPriorityQueue) SetLessFunc(lessFunc txPriorityQueueLessFunc) {
	pq.lessFunc = lessFunc
	heap.Init(pq)
}

// stakePriority is an integer that is used to sort stake transactions
// by importance when they enter the min heap for block construction.
// 2 is for votes (highest), followed by 1 for tickets (2nd highest),
// followed by 0 for regular transactions and revocations (lowest).
type stakePriority int

const (
	regOrRevocPriority stakePriority = iota
	ticketPriority
	votePriority
)

// stakePriority assigns a stake priority based on a transaction type.
func txStakePriority(txType stake.TxType) stakePriority {
	prio := regOrRevocPriority
	switch txType {
	case stake.TxTypeSSGen:
		prio = votePriority
	case stake.TxTypeSStx:
		prio = ticketPriority
	}

	return prio
}

// compareStakePriority compares the stake priority of two transactions.
// It uses votes > tickets > regular transactions or revocations. It
// returns 1 if i > j, 0 if i == j, and -1 if i < j in terms of stake
// priority.
func compareStakePriority(i, j *txPrioItem) int {
	iStakePriority := txStakePriority(i.txType)
	jStakePriority := txStakePriority(j.txType)

	if iStakePriority > jStakePriority {
		return 1
	}
	if iStakePriority < jStakePriority {
		return -1
	}
	return 0
}

// txPQByPriority sorts a txPriorityQueue by transaction priority and then fees
// per kilobyte.
func txPQByPriority(pq *txPriorityQueue, i, j int) bool {
	// Using > here so that pop gives the highest priority item as opposed
	// to the lowest.  Sort by priority first, then fee.
	if pq.items[i].priority == pq.items[j].priority {
		return pq.items[i].feePerKB > pq.items[j].feePerKB
	}
	return pq.items[i].priority > pq.items[j].priority
}

// txPQByStakeAndPriority sorts a txPriorityQueue by stake priority then
// transaction priority, and then fees per kilobyte.
func txPQByStakeAndPriority(pq *txPriorityQueue, i, j int) bool {
	// Sort by stake priority, continue if they're the same stake priority.
	cmp := compareStakePriority(pq.items[i], pq.items[j])
	if cmp == 1 {
		return true
	}
	if cmp == -1 {
		return false
	}

	// Using > here so that pop gives the highest priority item as opposed
	// to the lowest.  Sort by priority first, then fee.
	if pq.items[i].priority == pq.items[j].priority {
		return pq.items[i].feePerKB > pq.items[j].feePerKB
	}

	return pq.items[i].priority > pq.items[j].priority
}

// txPQByFee sorts a txPriorityQueue by fees per kilobyte and then transaction
// priority.
func txPQByFee(pq *txPriorityQueue, i, j int) bool {
	// Using > here so that pop gives the highest fee item as opposed
	// to the lowest.  Sort by fee first, then priority.
	if pq.items[i].feePerKB == pq.items[j].feePerKB {
		return pq.items[i].priority > pq.items[j].priority
	}
	return pq.items[i].feePerKB > pq.items[j].feePerKB
}

// txPQByStakeAndFee sorts a txPriorityQueue by stake priority, followed by
// fees per kilobyte, and then transaction priority.
func txPQByStakeAndFee(pq *txPriorityQueue, i, j int) bool {
	// Sort by stake priority, continue if they're the same stake priority.
	cmp := compareStakePriority(pq.items[i], pq.items[j])
	if cmp == 1 {
		return true
	}
	if cmp == -1 {
		return false
	}

	// Using > here so that pop gives the highest fee item as opposed
	// to the lowest.  Sort by fee first, then priority.
	if pq.items[i].feePerKB == pq.items[j].feePerKB {
		return pq.items[i].priority > pq.items[j].priority
	}

	// The stake priorities are equal, so return based on fees
	// per KB.
	return pq.items[i].feePerKB > pq.items[j].feePerKB
}

// txPQByStakeAndFeeAndThenPriority sorts a txPriorityQueue by stake priority,
// followed by fees per kilobyte, and then if the transaction type is regular
// or a revocation it sorts it by priority.
func txPQByStakeAndFeeAndThenPriority(pq *txPriorityQueue, i, j int) bool {
	// Sort by stake priority, continue if they're the same stake priority.
	cmp := compareStakePriority(pq.items[i], pq.items[j])
	if cmp == 1 {
		return true
	}
	if cmp == -1 {
		return false
	}

	bothAreLowStakePriority :=
		txStakePriority(pq.items[i].txType) == regOrRevocPriority &&
			txStakePriority(pq.items[j].txType) == regOrRevocPriority

	// Use fees per KB on high stake priority transactions.
	if !bothAreLowStakePriority {
		return pq.items[i].feePerKB > pq.items[j].feePerKB
	}

	// Both transactions are of low stake importance. Use > here so that
	// pop gives the highest priority item as opposed to the lowest.
	// Sort by priority first, then fee.
	if pq.items[i].priority == pq.items[j].priority {
		return pq.items[i].feePerKB > pq.items[j].feePerKB
	}

	return pq.items[i].priority > pq.items[j].priority
}

// newTxPriorityQueue returns a new transaction priority queue that reserves the
// passed amount of space for the elements.  The new priority queue uses the
// less than function lessFunc to sort the items in the min heap. The priority
// queue can grow larger than the reserved space, but extra copies of the
// underlying array can be avoided by reserving a sane value.
func newTxPriorityQueue(reserve int, lessFunc func(*txPriorityQueue, int,
	int) bool) *txPriorityQueue {
	pq := &txPriorityQueue{
		items: make([]*txPrioItem, 0, reserve),
	}
	pq.SetLessFunc(lessFunc)
	return pq
}

// containsTx is a helper function that checks to see if a list of transactions
// contains any of the TxIns of some transaction.
func containsTxIns(txs []*dcrutil.Tx, tx *dcrutil.Tx) bool {
	for _, txToCheck := range txs {
		for _, txIn := range tx.MsgTx().TxIn {
			if txIn.PreviousOutPoint.Hash.IsEqual(txToCheck.Sha()) {
				return true
			}
		}
	}

	return false
}

// BlockTemplate houses a block that has yet to be solved along with additional
// details about the fees and the number of signature operations for each
// transaction in the block.
type BlockTemplate struct {
	block           *wire.MsgBlock
	fees            []int64
	sigOpCounts     []int64
	height          int64
	validPayAddress bool
}

// hashExistsInList checks if a hash exists in a list of hashes.
func hashExistsInList(hash *chainhash.Hash, list []chainhash.Hash) bool {
	for _, h := range list {
		if hash.IsEqual(&h) {
			return true
		}
	}

	return false
}

// txIndexFromTxList returns a transaction's index in a list, or -1 if it
// can not be found.
func txIndexFromTxList(hash chainhash.Hash, list []*dcrutil.Tx) int {
	for i, tx := range list {
		h := tx.Sha()
		if hash == *h {
			return i
		}
	}

	return -1
}

// mergeTxStore adds all of the transactions in txStoreB to txStoreA.  The
// result is that txStoreA will contain all of its original transactions plus
// all of the transactions in txStoreB.
func mergeTxStore(txStoreA blockchain.TxStore, txStoreB blockchain.TxStore) {
	for hash, txDataB := range txStoreB {
		if txDataA, exists := txStoreA[hash]; !exists ||
			(txDataA.Err == database.ErrTxShaMissing && txDataB.Err !=
				database.ErrTxShaMissing) {

			txStoreA[hash] = txDataB
		}
	}
}

// standardCoinbaseOpReturn creates a standard OP_RETURN output to insert into
// coinbase to use as extranonces. The OP_RETURN pushes 32 bytes.
func standardCoinbaseOpReturn(height uint32, extraNonces []uint64) ([]byte,
	error) {
	if len(extraNonces) != 4 {
		return nil, fmt.Errorf("extranonces has wrong num uint64s")
	}

	enData := make([]byte, 36, 36)
	binary.LittleEndian.PutUint32(enData[0:4], height)
	binary.LittleEndian.PutUint64(enData[4:12], extraNonces[0])
	binary.LittleEndian.PutUint64(enData[12:20], extraNonces[1])
	binary.LittleEndian.PutUint64(enData[20:28], extraNonces[2])
	binary.LittleEndian.PutUint64(enData[28:36], extraNonces[3])
	extraNonceScript, err := txscript.GenerateProvablyPruneableOut(enData)
	if err != nil {
		return nil, err
	}

	return extraNonceScript, nil
}

// getCoinbaseExtranonce extracts the extranonce from a block template's
// coinbase transaction.
func (bt *BlockTemplate) getCoinbaseExtranonces() []uint64 {
	if len(bt.block.Transactions[0].TxOut) < 2 {
		return []uint64{0, 0, 0, 0}
	}

	if len(bt.block.Transactions[0].TxOut[1].PkScript) < 38 {
		return []uint64{0, 0, 0, 0}
	}

	ens := make([]uint64, 4, 4) // 32-bytes
	ens[0] = binary.LittleEndian.Uint64(
		bt.block.Transactions[0].TxOut[1].PkScript[6:14])
	ens[1] = binary.LittleEndian.Uint64(
		bt.block.Transactions[0].TxOut[1].PkScript[14:22])
	ens[2] = binary.LittleEndian.Uint64(
		bt.block.Transactions[0].TxOut[1].PkScript[22:30])
	ens[3] = binary.LittleEndian.Uint64(
		bt.block.Transactions[0].TxOut[1].PkScript[30:38])

	return ens
}

// getCoinbaseExtranonce extracts the extranonce from a block template's
// coinbase transaction.
func getCoinbaseExtranonces(msgBlock *wire.MsgBlock) []uint64 {
	if len(msgBlock.Transactions[0].TxOut) < 2 {
		return []uint64{0, 0, 0, 0}
	}

	if len(msgBlock.Transactions[0].TxOut[1].PkScript) < 38 {
		return []uint64{0, 0, 0, 0}
	}

	ens := make([]uint64, 4, 4) // 32-bytes
	ens[0] = binary.LittleEndian.Uint64(
		msgBlock.Transactions[0].TxOut[1].PkScript[6:14])
	ens[1] = binary.LittleEndian.Uint64(
		msgBlock.Transactions[0].TxOut[1].PkScript[14:22])
	ens[2] = binary.LittleEndian.Uint64(
		msgBlock.Transactions[0].TxOut[1].PkScript[22:30])
	ens[3] = binary.LittleEndian.Uint64(
		msgBlock.Transactions[0].TxOut[1].PkScript[30:38])

	return ens
}

// UpdateExtraNonce updates the extra nonce in the coinbase script of the passed
// block by regenerating the coinbase script with the passed value and block
// height.  It also recalculates and updates the new merkle root that results
// from changing the coinbase script.
func UpdateExtraNonce(msgBlock *wire.MsgBlock, blockHeight int64,
	extraNonces []uint64) error {
	// First block has no extranonce.
	if blockHeight == 1 {
		return nil
	}
	if len(extraNonces) != 4 {
		return fmt.Errorf("not enough nonce information passed")
	}

	coinbaseOpReturn, err := standardCoinbaseOpReturn(uint32(blockHeight),
		extraNonces)
	if err != nil {
		return err
	}
	msgBlock.Transactions[0].TxOut[1].PkScript = coinbaseOpReturn

	// TODO(davec): A dcrutil.Block should use saved in the state to avoid
	// recalculating all of the other transaction hashes.
	// block.Transactions[0].InvalidateCache()

	// Recalculate the merkle root with the updated extra nonce.
	block := dcrutil.NewBlockDeepCopyCoinbase(msgBlock)
	merkles := blockchain.BuildMerkleTreeStore(block.Transactions())
	msgBlock.Header.MerkleRoot = *merkles[len(merkles)-1]
	return nil
}

// createCoinbaseTx returns a coinbase transaction paying an appropriate subsidy
// based on the passed block height to the provided address.  When the address
// is nil, the coinbase transaction will instead be redeemable by anyone.
//
// See the comment for NewBlockTemplate for more information about why the nil
// address handling is useful.
func createCoinbaseTx(coinbaseScript []byte,
	opReturnPkScript []byte,
	nextBlockHeight int64,
	addr dcrutil.Address,
	voters uint16,
	params *chaincfg.Params) (*dcrutil.Tx, error) {

	tx := wire.NewMsgTx()
	tx.AddTxIn(&wire.TxIn{
		// Coinbase transactions have no inputs, so previous outpoint is
		// zero hash and max index.
		PreviousOutPoint: *wire.NewOutPoint(&chainhash.Hash{},
			wire.MaxPrevOutIndex, dcrutil.TxTreeRegular),
		Sequence:        wire.MaxTxInSequenceNum,
		BlockHeight:     wire.NullBlockHeight,
		BlockIndex:      wire.NullBlockIndex,
		SignatureScript: coinbaseScript,
	})

	// Block one is a special block that might pay out tokens to a ledger.
	if nextBlockHeight == 1 && len(params.BlockOneLedger) != 0 {
		// Convert the addresses in the ledger into useable format.
		addrs := make([]dcrutil.Address,
			len(params.BlockOneLedger),
			len(params.BlockOneLedger))
		for i, payout := range params.BlockOneLedger {
			addr, err := dcrutil.DecodeAddress(payout.Address, params)
			if err != nil {
				return nil, err
			}
			addrs[i] = addr
		}

		for i, payout := range params.BlockOneLedger {
			// Make payout to this address.
			pks, err := txscript.PayToAddrScript(addrs[i])
			if err != nil {
				return nil, err
			}
			tx.AddTxOut(&wire.TxOut{
				Value:    payout.Amount,
				PkScript: pks,
			})
		}

		tx.TxIn[0].ValueIn = params.BlockOneSubsidy()

		return dcrutil.NewTx(tx), nil
	}

	// Create a coinbase with correct block subsidy and extranonce.
	subsidy := blockchain.CalcBlockWorkSubsidy(nextBlockHeight,
		voters,
		activeNetParams.Params)
	tax := blockchain.CalcBlockTaxSubsidy(nextBlockHeight,
		voters,
		activeNetParams.Params)
	addrOrg, err := dcrutil.DecodeAddress(params.OrganizationAddress, params)
	if err != nil {
		return nil, err
	}
	pksOrg, err := txscript.PayToAddrScript(addrOrg)
	if err != nil {
		return nil, err
	}

	// Tax output.
	if params.BlockTaxProportion > 0 {
		tx.AddTxOut(&wire.TxOut{
			Value:    tax,
			PkScript: pksOrg,
		})
	} else {
		// Tax disabled.
		scriptBuilder := txscript.NewScriptBuilder()
		trueScript, err := scriptBuilder.AddOp(txscript.OP_TRUE).Script()
		if err != nil {
			return nil, err
		}
		tx.AddTxOut(&wire.TxOut{
			Value:    tax,
			PkScript: trueScript,
		})
	}
	// Extranonce.
	tx.AddTxOut(&wire.TxOut{
		Value:    0,
		PkScript: opReturnPkScript,
	})
	// ValueIn.
	tx.TxIn[0].ValueIn = subsidy + tax

	// Create the script to pay to the provided payment address if one was
	// specified.  Otherwise create a script that allows the coinbase to be
	// redeemable by anyone.
	var pksSubsidy []byte
	if addr != nil {
		var err error
		pksSubsidy, err = txscript.PayToAddrScript(addr)
		if err != nil {
			return nil, err
		}
	} else {
		var err error
		scriptBuilder := txscript.NewScriptBuilder()
		pksSubsidy, err = scriptBuilder.AddOp(txscript.OP_TRUE).Script()
		if err != nil {
			return nil, err
		}
	}
	// Subsidy paid to miner.
	tx.AddTxOut(&wire.TxOut{
		Value:    subsidy,
		PkScript: pksSubsidy,
	})

	return dcrutil.NewTx(tx), nil
}

// spendTransaction updates the passed transaction store by marking the inputs
// to the passed transaction as spent.  It also adds the passed transaction to
// the store at the provided height.
func spendTransaction(txStore blockchain.TxStore, tx *dcrutil.Tx,
	height int64) error {
	for _, txIn := range tx.MsgTx().TxIn {
		originHash := &txIn.PreviousOutPoint.Hash
		originIndex := txIn.PreviousOutPoint.Index
		if originTx, exists := txStore[*originHash]; exists {
			originTx.Spent[originIndex] = true
		}
	}

	txStore[*tx.Sha()] = &blockchain.TxData{
		Tx:          tx,
		Hash:        tx.Sha(),
		BlockHeight: height,
		BlockIndex:  wire.NullBlockIndex,
		Spent:       make([]bool, len(tx.MsgTx().TxOut)),
		Err:         nil,
	}

	return nil
}

// logSkippedDeps logs any dependencies which are also skipped as a result of
// skipping a transaction while generating a block template at the trace level.
func logSkippedDeps(tx *dcrutil.Tx, deps *list.List) {
	if deps == nil {
		return
	}

	for e := deps.Front(); e != nil; e = e.Next() {
		item := e.Value.(*txPrioItem)
		minrLog.Tracef("Skipping tx %s since it depends on %s\n",
			item.tx.Sha(), tx.Sha())
	}
}

// minimumMedianTime returns the minimum allowed timestamp for a block building
// on the end of the current best chain.  In particular, it is one second after
// the median timestamp of the last several blocks per the chain consensus
// rules.
func minimumMedianTime(chainState *chainState) (time.Time, error) {
	chainState.Lock()
	defer chainState.Unlock()
	if chainState.pastMedianTimeErr != nil {
		return time.Time{}, chainState.pastMedianTimeErr
	}

	return chainState.pastMedianTime.Add(time.Second), nil
}

// medianAdjustedTime returns the current time adjusted to ensure it is at least
// one second after the median timestamp of the last several blocks per the
// chain consensus rules.
func medianAdjustedTime(chainState *chainState,
	timeSource blockchain.MedianTimeSource) (time.Time, error) {
	chainState.Lock()
	defer chainState.Unlock()
	if chainState.pastMedianTimeErr != nil {
		return time.Time{}, chainState.pastMedianTimeErr
	}

	// The timestamp for the block must not be before the median timestamp
	// of the last several blocks.  Thus, choose the maximum between the
	// current time and one second after the past median time.  The current
	// timestamp is truncated to a second boundary before comparison since a
	// block timestamp does not supported a precision greater than one
	// second.
	newTimestamp := timeSource.AdjustedTime()
	minTimestamp := chainState.pastMedianTime.Add(time.Second)
	if newTimestamp.Before(minTimestamp) {
		newTimestamp = minTimestamp
	}

	// Adjust by the amount requested from the command line argument.
	newTimestamp = newTimestamp.Add(
		time.Duration(-cfg.MiningTimeOffset) * time.Second)

	return newTimestamp, nil
}

// maybeInsertStakeTx checks to make sure that a stake tx is
// valid from the perspective of the mainchain (not necessarily
// the mempool or block) before inserting into a tx tree.
// If it fails the check, it returns false; otherwise true.
func maybeInsertStakeTx(mp *txMemPool, stx *dcrutil.Tx, treeValid bool) bool {
	bm := mp.server.blockManager

	missingInput := false

	txStore, err := bm.FetchTransactionStore(stx, treeValid)
	if err != nil {
		minrLog.Warnf("Unable to fetch transaction store for "+
			"stx %s: %v", stx.Sha(), err)
		return false
	}
	isSSGen, _ := stake.IsSSGen(stx)
	for i, txIn := range stx.MsgTx().TxIn {
		// Evaluate if this is a stakebase input or not. If it
		// is, continue without evaluation of the input.
		// if isStakeBase
		if isSSGen && (i == 0) {
			txIn.BlockHeight = wire.NullBlockHeight
			txIn.BlockIndex = wire.NullBlockIndex

			continue
		}

		originHash := &txIn.PreviousOutPoint.Hash
		txData, exists := txStore[*originHash]
		if !exists || txData.Err != nil || txData.Tx == nil {
			missingInput = true
			break
		} else {
			originIdx := txIn.PreviousOutPoint.Index
			txIn.ValueIn = txData.Tx.MsgTx().TxOut[originIdx].Value
			txIn.BlockHeight = uint32(txData.BlockHeight)
			txIn.BlockIndex = txData.BlockIndex
		}
	}
	return !missingInput
}

// deepCopyBlockTemplate returns a deeply copied block template that copies all
// data except a block's references to transactions, which are kept as pointers
// in the block. This is considered safe because transaction data is generally
// immutable, with the exception of coinbases which we alternatively also
// deep copy.
func deepCopyBlockTemplate(blockTemplate *BlockTemplate) *BlockTemplate {
	if blockTemplate == nil {
		return nil
	}

	// Deep copy the header, which we hash on.
	headerCopy := wire.BlockHeader{
		Version:     blockTemplate.block.Header.Version,
		PrevBlock:   blockTemplate.block.Header.PrevBlock,
		MerkleRoot:  blockTemplate.block.Header.MerkleRoot,
		StakeRoot:   blockTemplate.block.Header.StakeRoot,
		VoteBits:    blockTemplate.block.Header.VoteBits,
		FinalState:  blockTemplate.block.Header.FinalState,
		Voters:      blockTemplate.block.Header.Voters,
		FreshStake:  blockTemplate.block.Header.FreshStake,
		Revocations: blockTemplate.block.Header.Revocations,
		PoolSize:    blockTemplate.block.Header.PoolSize,
		Timestamp:   blockTemplate.block.Header.Timestamp,
		Bits:        blockTemplate.block.Header.Bits,
		SBits:       blockTemplate.block.Header.SBits,
		Nonce:       blockTemplate.block.Header.Nonce,
		Height:      blockTemplate.block.Header.Height,
		Size:        blockTemplate.block.Header.Size,
	}

	// Copy transactions pointers. Duplicate the coinbase
	// transaction, because it might update it by modifying
	// the extra nonce.
	transactionsCopy := make([]*wire.MsgTx, len(blockTemplate.block.Transactions),
		len(blockTemplate.block.Transactions))
	coinbaseCopy :=
		dcrutil.NewTxDeep(blockTemplate.block.Transactions[0])
	for i, mtx := range blockTemplate.block.Transactions {
		if i == 0 {
			transactionsCopy[i] = coinbaseCopy.MsgTx()
		} else {
			transactionsCopy[i] = mtx
		}
	}

	sTransactionsCopy := make([]*wire.MsgTx,
		len(blockTemplate.block.STransactions),
		len(blockTemplate.block.STransactions))
	for i, mtx := range blockTemplate.block.STransactions {
		sTransactionsCopy[i] = mtx
	}

	msgBlockCopy := &wire.MsgBlock{
		Header:        headerCopy,
		Transactions:  transactionsCopy,
		STransactions: sTransactionsCopy,
	}

	fees := make([]int64, len(blockTemplate.fees), len(blockTemplate.fees))
	for i, f := range blockTemplate.fees {
		fees[i] = f
	}

	sigOps := make([]int64, len(blockTemplate.sigOpCounts),
		len(blockTemplate.sigOpCounts))
	for i, s := range blockTemplate.sigOpCounts {
		sigOps[i] = s
	}

	return &BlockTemplate{
		block:           msgBlockCopy,
		fees:            fees,
		sigOpCounts:     sigOps,
		height:          blockTemplate.height,
		validPayAddress: blockTemplate.validPayAddress,
	}
}

// handleTooFewVoters handles the situation in which there are too few voters on
// of the blockchain. If there are too few voters and a cached parent template to
// work off of is present, it will return a copy of that template to pass to the
// miner.
// Safe for concurrent access.
func handleTooFewVoters(nextHeight int64,
	miningAddress dcrutil.Address,
	bm *blockManager) (*BlockTemplate, error) {
	timeSource := bm.server.timeSource
	chainState := &bm.chainState
	stakeValidationHeight := bm.server.chainParams.StakeValidationHeight
	curTemplate := bm.GetCurrentTemplate()

	// Check to see if we've fallen off the chain, for example if a
	// reorganization had recently occurred. If this is the case,
	// nuke the templates.
	bestHeader := chainState.GetTopBlockHeader()
	if curTemplate != nil {
		if !bestHeader.PrevBlock.IsEqual(
			&curTemplate.block.Header.PrevBlock) {
			minrLog.Debugf("Cached mining templates are no longer current, " +
				"resetting")
			bm.SetCurrentTemplate(nil)
			bm.SetParentTemplate(nil)
		}
	}

	// Handle not enough voters being present if we're set to mine aggressively
	// (default behaviour).
	if nextHeight >= stakeValidationHeight {
		if bm.AggressiveMining {
			if curTemplate != nil {
				cptCopy := deepCopyBlockTemplate(curTemplate)

				// Update the timestamp of the old template.
				ts, err := medianAdjustedTime(chainState, timeSource)
				if err != nil {
					return nil, err
				}
				cptCopy.block.Header.Timestamp = ts

				// If we're on testnet, the time since this last block
				// listed as the parent must be taken into consideration.
				if bm.server.chainParams.ResetMinDifficulty {
					parentHash := cptCopy.block.Header.PrevBlock

					requiredDifficulty, err :=
						bm.CalcNextRequiredDiffNode(&parentHash, ts)
					if err != nil {
						return nil, miningRuleError(ErrGettingDifficulty,
							err.Error())
					}

					cptCopy.block.Header.Bits = requiredDifficulty
				}

				// Choose a new extranonce value that is one greater
				// than the previous extranonce, so we don't remine the
				// same block and choose the same winners as before.
				ens := cptCopy.getCoinbaseExtranonces()
				ens[0]++
				UpdateExtraNonce(cptCopy.block, cptCopy.height, ens)

				// Update extranonce of the original template too, so
				// we keep getting unique numbers.
				UpdateExtraNonce(curTemplate.block, curTemplate.height, ens)

				// Make sure the block validates.
				block := dcrutil.NewBlockDeepCopyCoinbase(cptCopy.block)
				block.SetHeight(cptCopy.height)
				if err := blockchain.CheckWorklessBlockSanity(block,
					bm.server.timeSource,
					bm.server.chainParams); err != nil {
					return nil, miningRuleError(ErrCheckConnectBlock,
						err.Error())
				}

				if err := bm.CheckConnectBlock(block); err != nil {
					minrLog.Errorf("failed to check template while "+
						"duplicating a parent: %v", err.Error())
					return nil, miningRuleError(ErrCheckConnectBlock,
						err.Error())
				}

				return cptCopy, nil
			}

			// We may have just started mining and stored the current block
			// template, so we don't have a parent.
			if curTemplate == nil {
				// Fetch the latest block and head and begin working
				// off of it with an empty transaction tree regular
				// and the contents of that stake tree. In the future
				// we should have the option of readding some
				// transactions from this block, too.
				topBlock, err :=
					bm.GetTopBlockFromChain()
				if err != nil {
					return nil, fmt.Errorf("failed to get top block from " +
						"chain")
				}
				btMsgBlock := new(wire.MsgBlock)
				rand, err := wire.RandomUint64()
				if err != nil {
					return nil, err
				}
				opReturnPkScript, err :=
					standardCoinbaseOpReturn(topBlock.MsgBlock().Header.Height,
						[]uint64{0, 0, 0, rand})
				if err != nil {
					return nil, err
				}
				coinbaseTx, err := createCoinbaseTx([]byte{0x01, 0x02},
					opReturnPkScript,
					topBlock.Height(),
					miningAddress,
					topBlock.MsgBlock().Header.Voters,
					bm.server.chainParams)
				if err != nil {
					return nil, err
				}
				btMsgBlock.AddTransaction(coinbaseTx.MsgTx())

				for _, stx := range topBlock.STransactions() {
					btMsgBlock.AddSTransaction(stx.MsgTx())
				}

				// Copy the rest of the header.
				btMsgBlock.Header.Version =
					topBlock.MsgBlock().Header.Version
				btMsgBlock.Header.PrevBlock =
					topBlock.MsgBlock().Header.PrevBlock
				btMsgBlock.Header.VoteBits =
					topBlock.MsgBlock().Header.VoteBits
				btMsgBlock.Header.FinalState =
					topBlock.MsgBlock().Header.FinalState
				btMsgBlock.Header.Voters =
					topBlock.MsgBlock().Header.Voters
				btMsgBlock.Header.FreshStake =
					topBlock.MsgBlock().Header.FreshStake
				btMsgBlock.Header.Revocations =
					topBlock.MsgBlock().Header.Revocations
				btMsgBlock.Header.PoolSize =
					topBlock.MsgBlock().Header.PoolSize
				btMsgBlock.Header.Bits =
					topBlock.MsgBlock().Header.Bits
				btMsgBlock.Header.SBits =
					topBlock.MsgBlock().Header.SBits
				btMsgBlock.Header.Height =
					topBlock.MsgBlock().Header.Height

				// Set a fresh timestamp.
				ts, err := medianAdjustedTime(chainState, timeSource)
				if err != nil {
					return nil, err
				}
				btMsgBlock.Header.Timestamp = ts

				// If we're on testnet, the time since this last block
				// listed as the parent must be taken into consideration.
				if bm.server.chainParams.ResetMinDifficulty {
					parentHash := topBlock.MsgBlock().Header.PrevBlock

					requiredDifficulty, err :=
						bm.CalcNextRequiredDiffNode(&parentHash, ts)
					if err != nil {
						return nil, miningRuleError(ErrGettingDifficulty,
							err.Error())
					}

					btMsgBlock.Header.Bits = requiredDifficulty
				}

				// Recalculate the size.
				btMsgBlock.Header.Size = uint32(btMsgBlock.SerializeSize())

				bt := &BlockTemplate{
					block:           btMsgBlock,
					fees:            []int64{0},
					sigOpCounts:     []int64{0},
					height:          int64(topBlock.MsgBlock().Header.Height),
					validPayAddress: miningAddress != nil,
				}

				// Recalculate the merkle roots. Use a temporary 'immutable'
				// block object as we're changing the header contents.
				btBlockTemp := dcrutil.NewBlockDeepCopyCoinbase(btMsgBlock)
				merkles :=
					blockchain.BuildMerkleTreeStore(btBlockTemp.Transactions())
				merklesStake :=
					blockchain.BuildMerkleTreeStore(btBlockTemp.STransactions())
				btMsgBlock.Header.MerkleRoot = *merkles[len(merkles)-1]
				btMsgBlock.Header.StakeRoot = *merklesStake[len(merklesStake)-1]

				// Make sure the block validates.
				btBlock := dcrutil.NewBlockDeepCopyCoinbase(btMsgBlock)
				btBlock.SetHeight(bt.height)
				if err := blockchain.CheckWorklessBlockSanity(btBlock,
					bm.server.timeSource,
					bm.server.chainParams); err != nil {
					str := fmt.Sprintf("failed to check sanity of template "+
						"while constructing a new parent: %v",
						err.Error())
					return nil, miningRuleError(ErrCheckConnectBlock,
						str)
				}

				if err := bm.CheckConnectBlock(btBlock); err != nil {
					str := fmt.Sprintf("failed to check template: %v while "+
						"constructing a new parent", err.Error())
					return nil, miningRuleError(ErrCheckConnectBlock,
						str)
				}

				// Make a copy to return.
				cptCopy := deepCopyBlockTemplate(bt)

				return cptCopy, nil
			}
		}
	}

	bmgrLog.Debugf("Not enough voters on top block to generate " +
		"new block template")

	return nil, nil
}

// handleCreatedBlockTemplate stores a successfully created block template to
// the appropriate cache if needed, then returns the template to the miner to
// work on. The stored template is a copy of the template, to prevent races
// from occuring in case the template is mined on by the CPUminer.
func handleCreatedBlockTemplate(blockTemplate *BlockTemplate,
	bm *blockManager) (*BlockTemplate, error) {
	curTemplate := bm.GetCurrentTemplate()

	nextBlockHeight := blockTemplate.height
	stakeValidationHeight := bm.server.chainParams.StakeValidationHeight
	// This is where we begin storing block templates, when either the
	// program is freshly started or the chain is matured to stake
	// validation height.
	if curTemplate == nil &&
		nextBlockHeight >= stakeValidationHeight-2 {
		bm.SetCurrentTemplate(blockTemplate)
	}

	// We're at the height where the next block needs to include SSGens,
	// so we check to if CachedCurrentTemplate is out of date. If it is,
	// we store it as the cached parent template, and store the new block
	// template as the currenct template.
	if curTemplate != nil &&
		nextBlockHeight >= stakeValidationHeight-1 {
		if curTemplate.height < nextBlockHeight {
			bm.SetParentTemplate(curTemplate)
			bm.SetCurrentTemplate(blockTemplate)
		}
	}

	// Overwrite the old cached block if it's out of date.
	if curTemplate != nil {
		if curTemplate.height == nextBlockHeight {
			bm.SetCurrentTemplate(blockTemplate)
		}
	}

	return blockTemplate, nil
}

// NewBlockTemplate returns a new block template that is ready to be solved
// using the transactions from the passed transaction memory pool and a coinbase
// that either pays to the passed address if it is not nil, or a coinbase that
// is redeemable by anyone if the passed address is nil.  The nil address
// functionality is useful since there are cases such as the getblocktemplate
// RPC where external mining software is responsible for creating their own
// coinbase which will replace the one generated for the block template.  Thus
// the need to have configured address can be avoided.
//
// The transactions selected and included are prioritized according to several
// factors.  First, each transaction has a priority calculated based on its
// value, age of inputs, and size.  Transactions which consist of larger
// amounts, older inputs, and small sizes have the highest priority.  Second, a
// fee per kilobyte is calculated for each transaction.  Transactions with a
// higher fee per kilobyte are preferred.  Finally, the block generation related
// configuration options are all taken into account.
//
// Transactions which only spend outputs from other transactions already in the
// block chain are immediately added to a priority queue which either
// prioritizes based on the priority (then fee per kilobyte) or the fee per
// kilobyte (then priority) depending on whether or not the BlockPrioritySize
// configuration option allots space for high-priority transactions.
// Transactions which spend outputs from other transactions in the memory pool
// are added to a dependency map so they can be added to the priority queue once
// the transactions they depend on have been included.
//
// Once the high-priority area (if configured) has been filled with transactions,
// or the priority falls below what is considered high-priority, the priority
// queue is updated to prioritize by fees per kilobyte (then priority).
//
// When the fees per kilobyte drop below the TxMinFreeFee configuration option,
// the transaction will be skipped unless there is a BlockMinSize set, in which
// case the block will be filled with the low-fee/free transactions until the
// block size reaches that minimum size.
//
// Any transactions whome mulch to go put down which is more fun than replacing hashes
// configuration option, exceed the maximum allowed signature operations per
// block, or otherwise cause the block to be invalid are skipped.
//
// Given the above, a block generated by this function is of the following form:
//
//   -----------------------------------  --  --
//  |      Coinbase Transaction         |   |   |
//  |-----------------------------------|   |   |
//  |                                   |   |   | ----- cfg.BlockPrioritySize
//  |   High-priority Transactions      |   |   |
//  |                                   |   |   |
//  |-----------------------------------|   | --
//  |                                   |   |
//  |                                   |   |
//  |                                   |   |--- (cfg.BlockMaxSize) / 2
//  |  Transactions prioritized by fee  |   |
//  |  until <= cfg.TxMinFreeFee        |   |
//  |                                   |   |
//  |                                   |   |
//  |                                   |   |
//  |-----------------------------------|   |
//  |  Low-fee/Non high-priority (free) |   |
//  |  transactions (while block size   |   |
//  |  <= cfg.BlockMinSize)             |   |
//   -----------------------------------  --
//
// TODO - DECRED
// We also need to include a stake tx tree that looks like the following:
//
//   -----------------------------------  --  --
//  |                                   |   |   |
//  |           SSGen tx                |   |   | ----- cfg.SSGenAllocatedSize ?
//  |                                   |   |   |
//  |-----------------------------------|   | --
//  |                                   |   |
//  |            SStx tx                |   |--- (cfg.BlockMaxSize) / 2
//  |                                   |   |
//  |-----------------------------------|   |
//  |                                   |   |
//  |           SSRtx tx                |   |
//  |                                   |   |
//   -----------------------------------  --
//
//  This function returns nil, nil if there are not enough voters on any of
//  the current top blocks to create a new block template.
func NewBlockTemplate(mempool *txMemPool,
	payToAddress dcrutil.Address) (*BlockTemplate, error) {
	blockManager := mempool.server.blockManager
	timeSource := mempool.server.timeSource
	chainState := &blockManager.chainState

	// Extend the most recently known best block.
	// The most recently known best block is the top block that has the most
	// ssgen votes for it. We only need this after the height in which stake voting
	// has kicked in.
	// To figure out which block has the most ssgen votes, we need to run the
	// following algorithm:
	// 1. Acquire the HEAD block and all of its orphans. Record their block header
	// hashes.
	// 2. Create a map of [blockHeaderHash] --> [mempoolTxnList].
	// 3. for blockHeaderHash in candidateBlocks:
	//		if mempoolTx.StakeDesc == SSGen &&
	//			mempoolTx.SSGenParseBlockHeader() == blockHeaderHash:
	//			map[blockHeaderHash].append(mempoolTx)
	// 4. Check len of each map entry and store.
	// 5. Query the ticketdb and check how many eligible ticket holders there are
	//    for the given block you are voting on.
	// 6. Divide #ofvotes (len(map entry)) / totalPossibleVotes --> penalty ratio
	// 7. Store penalty ratios for all block candidates.
	// 8. Select the one with the largest penalty ratio (highest block reward).
	//    This block is then selected to build upon instead of the others, because
	//    it yields the greater amount of rewards.
	chainState.Lock()
	prevHash := chainState.newestHash
	nextBlockHeight := chainState.newestHeight + 1
	poolSize := chainState.nextPoolSize
	requiredStakeDifficulty := chainState.nextStakeDifficulty
	finalState := chainState.nextFinalState
	winningTickets := make([]chainhash.Hash, len(chainState.winningTickets),
		len(chainState.winningTickets))
	for i, h := range chainState.winningTickets {
		winningTickets[i] = h
	}
	missedTickets := make([]chainhash.Hash, len(chainState.missedTickets),
		len(chainState.missedTickets))
	for i, h := range chainState.missedTickets {
		missedTickets[i] = h
	}
	chainState.Unlock()

	// Calculate the stake enabled height.
	stakeValidationHeight := mempool.server.chainParams.StakeValidationHeight

	if nextBlockHeight >= stakeValidationHeight {
		// Obtain the entire generation of blocks stemming from this parent.
		children, err := blockManager.GetGeneration(*prevHash)
		if err != nil {
			return nil, miningRuleError(ErrFailedToGetGeneration, err.Error())
		}

		// Get the list of blocks that we can actually build on top of. If we're
		// not currently on the block that has the most votes, switch to that
		// block.
		eligibleParents, err := mempool.SortParentsByVotes(*prevHash, children)
		if err != nil {
			if err.(MiningRuleError).GetCode() == ErrNotEnoughVoters {
				minrLog.Debugf("Too few voters found on any HEAD block, " +
					"recycling a parent block to mine on")
				return handleTooFewVoters(nextBlockHeight, payToAddress,
					mempool.server.blockManager)
			}
			minrLog.Errorf("unexpected error while sorting eligible "+
				"parents: %v", err.Error())
			return nil, err
		}

		minrLog.Debugf("Found eligible parent %v with enough votes to build "+
			"block on, proceeding to create a new block template",
			eligibleParents[0])

		// Force a reorganization to the parent with the most votes if we need
		// to.
		if !eligibleParents[0].IsEqual(prevHash) {
			for _, newHead := range eligibleParents {
				err := blockManager.ForceReorganization(*prevHash, newHead)
				if err != nil {
					minrLog.Errorf("failed to reorganize to new parent: %v", err)
					continue
				}

				// Check to make sure we actually have the transactions
				// (votes) we need in the mempool.
				voteHashes, err := mempool.GetVoteHashesForBlock(newHead)
				if err != nil {
					return nil, err
				}

				if exist := mempool.CheckIfTxsExist(voteHashes); !exist {
					continue
				} else {
					prevHash = &newHead
					break
				}
			}
		}
	}

	// Get the current memory pool transactions and create a priority queue
	// to hold the transactions which are ready for inclusion into a block
	// along with some priority related and fee metadata.  Reserve the same
	// number of items that are in the memory pool for the priority queue.
	// Also, choose the initial sort order for the priority queue based on
	// whether or not there is an area allocated for high-priority
	// transactions.
	mempoolTxns := mempool.TxDescs()
	sortedByFee := cfg.BlockPrioritySize == 0
	lessFunc := txPQByStakeAndFeeAndThenPriority
	if sortedByFee {
		lessFunc = txPQByStakeAndFee
	}
	priorityQueue := newTxPriorityQueue(len(mempoolTxns), lessFunc)

	// Create a slice to hold the transactions to be included in the
	// generated block with reserved space.  Also create a transaction
	// store to house all of the input transactions so multiple lookups
	// can be avoided.
	blockTxns := make([]*dcrutil.Tx, 0, len(mempoolTxns))
	blockTxStore := make(blockchain.TxStore)

	// dependers is used to track transactions which depend on another
	// transaction in the memory pool.  This, in conjunction with the
	// dependsOn map kept with each dependent transaction helps quickly
	// determine which dependent transactions are now eligible for inclusion
	// in the block once each transaction has been included.
	dependers := make(map[chainhash.Hash]*list.List)

	// Create slices to hold the fees and number of signature operations
	// for each of the selected transactions and add an entry for the
	// coinbase.  This allows the code below to simply append details about
	// a transaction as it is selected for inclusion in the final block.
	// However, since the total fees aren't known yet, use a dummy value for
	// the coinbase fee which will be updated later.
	txFees := make([]int64, 0, len(mempoolTxns))
	txFeesMap := make(map[chainhash.Hash]int64)
	txSigOpCounts := make([]int64, 0, len(mempoolTxns))
	txSigOpCountsMap := make(map[chainhash.Hash]int64)
	txFees = append(txFees, -1) // Updated once known

	minrLog.Debugf("Considering %d mempool transactions for inclusion to "+
		"new block", len(mempoolTxns))
	treeValid := mempool.IsTxTreeValid(prevHash)

mempoolLoop:
	for _, txDesc := range mempoolTxns {
		// A block can't have more than one coinbase or contain
		// non-finalized transactions.
		tx := txDesc.Tx
		if blockchain.IsCoinBase(tx) {
			minrLog.Tracef("Skipping coinbase tx %s", tx.Sha())
			continue
		}
		if !blockchain.IsFinalizedTransaction(tx, nextBlockHeight,
			timeSource.AdjustedTime()) {

			minrLog.Tracef("Skipping non-finalized tx %s", tx.Sha())
			continue
		}

		// Need this for a check below for stake base input, and to check
		// the ticket number.
		isSSGen := txDesc.Type == stake.TxTypeSSGen
		if isSSGen {
			blockHash, blockHeight, err := stake.GetSSGenBlockVotedOn(tx)
			if err != nil { // Should theoretically never fail.
				minrLog.Tracef("Skipping ssgen tx %s because of failure "+
					"to extract block voting data", tx.Sha())
				continue
			}

			if !((blockHash == *prevHash) &&
				(int64(blockHeight) == nextBlockHeight-1)) {
				minrLog.Tracef("Skipping ssgen tx %s because it does "+
					"not vote on the correct block", tx.Sha())
				continue
			}
		}

		// Fetch all of the transactions referenced by the inputs to
		// this transaction.  NOTE: This intentionally does not fetch
		// inputs from the mempool since a transaction which depends on
		// other transactions in the mempool must come after those
		// dependencies in the final generated block.
		txStore, err := blockManager.FetchTransactionStore(tx, treeValid)
		if err != nil {
			minrLog.Warnf("Unable to fetch transaction store for "+
				"tx %s: %v", tx.Sha(), err)
			continue
		}

		// Calculate the input value age sum for the transaction.  This
		// is comprised of the sum all of input amounts multiplied by
		// their respective age (number of confirmations since the
		// referenced input transaction).  While doing the above, also
		// setup dependencies for any transactions which reference other
		// transactions in the mempool so they can be properly ordered
		// below.
		prioItem := &txPrioItem{tx: txDesc.Tx, txType: txDesc.Type}
		inputValueAge := float64(0.0)
		for i, txIn := range tx.MsgTx().TxIn {
			// Evaluate if this is a stakebase input or not. If it is, continue
			// without evaluation of the input.
			// if isStakeBase
			if isSSGen && (i == 0) {
				continue
			}

			originHash := &txIn.PreviousOutPoint.Hash
			originIndex := txIn.PreviousOutPoint.Index
			txData, exists := txStore[*originHash]
			if !exists || txData.Err != nil || txData.Tx == nil {
				if !mempool.HaveTransaction(originHash) {
					minrLog.Tracef("Skipping tx %s because "+
						"it references tx %s which is "+
						"not available", tx.Sha,
						originHash)
					continue mempoolLoop
				}

				// The transaction is referencing another
				// transaction in the memory pool, so setup an
				// ordering dependency.
				depList, exists := dependers[*originHash]
				if !exists {
					depList = list.New()
					dependers[*originHash] = depList
				}
				depList.PushBack(prioItem)
				if prioItem.dependsOn == nil {
					prioItem.dependsOn = make(
						map[chainhash.Hash]struct{})
				}
				prioItem.dependsOn[*originHash] = struct{}{}

				// No need to calculate or sum input value age
				// for this input since it's zero due to
				// the input age multiplier of 0.
				continue
			}

			// Ensure the output index in the referenced transaction
			// is available.
			msgTx := txData.Tx.MsgTx()
			if originIndex > uint32(len(msgTx.TxOut)) {
				minrLog.Tracef("Skipping tx %s because "+
					"it references output %d of tx %s "+
					"which is out of bounds", tx.Sha,
					originIndex, originHash)
				continue mempoolLoop
			}

			// Sum the input value times age.
			originTxOut := txData.Tx.MsgTx().TxOut[originIndex]
			inputValue := originTxOut.Value
			inputAge := nextBlockHeight - txData.BlockHeight
			inputValueAge += float64(inputValue * inputAge)
		}

		// Calculate the final transaction priority using the input
		// value age sum as well as the adjusted transaction size.  The
		// formula is: sum(inputValue * inputAge) / adjustedTxSize
		txSize := tx.MsgTx().SerializeSize()
		prioItem.priority = calcPriority(tx, inputValueAge)

		// Calculate the fee in Atoms/KB.
		// NOTE: This is a more precise value than the one calculated
		// during calcMinRelayFee which rounds up to the nearest full
		// kilobyte boundary.  This is beneficial since it provides an
		// incentive to create smaller transactions.
		prioItem.feePerKB = (float64(txDesc.Fee) * float64(kilobyte)) /
			float64(txSize)
		prioItem.fee = txDesc.Fee

		// Add the transaction to the priority queue to mark it ready
		// for inclusion in the block unless it has dependencies.
		if prioItem.dependsOn == nil {
			heap.Push(priorityQueue, prioItem)
		}

		// Merge the store which contains all of the input transactions
		// for this transaction into the input transaction store.  This
		// allows the code below to avoid a second lookup.
		mergeTxStore(blockTxStore, txStore)
	}

	minrLog.Tracef("Priority queue len %d, dependers len %d",
		priorityQueue.Len(), len(dependers))

	// The starting block size is the size of the block header plus the max
	// possible transaction count size, plus the size of the coinbase
	// transaction.
	blockSize := uint32(blockHeaderOverhead)

	// Guesstimate for sigops based on valid txs in loop below. This number
	// tends to overestimate sigops because of the way the loop below is
	// coded and the fact that tx can sometimes be removed from the tx
	// trees if they fail one of the stake checks below the priorityQueue
	// pop loop. This is buggy, but not catastrophic behaviour. A future
	// release should fix it. TODO
	blockSigOps := int64(0)
	totalFees := int64(0)

	numSStx := 0

	foundWinningTickets := make(map[chainhash.Hash]bool, len(winningTickets))
	for _, ticketHash := range winningTickets {
		foundWinningTickets[ticketHash] = false
	}

	// Choose which transactions make it into the block.
	for priorityQueue.Len() > 0 {
		// Grab the highest priority (or highest fee per kilobyte
		// depending on the sort order) transaction.
		prioItem := heap.Pop(priorityQueue).(*txPrioItem)
		tx := prioItem.tx

		// Store if this is an SStx or not.
		isSStx := prioItem.txType == stake.TxTypeSStx

		// Store if this is an SSGen or not.
		isSSGen := prioItem.txType == stake.TxTypeSSGen

		// Store if this is an SSRtx or not.
		isSSRtx := prioItem.txType == stake.TxTypeSSRtx

		// Grab the list of transactions which depend on this one (if
		// any) and remove the entry for this transaction as it will
		// either be included or skipped, but in either case the deps
		// are no longer needed.
		deps := dependers[*tx.Sha()]
		delete(dependers, *tx.Sha())

		// Skip if we already have too many SStx.
		if isSStx && (numSStx >=
			int(mempool.server.chainParams.MaxFreshStakePerBlock)) {
			minrLog.Tracef("Skipping sstx %s because it would exceed "+
				"the max number of sstx allowed in a block", tx.Sha())
			logSkippedDeps(tx, deps)
			continue
		}

		// Skip if the SStx commit value is below the value required by the
		// stake diff.
		if isSStx && (tx.MsgTx().TxOut[0].Value < requiredStakeDifficulty) {
			continue
		}

		// Skip all missed tickets that we've never heard of.
		if isSSRtx {
			ticketHash := &tx.MsgTx().TxIn[0].PreviousOutPoint.Hash

			if !hashExistsInList(ticketHash, missedTickets) {
				continue
			}
		}

		// Enforce maximum block size.  Also check for overflow.
		txSize := uint32(tx.MsgTx().SerializeSize())
		blockPlusTxSize := blockSize + txSize
		if blockPlusTxSize < blockSize || blockPlusTxSize >=
			uint32(mempool.server.chainParams.MaximumBlockSize) {
			minrLog.Tracef("Skipping tx %s (size %v) because it would exceed "+
				"the max block size; cur block size %v, cur num tx %v", tx.Sha(),
				txSize, blockSize, len(blockTxns))
			logSkippedDeps(tx, deps)
			continue
		}

		// Enforce maximum signature operations per block.  Also check
		// for overflow.
		numSigOps := int64(blockchain.CountSigOps(tx, false, isSSGen))
		if blockSigOps+numSigOps < blockSigOps ||
			blockSigOps+numSigOps > blockchain.MaxSigOpsPerBlock {
			minrLog.Tracef("Skipping tx %s because it would "+
				"exceed the maximum sigops per block", tx.Sha())
			logSkippedDeps(tx, deps)
			continue
		}

		// This isn't very expensive, but we do this check a number of times.
		// Consider caching this in the mempool in the future. - Decred
		numP2SHSigOps, err := blockchain.CountP2SHSigOps(tx, false,
			isSSGen, blockTxStore)
		if err != nil {
			minrLog.Tracef("Skipping tx %s due to error in "+
				"CountP2SHSigOps: %v", tx.Sha(), err)
			logSkippedDeps(tx, deps)
			continue
		}
		numSigOps += int64(numP2SHSigOps)
		if blockSigOps+numSigOps < blockSigOps ||
			blockSigOps+numSigOps > blockchain.MaxSigOpsPerBlock {
			minrLog.Tracef("Skipping tx %s because it would "+
				"exceed the maximum sigops per block (p2sh)",
				tx.Sha())
			logSkippedDeps(tx, deps)
			continue
		}

		// Check to see if the SSGen tx actually uses a ticket that is
		// valid for the next block.
		if isSSGen {
			if foundWinningTickets[tx.MsgTx().TxIn[1].PreviousOutPoint.Hash] {
				continue
			}
			msgTx := tx.MsgTx()
			isEligible := false
			for _, sstxHash := range winningTickets {
				if sstxHash.IsEqual(&msgTx.TxIn[1].PreviousOutPoint.Hash) {
					isEligible = true
				}
			}

			if !isEligible {
				continue
			}
		}

		// Skip free transactions once the block is larger than the
		// minimum block size, except for stake transactions.
		if sortedByFee &&
			(prioItem.feePerKB < float64(cfg.minRelayTxFee)) &&
			(tx.Tree() != dcrutil.TxTreeStake) &&
			(blockPlusTxSize >= cfg.BlockPrioritySize) {

			minrLog.Tracef("Skipping tx %s with feePerKB %.2f "+
				"< minTxRelayFee %v and block size %d >= "+
				"BlockPrioritySize %v", tx.Sha(), prioItem.feePerKB,
				cfg.minRelayTxFee, blockPlusTxSize,
				cfg.BlockPrioritySize)
			logSkippedDeps(tx, deps)
			continue
		}

		// Prioritize by fee per kilobyte once the block is larger than
		// the priority size or there are no more high-priority
		// transactions.
		if !sortedByFee && (blockPlusTxSize >= cfg.BlockPrioritySize ||
			prioItem.priority <= minHighPriority) {

			minrLog.Tracef("Switching to sort by fees per "+
				"kilobyte blockSize %d >= BlockPrioritySize "+
				"%d || priority %.2f <= minHighPriority %.2f",
				blockPlusTxSize, cfg.BlockPrioritySize,
				prioItem.priority, minHighPriority)

			sortedByFee = true
			priorityQueue.SetLessFunc(txPQByFee)

			// Put the transaction back into the priority queue and
			// skip it so it is re-priortized by fees if it won't
			// fit into the high-priority section or the priority is
			// too low.  Otherwise this transaction will be the
			// final one in the high-priority section, so just fall
			// though to the code below so it is added now.
			if blockPlusTxSize > cfg.BlockPrioritySize ||
				prioItem.priority < minHighPriority {

				heap.Push(priorityQueue, prioItem)
				continue
			}
		}

		// Ensure the transaction inputs pass all of the necessary
		// preconditions before allowing it to be added to the block.
		_, err = blockchain.CheckTransactionInputs(tx,
			nextBlockHeight,
			blockTxStore,
			false, // Don't check fraud proofs; missing ones are filled out below
			mempool.server.chainParams)
		if err != nil {
			minrLog.Tracef("Skipping tx %s due to error in "+
				"CheckTransactionInputs: %v", tx.Sha(), err)
			logSkippedDeps(tx, deps)
			continue
		}
		err = blockchain.ValidateTransactionScripts(tx, blockTxStore,
			txscript.StandardVerifyFlags, mempool.server.sigCache)
		if err != nil {
			minrLog.Tracef("Skipping tx %s due to error in "+
				"ValidateTransactionScripts: %v", tx.Sha(), err)
			logSkippedDeps(tx, deps)
			continue
		}

		// Spend the transaction inputs in the block transaction store
		// and add an entry for it to ensure any transactions which
		// reference this one have it available as an input and can
		// ensure they aren't double spending.
		spendTransaction(blockTxStore, tx, nextBlockHeight)

		// Add the transaction to the block, increment counters, and
		// save the fees and signature operation counts to the block
		// template.
		blockTxns = append(blockTxns, tx)
		blockSize += txSize
		blockSigOps += numSigOps

		// Accumulate the SStxs in the block, because only a certain number
		// are allowed.
		if isSStx {
			numSStx++
		}
		if isSSGen {
			foundWinningTickets[tx.MsgTx().TxIn[1].PreviousOutPoint.Hash] = true
		}

		txFeesMap[*tx.Sha()] = prioItem.fee
		txSigOpCountsMap[*tx.Sha()] = numSigOps

		minrLog.Tracef("Adding tx %s (priority %.2f, feePerKB %.2f)",
			prioItem.tx.Sha(), prioItem.priority, prioItem.feePerKB)

		// Add transactions which depend on this one (and also do not
		// have any other unsatisified dependencies) to the priority
		// queue.
		if deps != nil {
			for e := deps.Front(); e != nil; e = e.Next() {
				// Add the transaction to the priority queue if
				// there are no more dependencies after this
				// one.
				item := e.Value.(*txPrioItem)
				delete(item.dependsOn, *tx.Sha())
				if len(item.dependsOn) == 0 {
					heap.Push(priorityQueue, item)
				}
			}
		}
	}

	// Build tx list for stake tx.
	blockTxnsStake := make([]*dcrutil.Tx, 0, len(blockTxns))

	// Stake tx ordering in stake tree:
	// 1. SSGen (votes).
	// 2. SStx (fresh stake tickets).
	// 3. SSRtx (revocations for missed tickets).

	// Get the block votes (SSGen tx) and store them and their number.
	voters := 0
	var voteBitsVoters []uint16

	for _, tx := range blockTxns {
		if nextBlockHeight < stakeValidationHeight {
			break // No SSGen should be present before this height.
		}

		if isSSGen, _ := stake.IsSSGen(tx); isSSGen {
			txCopy := dcrutil.NewTxDeepTxIns(tx.MsgTx())
			if maybeInsertStakeTx(mempool, txCopy, treeValid) {
				vb := stake.GetSSGenVoteBits(txCopy)
				voteBitsVoters = append(voteBitsVoters, vb)
				blockTxnsStake = append(blockTxnsStake, txCopy)
				voters++
			}
		}

		// Don't let this overflow, although probably it's impossible.
		if voters >= math.MaxUint16 {
			break
		}
	}

	// Set votebits, which determines whether the TxTreeRegular of the previous
	// block is valid or not.
	var votebits uint16
	if nextBlockHeight < stakeValidationHeight {
		votebits = uint16(0x0001) // TxTreeRegular enabled pre-staking
	} else {
		// Otherwise, we need to check the votes to determine if the tx tree was
		// validated or not.
		voteYea := 0
		totalVotes := 0

		for _, vb := range voteBitsVoters {
			if dcrutil.IsFlagSet16(vb, dcrutil.BlockValid) {
				voteYea++
			}
			totalVotes++
		}

		if voteYea == 0 { // Handle zero case for div by zero error prevention.
			votebits = uint16(0x0000) // TxTreeRegular disabled
		} else if (totalVotes / voteYea) <= 1 {
			votebits = uint16(0x0001) // TxTreeRegular enabled
		} else {
			votebits = uint16(0x0000) // TxTreeRegular disabled
		}

		if votebits == uint16(0x0000) {
			// In the event TxTreeRegular is disabled, we need to remove all tx
			// in the current block that depend on tx from the TxTreeRegular of
			// the previous block.
			// DECRED WARNING: The ideal behaviour should also be that we re-add
			// all tx that we just removed from the previous block into our
			// current block template. Right now this code fails to do that;
			// these tx will then be included in the next block, which isn't
			// catastrophic but is kind of buggy.

			// Retrieve the current top block, whose TxTreeRegular was voted
			// out.
			// Decred TODO: This is super inefficient, this block should be
			// cached and stored somewhere.
			topBlock, err := blockManager.GetTopBlockFromChain()
			if err != nil {
				return nil, miningRuleError(ErrGetTopBlock, "couldn't get "+
					"top block")
			}
			topBlockRegTx := topBlock.Transactions()

			tempBlockTxns := make([]*dcrutil.Tx, 0, len(mempoolTxns))
			for _, tx := range blockTxns {
				if tx.Tree() == dcrutil.TxTreeRegular {
					// Go through all the inputs and check to see if this mempool
					// tx uses outputs from the parent block. This loop is
					// probably very expensive.
					isValid := true
					for _, txIn := range tx.MsgTx().TxIn {
						for _, parentTx := range topBlockRegTx {
							if txIn.PreviousOutPoint.Hash.IsEqual(
								parentTx.Sha()) {
								isValid = false
							}
						}
					}

					if isValid {
						txCopy := dcrutil.NewTxDeepTxIns(tx.MsgTx())
						tempBlockTxns = append(tempBlockTxns, txCopy)
					}
				} else {
					txCopy := dcrutil.NewTxDeepTxIns(tx.MsgTx())
					tempBlockTxns = append(tempBlockTxns, txCopy)
				}
			}

			// Replace blockTxns with the pruned list of valid mempool tx.
			blockTxns = tempBlockTxns
		}
	}

	// Get the newly purchased tickets (SStx tx) and store them and their number.
	freshStake := 0
	for _, tx := range blockTxns {
		isSStx, _ := stake.IsSStx(tx)
		if tx.Tree() == dcrutil.TxTreeStake && isSStx {
			// A ticket can not spend an input from TxTreeRegular, since it
			// has not yet been validated.
			if containsTxIns(blockTxns, tx) {
				continue
			}

			// Quick check for difficulty here.
			if tx.MsgTx().TxOut[0].Value >= requiredStakeDifficulty {
				txCopy := dcrutil.NewTxDeepTxIns(tx.MsgTx())
				if maybeInsertStakeTx(mempool, txCopy, treeValid) {
					blockTxnsStake = append(blockTxnsStake, txCopy)
					freshStake++
				}
			}
		}

		// Don't let this overflow.
		if freshStake >= int(mempool.server.chainParams.MaxFreshStakePerBlock) {
			break
		}
	}

	// Get the ticket revocations (SSRtx tx) and store them and their number.
	revocations := 0
	for _, tx := range blockTxns {
		if nextBlockHeight < stakeValidationHeight {
			break // No SSRtx should be present before this height.
		}

		isSSRtx, _ := stake.IsSSRtx(tx)
		if tx.Tree() == dcrutil.TxTreeStake && isSSRtx {
			txCopy := dcrutil.NewTxDeepTxIns(tx.MsgTx())
			if maybeInsertStakeTx(mempool, txCopy, treeValid) {
				blockTxnsStake = append(blockTxnsStake, txCopy)
				revocations++
			}
		}

		// Don't let this overflow.
		if revocations >= math.MaxUint8 {
			break
		}
	}

	// Create a standard coinbase transaction paying to the provided
	// address.  NOTE: The coinbase value will be updated to include the
	// fees from the selected transactions later after they have actually
	// been selected.  It is created here to detect any errors early
	// before potentially doing a lot of work below.  The extra nonce helps
	// ensure the transaction is not a duplicate transaction (paying the
	// same value to the same public key address would otherwise be an
	// identical transaction for block version 1).
	// Decred: We need to move this downwards because of the requirements
	// to incorporate voters and potential voters.
	coinbaseScript := []byte{0x00, 0x00}
	coinbaseScript = append(coinbaseScript, []byte(coinbaseFlags)...)

	// Add a random coinbase nonce to ensure that tx prefix hash
	// so that our merkle root is unique for lookups needed for
	// getwork, etc.
	rand, err := wire.RandomUint64()
	if err != nil {
		return nil, err
	}
	opReturnPkScript, err := standardCoinbaseOpReturn(uint32(nextBlockHeight),
		[]uint64{0, 0, 0, rand})
	if err != nil {
		return nil, err
	}
	coinbaseTx, err := createCoinbaseTx(coinbaseScript,
		opReturnPkScript,
		nextBlockHeight,
		payToAddress,
		uint16(voters),
		mempool.server.chainParams)
	if err != nil {
		return nil, err
	}

	coinbaseTx.SetTree(dcrutil.TxTreeRegular) // Coinbase only in regular tx tree
	if err != nil {
		return nil, err
	}
	numCoinbaseSigOps := int64(blockchain.CountSigOps(coinbaseTx, true, false))
	blockSize += uint32(coinbaseTx.MsgTx().SerializeSize())
	blockSigOps += numCoinbaseSigOps
	txFeesMap[*coinbaseTx.Sha()] = 0
	txSigOpCountsMap[*coinbaseTx.Sha()] = numCoinbaseSigOps

	// Build tx lists for regular tx.
	blockTxnsRegular := make([]*dcrutil.Tx, 0, len(blockTxns)+1)

	// Append coinbase.
	blockTxnsRegular = append(blockTxnsRegular, coinbaseTx)

	// Assemble the two transaction trees.
	for _, tx := range blockTxns {
		if tx.Tree() == dcrutil.TxTreeRegular {
			blockTxnsRegular = append(blockTxnsRegular, tx)
		} else if tx.Tree() == dcrutil.TxTreeStake {
			continue
		} else {
			minrLog.Tracef("Error adding tx %s to block; invalid tree", tx.Sha())
			continue
		}
	}

	for _, tx := range blockTxnsRegular {
		fee, ok := txFeesMap[*tx.Sha()]
		if !ok {
			return nil, fmt.Errorf("couldn't find fee for tx %v",
				*tx.Sha())
		}
		totalFees += fee
		txFees = append(txFees, fee)

		tsos, ok := txSigOpCountsMap[*tx.Sha()]
		if !ok {
			return nil, fmt.Errorf("couldn't find sig ops count for tx %v",
				*tx.Sha())
		}
		txSigOpCounts = append(txSigOpCounts, tsos)
	}

	for _, tx := range blockTxnsStake {
		fee, ok := txFeesMap[*tx.Sha()]
		if !ok {
			return nil, fmt.Errorf("couldn't find fee for stx %v",
				*tx.Sha())
		}
		totalFees += fee
		txFees = append(txFees, fee)

		tsos, ok := txSigOpCountsMap[*tx.Sha()]
		if !ok {
			return nil, fmt.Errorf("couldn't find sig ops count for stx %v",
				*tx.Sha())
		}
		txSigOpCounts = append(txSigOpCounts, tsos)
	}

	txSigOpCounts = append(txSigOpCounts, numCoinbaseSigOps)

	// If we're greater than or equal to stake validation height, scale the
	// fees according to the number of voters.
	totalFees *= int64(voters)
	totalFees /= int64(mempool.server.chainParams.TicketsPerBlock)

	// Now that the actual transactions have been selected, update the
	// block size for the real transaction count and coinbase value with
	// the total fees accordingly.
	if nextBlockHeight > 1 {
		blockSize -= wire.MaxVarIntPayload -
			uint32(wire.VarIntSerializeSize(uint64(len(blockTxnsRegular))+
				uint64(len(blockTxnsStake))))
		coinbaseTx.MsgTx().TxOut[2].Value += totalFees
		txFees[0] = -totalFees
	}

	// Calculate the required difficulty for the block.  The timestamp
	// is potentially adjusted to ensure it comes after the median time of
	// the last several blocks per the chain consensus rules.
	ts, err := medianAdjustedTime(chainState, timeSource)
	if err != nil {
		return nil, miningRuleError(ErrGettingMedianTime, err.Error())
	}

	requiredDifficulty, err := blockManager.CalcNextRequiredDifficulty(ts)
	if err != nil {
		return nil, miningRuleError(ErrGettingDifficulty, err.Error())
	}

	// Return nil if we don't yet have enough voters; sometimes it takes a
	// bit for the mempool to sync with the votes map and we end up down
	// here despite having the relevant votes available in the votes map.
	minimumVotesRequired :=
		int((mempool.server.chainParams.TicketsPerBlock / 2) + 1)
	if nextBlockHeight >= stakeValidationHeight &&
		voters < minimumVotesRequired {
		minrLog.Warnf("incongruent number of voters in mempool " +
			"vs mempool.voters; not enough voters found")
		return handleTooFewVoters(nextBlockHeight, payToAddress,
			mempool.server.blockManager)
	}

	// Correct transaction index fraud proofs for any transactions that
	// are chains. maybeInsertStakeTx fills this in for stake transactions
	// already, so only do it for regular transactions.
	for i, tx := range blockTxnsRegular {
		txs, err := blockManager.FetchTransactionStore(tx, treeValid)
		if err != nil {
			str := fmt.Sprintf("failed to fetch tx store for tx %v",
				tx.Sha())
			return nil, miningRuleError(ErrFetchTxStore, str)
		}

		// Copy the transaction and swap the pointer.
		txCopy := dcrutil.NewTxDeepTxIns(tx.MsgTx())
		blockTxnsRegular[i] = txCopy
		tx = txCopy

		for _, txIn := range tx.MsgTx().TxIn {
			originHash := &txIn.PreviousOutPoint.Hash
			txData, exists := txs[*originHash]
			if !exists || txData.Err != nil || txData.Tx == nil {
				// Set a flag with the index so we can properly set
				// the fraud proof below.
				txIn.BlockIndex = wire.NullBlockIndex
			} else {
				originIdx := txIn.PreviousOutPoint.Index
				txIn.ValueIn = txData.Tx.MsgTx().TxOut[originIdx].Value
				txIn.BlockHeight = uint32(txData.BlockHeight)
				txIn.BlockIndex = txData.BlockIndex
			}
		}
	}

	// Fill in locally referenced inputs.
	for i, tx := range blockTxnsRegular {
		// Skip coinbase.
		if i == 0 {
			continue
		}

		// Copy the transaction and swap the pointer.
		txCopy := dcrutil.NewTxDeepTxIns(tx.MsgTx())
		blockTxnsRegular[i] = txCopy
		tx = txCopy

		for _, txIn := range tx.MsgTx().TxIn {
			// This tx was at some point 0-conf and now requires the
			// correct block height and index. Set it here.
			if txIn.BlockIndex == wire.NullBlockIndex {
				idx := txIndexFromTxList(txIn.PreviousOutPoint.Hash,
					blockTxnsRegular)

				// The input is in the block, set it accordingly.
				if idx != -1 {
					originIdx := txIn.PreviousOutPoint.Index
					amt := blockTxnsRegular[idx].MsgTx().TxOut[originIdx].Value
					txIn.ValueIn = amt
					txIn.BlockHeight = uint32(nextBlockHeight)
					txIn.BlockIndex = uint32(idx)
				} else {
					str := fmt.Sprintf("failed find hash in tx list "+
						"for fraud proof; tx in hash %v",
						txIn.PreviousOutPoint.Hash)
					return nil, miningRuleError(ErrFraudProofIndex, str)
				}
			}
		}
	}

	// Create a new block ready to be solved.
	merkles := blockchain.BuildMerkleTreeStore(blockTxnsRegular)
	merklesStake := blockchain.BuildMerkleTreeStore(blockTxnsStake)

	var msgBlock wire.MsgBlock
	msgBlock.Header = wire.BlockHeader{
		Version:     mempool.server.chainParams.CurrentBlockVersion,
		PrevBlock:   *prevHash,
		MerkleRoot:  *merkles[len(merkles)-1],
		StakeRoot:   *merklesStake[len(merklesStake)-1],
		VoteBits:    votebits,
		FinalState:  finalState,
		Voters:      uint16(voters),
		FreshStake:  uint8(freshStake),
		Revocations: uint8(revocations),
		PoolSize:    poolSize,
		Timestamp:   ts,
		SBits:       requiredStakeDifficulty,
		Bits:        requiredDifficulty,
		Height:      uint32(nextBlockHeight),
		// Size declared below
	}

	for _, tx := range blockTxnsRegular {
		if err := msgBlock.AddTransaction(tx.MsgTx()); err != nil {
			return nil, miningRuleError(ErrTransactionAppend, err.Error())
		}
	}

	for _, tx := range blockTxnsStake {
		if err := msgBlock.AddSTransaction(tx.MsgTx()); err != nil {
			return nil, miningRuleError(ErrTransactionAppend, err.Error())
		}
	}

	msgBlock.Header.Size = uint32(msgBlock.SerializeSize())

	// Finally, perform a full check on the created block against the chain
	// consensus rules to ensure it properly connects to the current best
	// chain with no issues.
	block := dcrutil.NewBlockDeepCopyCoinbase(&msgBlock)
	block.SetHeight(nextBlockHeight)

	if err := blockchain.CheckWorklessBlockSanity(block,
		mempool.server.timeSource,
		mempool.server.chainParams); err != nil {
		str := fmt.Sprintf("failed to do final check for block workless "+
			"sanity when making new block template: %v",
			err.Error())
		return nil, miningRuleError(ErrCheckConnectBlock, str)
	}

	if err := blockManager.CheckConnectBlock(block); err != nil {
		str := fmt.Sprintf("failed to do final check for check connect "+
			"block when making new block template: %v",
			err.Error())
		return nil, miningRuleError(ErrCheckConnectBlock, str)
	}

	minrLog.Debugf("Created new block template (%d transactions, %d "+
		"stake transactions, %d in fees, %d signature operations, "+
		"%d bytes, target difficulty %064x, stake difficulty %v)",
		len(msgBlock.Transactions), len(msgBlock.STransactions),
		totalFees, blockSigOps, blockSize,
		blockchain.CompactToBig(msgBlock.Header.Bits),
		dcrutil.Amount(msgBlock.Header.SBits).ToCoin())

	blockTemplate := &BlockTemplate{
		block:           &msgBlock,
		fees:            txFees,
		sigOpCounts:     txSigOpCounts,
		height:          nextBlockHeight,
		validPayAddress: payToAddress != nil,
	}

	return handleCreatedBlockTemplate(blockTemplate, mempool.server.blockManager)
}

// UpdateBlockTime updates the timestamp in the header of the passed block to
// the current time while taking into account the median time of the last
// several blocks to ensure the new time is after that time per the chain
// consensus rules.  Finally, it will update the target difficulty if needed
// based on the new time for the test networks since their target difficulty can
// change based upon time.
func UpdateBlockTime(msgBlock *wire.MsgBlock, bManager *blockManager) error {
	// The new timestamp is potentially adjusted to ensure it comes after
	// the median time of the last several blocks per the chain consensus
	// rules.
	newTimestamp, err := medianAdjustedTime(&bManager.chainState,
		bManager.server.timeSource)
	if err != nil {
		return miningRuleError(ErrGettingMedianTime, err.Error())
	}
	msgBlock.Header.Timestamp = newTimestamp

	// If running on a network that requires recalculating the difficulty,
	// do so now.
	if activeNetParams.ResetMinDifficulty {
		difficulty, err := bManager.CalcNextRequiredDifficulty(newTimestamp)
		if err != nil {
			return miningRuleError(ErrGettingDifficulty, err.Error())
		}
		msgBlock.Header.Bits = difficulty
	}

	return nil
}
