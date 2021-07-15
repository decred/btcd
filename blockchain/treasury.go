// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/decred/dcrd/blockchain/stake/v4"
	"github.com/decred/dcrd/blockchain/standalone/v2"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/database/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr"
	"github.com/decred/dcrd/dcrutil/v4"
	"github.com/decred/dcrd/txscript/v4"
	"github.com/decred/dcrd/wire"
)

const (
	// yesTreasury signifies the treasury agenda should be treated as
	// though it is active.  It is used to increase the readability of the
	// code.
	yesTreasury = true
)

// errDbTreasury signifies that a problem was encountered when fetching or
// writing the treasury balance for a given block.
type errDbTreasury string

// Error implements the error interface.
func (e errDbTreasury) Error() string {
	return string(e)
}

// Is implements the interface to work with the standard library's errors.Is.
//
// It returns true in the following cases:
// - The target is errDbTreasury
func (e errDbTreasury) Is(target error) bool {
	var err errDbTreasury
	return errors.As(target, &err)
}

// -----------------------------------------------------------------------------
// The treasury state index consists of an entry for every known block.  It
// contains the balance of the treasury as of that block as well as all of the
// amounts added to and spent from the treasury in the block.
//
// The serialized key format is:
//
//   <block hash>
//
//   Field           Type              Size
//   block hash      chainhash.Hash    chainhash.HashSize
//
// The serialized value format is:
//
//   <balance><num values><values info>
//
//   Field              Type                Size
//   balance            VLQ                 variable
//   num values         VLQ                 variable
//   values
//     flag             VLQ                 variable
//     value            VLQ                 variable
//
// The flag attribute of each value is a bit field, serialized as follows:
//
// 00000ttt
// |    |      mask
// |    \----  0x07: treasuryValueType
// \-------------- : Unused
//
// -----------------------------------------------------------------------------

// treasuryValueType specifies the possible types of values that modify the
// treasury balance.
type treasuryValueType byte

// The following constants define the known types of values that modify the
// treasury balance.
const (
	treasuryValueTBase  treasuryValueType = 0x01
	treasuryValueTAdd   treasuryValueType = 0x02
	treasuryValueFee    treasuryValueType = 0x03
	treasuryValueTSpend treasuryValueType = 0x04

	// tvFlagTypMask is the mask of the bits used to encode the type in the
	// flags field of a serialized treasuryValue.
	tvFlagTypMask byte = 0x07
)

// treasuryValue specifies the type and amount that of a value that changes the
// treasury balance.
//
// NOTE: for tspends and tspend fees, the amount is *negative*.
type treasuryValue struct {
	typ    treasuryValueType
	amount int64
}

// treasuryState records the treasury balance as of this block as well as the
// yet to mature balance-changing values (treasurybase, adds, spends and spend
// fees) included in the block itself.
//
// Note that treasurybase and tadds are positive and tspends and tspend fees
// are negative.  Additionally the values are written in the exact same order
// as they appear in the block.  This can be used to verify the correctness of
// the record if needed.
type treasuryState struct {
	// balance is the treasury balance as of this block.
	balance int64

	// values stores all balance-changing values included in this block (for use
	// when block is mature).
	values []treasuryValue
}

// serializeTreasuryState serializes the treasury state into a single byte slice
// according to the format described in detail above.
func serializeTreasuryState(ts treasuryState) ([]byte, error) {
	// Just a little sanity testing.
	if ts.balance < 0 {
		str := fmt.Sprintf("invalid treasury balance: %v", ts.balance)
		return nil, errDbTreasury(str)
	}

	// Calculate total number of bytes it will take to serialize the treasury
	// state according to the format described above.
	serializeSize := serializeSizeVLQ(uint64(ts.balance)) +
		serializeSizeVLQ(uint64(len(ts.values)))
	for _, value := range ts.values {
		// Prevent serialization of wrong negative value. Note that
		// zero is still allowed even in negative types.
		wantNegative := value.typ == treasuryValueFee ||
			value.typ == treasuryValueTSpend
		gotNegative := value.amount < 0
		if value.amount != 0 && wantNegative != gotNegative {
			str := fmt.Sprintf("incorrect negative value for type "+
				"%d: %d", value.typ, value.amount)
			return nil, errDbTreasury(str)
		}

		serializeSize += 1 // Flag which is currently a 1 byte long VLQ.
		serializeSize += serializeSizeVLQ(absInt64(value.amount))
	}

	// Serialize the treasury state according to the format described above.
	serialized := make([]byte, serializeSize)
	offset := putVLQ(serialized, uint64(ts.balance))
	offset += putVLQ(serialized[offset:], uint64(len(ts.values)))
	for _, value := range ts.values {
		// tspends and fees are negative but store them as positive to
		// reduce storage needs.
		amount := absInt64(value.amount)
		flag := uint64(byte(value.typ) & tvFlagTypMask)

		offset += putVLQ(serialized[offset:], flag)
		offset += putVLQ(serialized[offset:], amount)
	}
	return serialized, nil
}

// deserializeTreasuryState deserializes the passed serialized treasury state
// according to the format described above.
func deserializeTreasuryState(data []byte) (*treasuryState, error) {
	// Deserialize the balance.
	balance, offset := deserializeVLQ(data)
	if offset == 0 {
		return nil, errDeserialize("unexpected end of data while reading " +
			"treasury balance")
	}

	// Deserialize the number of values.
	var values []treasuryValue
	numValues, bytesRead := deserializeVLQ(data[offset:])
	if bytesRead == 0 {
		return nil, errDeserialize("unexpected end of data while reading " +
			"number of value entries")
	}
	offset += bytesRead

	// Deserialize individual values.
	if numValues > 0 {
		values = make([]treasuryValue, numValues)
		for i := uint64(0); i < numValues; i++ {
			flag, bytesRead := deserializeVLQ(data[offset:])
			offset += bytesRead
			if bytesRead == 0 {
				return nil, errDeserialize(fmt.Sprintf("unexpected end of "+
					"data while reading value flag #%d", i))
			}

			value, bytesRead := deserializeVLQ(data[offset:])
			offset += bytesRead
			if bytesRead == 0 {
				return nil, errDeserialize(fmt.Sprintf("unexpected end of "+
					"data while reading value amount #%d", i))
			}

			typ := treasuryValueType(byte(flag) & tvFlagTypMask)
			amount := int64(value)

			// tspends and fees are negative but stored as
			// positive, so negate the amount if needed.
			wantNegative := typ == treasuryValueFee ||
				typ == treasuryValueTSpend
			if wantNegative {
				amount = -amount
			}
			values[i] = treasuryValue{
				typ:    typ,
				amount: amount,
			}
		}
	}

	var ts treasuryState
	ts.balance = int64(balance)
	ts.values = values
	return &ts, nil
}

// dbPutTreasuryBalance inserts a treasury state record into the database.
func dbPutTreasuryBalance(dbTx database.Tx, hash chainhash.Hash, ts treasuryState) error {
	// Serialize the current treasury state.
	serializedData, err := serializeTreasuryState(ts)
	if err != nil {
		return err
	}

	// Store the current treasury state into the database.
	meta := dbTx.Metadata()
	bucket := meta.Bucket(treasuryBucketName)
	return bucket.Put(hash[:], serializedData)
}

// dbFetchTreasuryBalance uses an existing database transaction to fetch the
// treasury state.
func dbFetchTreasuryBalance(dbTx database.Tx, hash chainhash.Hash) (*treasuryState, error) {
	meta := dbTx.Metadata()
	bucket := meta.Bucket(treasuryBucketName)

	v := bucket.Get(hash[:])
	if v == nil {
		str := fmt.Sprintf("treasury db missing key: %v", hash)
		return nil, errDbTreasury(str)
	}

	return deserializeTreasuryState(v)
}

// dbFetchTreasurySingle wraps dbFetchTreasuryBalance in a view.
func (b *BlockChain) dbFetchTreasurySingle(hash chainhash.Hash) (*treasuryState, error) {
	var ts *treasuryState
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		ts, err = dbFetchTreasuryBalance(dbTx, hash)
		return err
	})
	return ts, err
}

// serializeTSpend serializes the TSpend data for use in the database.
// The format is as follows:
// Block []chainhash.Hash (blocks where TSpend was mined).
func serializeTSpend(blocks []chainhash.Hash) ([]byte, error) {
	serializedData := new(bytes.Buffer)
	err := binary.Write(serializedData, byteOrder, int64(len(blocks)))
	if err != nil {
		return nil, err
	}
	for _, v := range blocks {
		err := binary.Write(serializedData, byteOrder, v[:])
		if err != nil {
			return nil, err
		}
	}
	return serializedData.Bytes(), nil
}

// deserializeTSpend deserializes a binary blob into a []chainhash.Hash.
func deserializeTSpend(data []byte) ([]chainhash.Hash, error) {
	buf := bytes.NewReader(data)
	var count int64
	err := binary.Read(buf, byteOrder, &count)
	if err != nil {
		return nil, fmt.Errorf("failed to read count: %w", err)
	}
	hashes := make([]chainhash.Hash, count)
	for i := int64(0); i < count; i++ {
		err := binary.Read(buf, byteOrder, &hashes[i])
		if err != nil {
			return nil,
				fmt.Errorf("failed to read idx %v: %w", i, err)
		}
	}

	return hashes, nil
}

// dbPutTSpend inserts a number of treasury tspends into a single database
// record.  Note that this call is the low level write to the database. Use
// dbUpdateTSpend instead.
func dbPutTSpend(dbTx database.Tx, tx chainhash.Hash, blocks []chainhash.Hash) error {
	// Serialize the current treasury state.
	serializedData, err := serializeTSpend(blocks)
	if err != nil {
		return err
	}

	// Store the current treasury state into the database.
	meta := dbTx.Metadata()
	bucket := meta.Bucket(treasuryTSpendBucketName)
	return bucket.Put(tx[:], serializedData)
}

// errDbTSpend signifies that the provided hash was not found during a fetch.
type errDbTSpend string

// Error implements the error interface.
func (e errDbTSpend) Error() string {
	return string(e)
}

// dbFetchTSpend uses an existing database transaction to fetch the block
// hashes that contains the provided transaction.
func dbFetchTSpend(dbTx database.Tx, tx chainhash.Hash) ([]chainhash.Hash, error) {
	meta := dbTx.Metadata()
	bucket := meta.Bucket(treasuryTSpendBucketName)

	v := bucket.Get(tx[:])
	if v == nil {
		return nil, errDbTSpend(fmt.Sprintf("tspend db missing key: %v",
			tx))
	}

	return deserializeTSpend(v)
}

// dbUpdateTSpend performs a read/modify/write operation on the provided
// transaction hash. It reads the record and appends the block hash and then
// writes it back to the database. Note that the append is dumb and does not
// deduplicate. This is ok because in practice a TX cannot appear in the same
// block more than once.
func dbUpdateTSpend(dbTx database.Tx, tx, block chainhash.Hash) error {
	var derr errDbTSpend
	hashes, err := dbFetchTSpend(dbTx, tx)
	if err != nil && !errors.As(err, &derr) {
		return err
	}

	hashes = append(hashes, block)
	return dbPutTSpend(dbTx, tx, hashes)
}

// FetchTSpend returns the blocks a treasury spend tx was included in.
func (b *BlockChain) FetchTSpend(tspend chainhash.Hash) ([]chainhash.Hash, error) {
	var hashes []chainhash.Hash
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		hashes, err = dbFetchTSpend(dbTx, tspend)
		return err
	})
	return hashes, err
}

// calculateTreasuryBalance calculates the treasury balance as of the provided
// node.
//
// The treasury balance for a given block is calculated as the balance of its
// parent block plus all maturing TADDs and TreasuryBases minus all maturing
// TSPENDS.
//
// The "maturing" TADDs, TreasuryBases and TSPENDS are those that were in the
// CoinbaseMaturity ancestor block of the passed node.
func (b *BlockChain) calculateTreasuryBalance(dbTx database.Tx, node *blockNode) int64 {
	wantNode := node.RelativeAncestor(int64(b.chainParams.CoinbaseMaturity))
	if wantNode == nil {
		// Since the node does not exist we can safely assume the
		// balance is 0. This is true at the beginning of the chain
		// because before CoinbaseMaturity blocks there can be no
		// mature treasurybase or funds from which to create a TADD.
		return 0
	}

	// Current balance is in the parent node
	ts, err := dbFetchTreasuryBalance(dbTx, node.parent.hash)
	if err != nil {
		// Since the node.parent.hash does not exist in the treasury db
		// we can safely assume the balance is 0
		return 0
	}

	// Fetch values that need to be added to the treasury balance.
	wts, err := dbFetchTreasuryBalance(dbTx, wantNode.hash)
	if err != nil {
		// Since wantNode does not exist in the treasury db we can
		// safely assume the balance is 0
		return 0
	}

	// Add all TAdd values to the balance. Note that negative Values are
	// TSpend.
	var netValue int64
	for _, v := range wts.values {
		netValue += v.amount
	}

	return ts.balance + netValue
}

// dbPutTreasuryBalance inserts the current balance and the future treasury
// add/spend into the database.
func (b *BlockChain) dbPutTreasuryBalance(dbTx database.Tx, block *dcrutil.Block, node *blockNode) error {
	// Calculate balance as of this node
	balance := b.calculateTreasuryBalance(dbTx, node)
	msgBlock := block.MsgBlock()
	ts := treasuryState{
		balance: balance,
		values:  make([]treasuryValue, 0, len(msgBlock.Transactions)*2),
	}
	trsyLog.Tracef("dbPutTreasuryBalance: %v start balance %v",
		node.hash.String(), balance)
	for _, v := range msgBlock.STransactions {
		if stake.IsTAdd(v) {
			// This is a TAdd, pull amount out of TxOut[0].  Note
			// that TxOut[1], if it exists, contains the change
			// output. We have to ignore change.
			tv := treasuryValue{
				typ:    treasuryValueTAdd,
				amount: v.TxOut[0].Value,
			}
			ts.values = append(ts.values, tv)
			trsyLog.Tracef("  dbPutTreasuryBalance: balance TADD "+
				"%v", tv.amount)
		} else if stake.IsTreasuryBase(v) {
			tv := treasuryValue{
				typ:    treasuryValueTBase,
				amount: v.TxOut[0].Value,
			}
			ts.values = append(ts.values, tv)
			trsyLog.Tracef("  dbPutTreasuryBalance: balance "+
				"treasury base %v", tv.amount)
		} else if stake.IsTSpend(v) {
			// This is a TSpend, pull values out of block. Skip
			// first TxOut since it is an OP_RETURN.
			var totalOut int64
			for _, vv := range v.TxOut[1:] {
				tv := treasuryValue{
					typ:    treasuryValueTSpend,
					amount: -vv.Value,
				}
				trsyLog.Tracef("  dbPutTreasuryBalance: "+
					"balance TSPEND %v", tv.amount)
				ts.values = append(ts.values, tv)
				totalOut += vv.Value
			}

			// Fees are supposed to be stored as negative amounts
			// in a treasuryValue value, so calculate it backwards
			// from the usual way of `in - out`.
			fee := totalOut - v.TxIn[0].ValueIn
			tv := treasuryValue{
				typ:    treasuryValueFee,
				amount: fee,
			}
			trsyLog.Tracef("  dbPutTreasuryBalance: "+
				"balance fee %v", tv.amount)
			ts.values = append(ts.values, tv)
		}
	}

	hash := block.Hash()
	return dbPutTreasuryBalance(dbTx, *hash, ts)
}

// dbPutTSpend inserts the TSpends that are included in this block to the
// database.
func (b *BlockChain) dbPutTSpend(dbTx database.Tx, block *dcrutil.Block) error {
	hash := block.Hash()
	msgBlock := block.MsgBlock()
	trsyLog.Tracef("dbPutTSpend: processing block %v", hash)
	for _, v := range msgBlock.STransactions {
		if !stake.IsTSpend(v) {
			continue
		}

		// Store TSpend and the block it was included in.
		txHash := v.TxHash()
		trsyLog.Tracef("  dbPutTSpend: tspend %v", txHash)
		err := dbUpdateTSpend(dbTx, txHash, *hash)
		if err != nil {
			return err
		}
	}

	return nil
}

// TreasuryBalanceInfo models information about the treasury balance as of a
// given block.
type TreasuryBalanceInfo struct {
	// BlockHeight is the height of the requested block.
	BlockHeight int64

	// Balance is the balance of the treasury as of the requested block.
	Balance uint64

	// Updates specifies all additions to and spends from the treasury in
	// the requested block.
	Updates []int64
}

// TreasuryBalance returns treasury balance information as of the given block.
func (b *BlockChain) TreasuryBalance(hash *chainhash.Hash) (*TreasuryBalanceInfo, error) {
	node := b.index.LookupNode(hash)
	if node == nil || !b.index.CanValidate(node) {
		return nil, unknownBlockError(hash)
	}

	// Treasury agenda is never active for the genesis block.
	if node.parent == nil {
		str := fmt.Sprintf("treasury balance not available for block %s", hash)
		return nil, contextError(ErrNoTreasuryBalance, str)
	}

	// Ensure the treasury agenda is active as of the requested block.
	var isActive bool
	b.chainLock.Lock()
	isActive, err := b.isTreasuryAgendaActive(node.parent)
	b.chainLock.Unlock()
	if err != nil {
		return nil, err
	}
	if !isActive {
		str := fmt.Sprintf("treasury balance not available for block %s", hash)
		return nil, contextError(ErrNoTreasuryBalance, str)
	}

	// Load treasury balance information.
	var ts *treasuryState
	err = b.db.View(func(dbTx database.Tx) error {
		ts, err = dbFetchTreasuryBalance(dbTx, node.hash)
		return err
	})
	if err != nil {
		return nil, err
	}

	updates := make([]int64, len(ts.values))
	for i := range ts.values {
		updates[i] = ts.values[i].amount
	}

	return &TreasuryBalanceInfo{
		BlockHeight: node.height,
		Balance:     uint64(ts.balance),
		Updates:     updates,
	}, nil
}

// verifyTSpendSignature verifies that the provided signature and public key
// were the ones that signed the provided message transaction.
func verifyTSpendSignature(msgTx *wire.MsgTx, signature, pubKey []byte) error {
	// Calculate signature hash.
	sigHash, err := txscript.CalcSignatureHash(nil,
		txscript.SigHashAll, msgTx, 0, nil)
	if err != nil {
		return fmt.Errorf("CalcSignatureHash: %w", err)
	}

	// Lift Signature from bytes.
	sig, err := schnorr.ParseSignature(signature)
	if err != nil {
		return fmt.Errorf("ParseSignature: %w", err)
	}

	// Lift public PI key from bytes.
	pk, err := schnorr.ParsePubKey(pubKey)
	if err != nil {
		return fmt.Errorf("ParsePubKey: %w", err)
	}

	// Verify transaction was properly signed.
	if !sig.Verify(sigHash, pk) {
		return fmt.Errorf("Verify failed")
	}

	return nil
}

// VerifyTSpendSignature verifies that the provided signature and public key
// were the ones that signed the provided message transaction.
//
// Note: This function should only be called with a valid TSpend.
func VerifyTSpendSignature(msgTx *wire.MsgTx, signature, pubKey []byte) error {
	return verifyTSpendSignature(msgTx, signature, pubKey)
}

// sumPastTreasuryChanges sums up the amounts spent from and added to the
// treasury (respectively) found within the range (node-nbBlocks..node).  Note
// that this sum is _inclusive_ of the passed block and is performed in
// descending order.  Generally, the passed node will be a node immediately
// before a TVI block.
//
// It also returns the node immediately before the last checked node (that is,
// the node before node-nbBlocks).
func (b *BlockChain) sumPastTreasuryChanges(preTVINode *blockNode, nbBlocks uint64) (int64, int64, *blockNode, error) {
	node := preTVINode
	var spent, added int64
	var derr errDbTreasury
	for i := uint64(0); i < nbBlocks && node != nil; i++ {
		ts, err := b.dbFetchTreasurySingle(node.hash)
		if errors.As(err, &derr) {
			// Record doesn't exist. Means we reached the end of
			// when treasury records are available.
			node = nil
			continue
		} else if err != nil {
			return 0, 0, nil, err
		}

		// Range over values.
		for _, v := range ts.values {
			switch v.typ {
			case treasuryValueTSpend, treasuryValueFee:
				// treasuryValues record debits as negative
				// amounts, so invert it here.
				spent += -v.amount
			default:
				added += v.amount
			}
		}

		node = node.parent
	}

	return spent, added, node, nil
}

// maxTreasuryExpenditureDCP0006 returns the maximum amount of funds that can
// be spent from the treasury at the block after the provided node.
//
// This is code that was activated as part of the 'treasury' consensus upgrade
// as defined in DCP0006.
//
// See notes on maxTreasuryExpenditure().
func (b *BlockChain) maxTreasuryExpenditureDCP0006(preTVINode *blockNode) (int64, error) {
	// The expenditure policy check is roughly speaking:
	//
	//     "The sum of tspends inside an expenditure window cannot exceed
	//     the average of the tspends in the previous N windows in addition
	//     to an X% increase."
	//
	// So in order to calculate the maximum expenditure for the _next_
	// block (the block after `preTVINode`, which must be a TVI block) we
	// need to add all the tspends in the expenditure window that ends in
	// `preTVINode` and subtract that amount from the average of the
	// preceding (N) windows.
	//
	// Currently this function is pretty naive. It simply iterates through
	// prior blocks one at a time. This is very expensive and may need to
	// be rethought into a proper index.

	policyWindow := b.chainParams.TreasuryVoteInterval *
		b.chainParams.TreasuryVoteIntervalMultiplier *
		b.chainParams.TreasuryExpenditureWindow

	// Each policy window starts at a TVI block and ends at the block
	// immediately prior to another TVI (inclusive of preTVINode).
	//
	// First: sum up tspends inside the most recent policyWindow.
	spentRecentWindow, _, node, err := b.sumPastTreasuryChanges(preTVINode, policyWindow)
	if err != nil {
		return 0, err
	}

	// Next, sum up all tspends inside the N prior policy windows. If a
	// given policy window does not have _any_ tspends, it isn't counted
	// towards the average.
	var spentPriorWindows int64
	var nbNonEmptyWindows int64
	for i := uint64(0); i < b.chainParams.TreasuryExpenditurePolicy && node != nil; i++ {
		var spent int64
		spent, _, node, err = b.sumPastTreasuryChanges(node, policyWindow)
		if err != nil {
			return 0, err
		}

		if spent > 0 {
			spentPriorWindows += spent
			nbNonEmptyWindows++
		}
	}

	// Calculate the average spent in each window. If there were _zero_
	// prior windows with tspends, fall back to using the bootstrap
	// average.
	var avgSpentPriorWindows int64
	if nbNonEmptyWindows > 0 {
		avgSpentPriorWindows = spentPriorWindows / nbNonEmptyWindows
	} else {
		avgSpentPriorWindows = int64(b.chainParams.TreasuryExpenditureBootstrap)
	}

	// Treasury can spend up to 150% the average amount of the prior
	// windows ("expenditure allowance").
	avgPlusAllowance := avgSpentPriorWindows + avgSpentPriorWindows/2

	// The maximum expenditure allowed for the next block is the difference
	// between the maximum possible and what has already been spent in the most
	// recent policy window. This is capped at zero on the lower end to account
	// for cases where the policy _already_ spent more than the allowed.
	var allowedToSpend int64
	if avgPlusAllowance > spentRecentWindow {
		allowedToSpend = avgPlusAllowance - spentRecentWindow
	}

	trsyLog.Tracef("  maxTSpendExpenditure: recentWindow %d priorWindows %d "+
		"(%d non-empty) allowedToSpend %d", spentRecentWindow,
		spentPriorWindows, nbNonEmptyWindows, allowedToSpend)

	return allowedToSpend, nil
}

// maxTreasuryExpenditureDCP0007 returns the maximum amount of funds that can
// be spent from the treasury at the block after the provided node.
//
// This is code that was activated as part of the 'fixtreasuryexp' consensus
// upgrade as defined in DCP0007.
//
// See notes on maxTreasuryExpenditure().
func (b *BlockChain) maxTreasuryExpenditureDCP0007(preTVINode *blockNode) (int64, error) {
	// The expenditure policy check is roughly speaking:
	//
	//     "The sum of tspends inside an expenditure window cannot exceed
	//     the total amount of income received by the treasury in the same
	//     window in addition to an X% increase."
	//
	// Currently this function is pretty naive. It simply iterates through
	// prior blocks one at a time. This is very expensive and may need to
	// be rethought into a proper index.

	policyWindow := b.chainParams.TreasuryVoteInterval *
		b.chainParams.TreasuryVoteIntervalMultiplier *
		b.chainParams.TreasuryExpenditureWindow

	// Each policy window starts at a TVI block and ends at the block
	// immediately prior to another TVI (inclusive of preTVINode).
	//
	// First: sum up tspends, tadds and tbases inside the most recent
	// policyWindow.
	spentRecent, addedRecent, _, err := b.sumPastTreasuryChanges(preTVINode, policyWindow)
	if err != nil {
		return 0, err
	}

	// Treasury can spend up to 150% the amount received in the previous
	// window.
	addedPlusAllowance := addedRecent + addedRecent/2

	// The maximum expenditure allowed for the next block is the difference
	// between the maximum possible and what has already been spent in the most
	// recent policy window. This is capped at zero on the lower end to account
	// for cases where the policy _already_ spent more than the allowed.
	var allowedToSpend int64
	if addedPlusAllowance > spentRecent {
		allowedToSpend = addedPlusAllowance - spentRecent
	}

	trsyLog.Tracef("  maxTSpendExpenditureDCP0007: spent %d, "+
		"added %d, allowedToSpend %d", spentRecent,
		addedRecent, allowedToSpend)

	return allowedToSpend, nil
}

// maxTreasuryExpenditure returns the maximum amount of funds that can be spent
// from the treasury at the block after the provided node.  A set of TSPENDs
// added to a TVI block that is a child to the passed node may spend up to the
// returned amount.
//
// The passed node MUST correspond to a node immediately prior to a TVI block.
func (b *BlockChain) maxTreasuryExpenditure(preTVINode *blockNode) (int64, error) {
	isRevertPolicyActive, err := b.isRevertTreasuryPolicyActive(preTVINode)
	if err != nil {
		return 0, err
	}
	if isRevertPolicyActive {
		return b.maxTreasuryExpenditureDCP0007(preTVINode)
	}
	return b.maxTreasuryExpenditureDCP0006(preTVINode)
}

// MaxTreasuryExpenditure is the maximum amount of funds that can be spent from
// the treasury by a set of TSpends for a block that extends the given block
// hash. Function will return 0 if it is called on an invalid TVI.
func (b *BlockChain) MaxTreasuryExpenditure(preTVIBlock *chainhash.Hash) (int64, error) {
	preTVINode := b.index.LookupNode(preTVIBlock)
	if preTVINode == nil {
		return 0, fmt.Errorf("unknown block %s", preTVIBlock)
	}

	if !standalone.IsTreasuryVoteInterval(uint64(preTVINode.height+1),
		b.chainParams.TreasuryVoteInterval) {
		return 0, nil
	}

	return b.maxTreasuryExpenditure(preTVINode)
}

// checkTSpendsExpenditure verifies that the sum of TSpend expenditures is
// within the allowable range for the chain ending in the given node.  There is
// a hard requirement that the passed node is a block immediately prior to a
// TVI block (with the tspends assumed to be txs in a block that extends
// preTVINode).
//
// The expenditure check is performed against the balance at preTVINode.
//
// This function must be called with the block index read lock held.
func (b *BlockChain) checkTSpendsExpenditure(preTVINode *blockNode, totalTSpendAmount int64) error {
	trsyLog.Tracef("checkTSpendExpenditure: processing %d tspent at height %d",
		totalTSpendAmount, preTVINode.height+1)
	if totalTSpendAmount == 0 {
		// Nothing to do.
		return nil
	}
	if totalTSpendAmount < 0 {
		return fmt.Errorf("invalid precondition: totalTSpendAmount must "+
			"not be negative (got %d)", totalTSpendAmount)
	}

	// Ensure that we are not depleting treasury.
	var (
		treasuryBalance int64
		err             error
	)
	err = b.db.View(func(dbTx database.Tx) error {
		treasuryBalance = b.calculateTreasuryBalance(dbTx, preTVINode)
		return nil
	})
	if err != nil {
		return err
	}
	if treasuryBalance-totalTSpendAmount < 0 {
		return fmt.Errorf("treasury balance may not become negative: "+
			"balance %v spend %v", treasuryBalance, totalTSpendAmount)
	}
	trsyLog.Tracef("  checkTSpendExpenditure: balance %v spend %v",
		treasuryBalance, totalTSpendAmount)

	allowedToSpend, err := b.maxTreasuryExpenditure(preTVINode)
	if err != nil {
		return err
	}
	if totalTSpendAmount > allowedToSpend {
		return fmt.Errorf("treasury spend greater than allowed %v > %v",
			totalTSpendAmount, allowedToSpend)
	}

	return nil
}

// checkTSpendExists verifies that the provided TSpend has not been mined in a
// block on the chain of prevNode.
func (b *BlockChain) checkTSpendExists(prevNode *blockNode, tspend chainhash.Hash) error {
	trsyLog.Tracef(" checkTSpendExists: tspend %v", tspend)

	var derr errDbTSpend
	blocks, err := b.FetchTSpend(tspend)
	if errors.As(err, &derr) {
		// Record does not exist.
		return nil
	} else if err != nil {
		return err
	}

	// Do fork detection on all blocks.
	for _, v := range blocks {
		// Lookup blockNode.
		node := b.index.LookupNode(&v)
		if node == nil {
			// This should not happen.
			trsyLog.Errorf("  checkTSpendExists: block not found "+
				"%v tspend %v", v, tspend)
			continue
		}

		if prevNode.Ancestor(node.height) != node {
			trsyLog.Errorf("  checkTSpendExists: not ancestor "+
				"block %v tspend %v", v, tspend)
			continue
		}
		trsyLog.Errorf("  checkTSpendExists: is ancestor "+
			"block %v tspend %v", v, tspend)
		return fmt.Errorf("tspend has already been mined on this "+
			"chain %v", tspend)
	}

	return nil
}

// CheckTSpendExists verifies that the provided TSpend has not been mined in a
// block on the chain of the provided block hash.
func (b *BlockChain) CheckTSpendExists(prevHash, tspend chainhash.Hash) error {
	prevNode := b.index.LookupNode(&prevHash)
	if prevNode == nil {
		return nil
	}
	return b.checkTSpendExists(prevNode, tspend)
}

// getVotes returns yes and no votes for the provided hash.
func getVotes(votes []stake.TreasuryVoteTuple, hash *chainhash.Hash) (yes int, no int) {
	if votes == nil {
		return
	}

	for _, v := range votes {
		if !hash.IsEqual(&v.Hash) {
			continue
		}

		switch v.Vote {
		case stake.TreasuryVoteYes:
			yes++
		case stake.TreasuryVoteNo:
			no++
		default:
			// Can't happen.
			trsyLog.Criticalf("getVotes: invalid vote 0x%v", v.Vote)
		}
	}

	return
}

// tspendVotes is a structure that contains a treasury vote tally for a given
// window.
type tspendVotes struct {
	start uint32 // Start block
	end   uint32 // End block
	yes   int    // Yes vote tally
	no    int    // No vote tally
}

// tSpendCountVotes returns the vote tally for a given tspend up to the
// specified block. Note that this function errors if the block is outside the
// voting window for the given tspend.
func (b *BlockChain) tSpendCountVotes(prevNode *blockNode, tspend *dcrutil.Tx) (*tspendVotes, error) {
	trsyLog.Tracef("tSpendCountVotes: processing tspend %v", tspend.Hash())

	var (
		t   tspendVotes
		err error
	)

	expiry := tspend.MsgTx().Expiry
	t.start, t.end, err = standalone.CalcTSpendWindow(expiry,
		b.chainParams.TreasuryVoteInterval,
		b.chainParams.TreasuryVoteIntervalMultiplier)
	if err != nil {
		return nil, err
	}

	nextHeight := prevNode.height + 1
	trsyLog.Tracef("  tSpendCountVotes: nextHeight %v start %v expiry %v",
		nextHeight, t.start, t.end)

	// Ensure tspend is within the window.
	if !standalone.InsideTSpendWindow(nextHeight,
		expiry, b.chainParams.TreasuryVoteInterval,
		b.chainParams.TreasuryVoteIntervalMultiplier) {
		err = fmt.Errorf("tspend outside of window: nextHeight %v "+
			"start %v expiry %v", nextHeight, t.start, expiry)
		return nil, err
	}

	// Walk prevNode back to the start of the window and count votes.
	node := prevNode
	for {
		trsyLog.Tracef("  tSpendCountVotes height %v start %v",
			node.height, t.start)
		if node.height < int64(t.start) {
			break
		}

		trsyLog.Tracef("  tSpendCountVotes count votes: %v",
			node.hash)

		// Find SSGen and peel out votes.
		var xblock *dcrutil.Block
		xblock, err = b.fetchBlockByNode(node)
		if err != nil {
			// Should not happen.
			return nil, err
		}
		for _, v := range xblock.STransactions() {
			votes, err := stake.CheckSSGenVotes(v.MsgTx(),
				yesTreasury)
			if err != nil {
				// Not an SSGEN
				continue
			}

			// Find our vote bits.
			yes, no := getVotes(votes, tspend.Hash())
			t.yes += yes
			t.no += no
		}

		node = node.parent
		if node == nil {
			break
		}
	}

	return &t, nil
}

// TSpendCountVotes tallies the votes given for the specified tspend during its
// voting interval, up to the specified block. It returns the number of yes and
// no votes found between the passed block's height and the start of voting.
//
// Note that this function errors if the block _after_ the specified block is
// outside the tpsend voting window. In particular, calling this function for
// the TVI block that ends the voting interval for a given tspend fails, since
// the next block is outside the voting interval.
//
// This function is safe for concurrent access.
func (b *BlockChain) TSpendCountVotes(blockHash *chainhash.Hash, tspend *dcrutil.Tx) (yesVotes, noVotes int64, err error) {
	b.index.RLock()
	defer b.index.RUnlock()

	prevNode := b.index.lookupNode(blockHash)
	if prevNode == nil {
		return 0, 0, unknownBlockError(blockHash)
	}
	tv, err := b.tSpendCountVotes(prevNode, tspend)
	if err != nil {
		return 0, 0, err
	}

	return int64(tv.yes), int64(tv.no), nil
}

// checkTSpendHasVotes verifies that the provided TSpend has enough votes to be
// included in a block _after_ the provided block node. Such child node MUST be
// on a TVI.
func (b *BlockChain) checkTSpendHasVotes(prevNode *blockNode, tspend *dcrutil.Tx) error {
	t, err := b.tSpendCountVotes(prevNode, tspend)
	if err != nil {
		return err
	}

	// Passing criteria are 20% quorum and 60% yes.
	maxVotes := uint32(b.chainParams.TicketsPerBlock) * (t.end - t.start)
	quorum := uint64(maxVotes) * b.chainParams.TreasuryVoteQuorumMultiplier /
		b.chainParams.TreasuryVoteQuorumDivisor
	numVotesCast := uint64(t.yes + t.no)
	if numVotesCast < quorum {
		return fmt.Errorf("quorum not met: yes %v no %v  "+
			"quorum %v max %v", t.yes, t.no, quorum, maxVotes)
	}

	// Calculate max possible votes that are left in this window.
	curBlockHeight := uint32(prevNode.height + 1)
	remainingBlocks := t.end - curBlockHeight
	maxRemainingVotes := uint64(remainingBlocks *
		uint32(b.chainParams.TicketsPerBlock))

	// Treat maxRemainingVotes as possible no votes. This enables short
	// circuiting the overall TSpend vote but can only pass if the yes'
	// can't drop below the required threshold.
	requiredVotes := (numVotesCast + maxRemainingVotes) *
		b.chainParams.TreasuryVoteRequiredMultiplier /
		b.chainParams.TreasuryVoteRequiredDivisor
	if uint64(t.yes) < requiredVotes {
		return fmt.Errorf("not enough yes votes: yes %v no %v "+
			"quorum %v max %v required %v maxRemainingVotes %v",
			t.yes, t.no, quorum, maxVotes, requiredVotes,
			maxRemainingVotes)
	}

	trsyLog.Infof("TSpend %v passed with: yes %v no %v quorum %v "+
		"required %v", tspend.Hash(), t.yes, t.no, quorum,
		requiredVotes)

	return nil
}

// CheckTSpendHasVotes checks whether the given tspend has enough votes to be
// included in a block _after_ the specified prevHash block.
//
// Such child block MUST be on a TVI, otherwise the result of this function may
// not correspond to the behavior of the consensus rules.
//
// This function is safe for concurrent access.
func (b *BlockChain) CheckTSpendHasVotes(prevHash chainhash.Hash, tspend *dcrutil.Tx) error {
	prevNode := b.index.LookupNode(&prevHash)
	if prevNode == nil {
		return unknownBlockError(&prevHash)
	}
	return b.checkTSpendHasVotes(prevNode, tspend)
}
