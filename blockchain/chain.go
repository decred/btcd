// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2015-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/decred/dcrd/blockchain/stake/v3"
	"github.com/decred/dcrd/blockchain/standalone/v2"
	"github.com/decred/dcrd/blockchain/v3/indexers"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/database/v2"
	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/dcrd/gcs/v2"
	"github.com/decred/dcrd/gcs/v2/blockcf2"
	"github.com/decred/dcrd/txscript/v3"
	"github.com/decred/dcrd/wire"
)

const (
	// minMemoryNodes is the minimum number of consecutive nodes needed
	// in memory in order to perform all necessary validation.  It is used
	// to determine when it's safe to prune nodes from memory without
	// causing constant dynamic reloading.  This value should be larger than
	// that for minMemoryStakeNodes.
	minMemoryNodes = 2880

	// minMemoryStakeNodes is the maximum height to keep stake nodes
	// in memory for in their respective nodes.  Beyond this height,
	// they will need to be manually recalculated.  This value should
	// be at least the stake retarget interval.
	minMemoryStakeNodes = 288

	// mainChainBlockCacheSize is the number of main chain blocks to keep in
	// memory, by height from the tip of the main chain.  This value is set
	// based on the target block time for the main network such that there is
	// approximately one hour of blocks cached.  This could be made network
	// independent and calculated based on the parameters, but that would
	// result in larger caches than desired for other networks.
	mainChainBlockCacheSize = 12
)

// panicf is a convenience function that formats according to the given format
// specifier and arguments and then logs the result at the critical level and
// panics with it.
func panicf(format string, args ...interface{}) {
	str := fmt.Sprintf(format, args...)
	log.Critical(str)
	panic(str)
}

// BlockLocator is used to help locate a specific block.  The algorithm for
// building the block locator is to add the hashes in reverse order until
// the genesis block is reached.  In order to keep the list of locator hashes
// to a reasonable number of entries, first the most recent previous 12 block
// hashes are added, then the step is doubled each loop iteration to
// exponentially decrease the number of hashes as a function of the distance
// from the block being located.
//
// For example, assume a block chain with a side chain as depicted below:
// 	genesis -> 1 -> 2 -> ... -> 15 -> 16  -> 17  -> 18
// 	                              \-> 16a -> 17a
//
// The block locator for block 17a would be the hashes of blocks:
// [17a 16a 15 14 13 12 11 10 9 8 7 6 4 genesis]
type BlockLocator []*chainhash.Hash

// BestState houses information about the current best block and other info
// related to the state of the main chain as it exists from the point of view of
// the current best block.
//
// The BestSnapshot method can be used to obtain access to this information
// in a concurrent safe manner and the data will not be changed out from under
// the caller when chain state changes occur as the function name implies.
// However, the returned snapshot must be treated as immutable since it is
// shared by all callers.
type BestState struct {
	Hash               chainhash.Hash   // The hash of the block.
	PrevHash           chainhash.Hash   // The previous block hash.
	Height             int64            // The height of the block.
	Bits               uint32           // The difficulty bits of the block.
	NextPoolSize       uint32           // The ticket pool size.
	NextStakeDiff      int64            // The next stake difficulty.
	BlockSize          uint64           // The size of the block.
	NumTxns            uint64           // The number of txns in the block.
	TotalTxns          uint64           // The total number of txns in the chain.
	MedianTime         time.Time        // Median time as per CalcPastMedianTime.
	TotalSubsidy       int64            // The total subsidy for the chain.
	NextWinningTickets []chainhash.Hash // The eligible tickets to vote on the next block.
	MissedTickets      []chainhash.Hash // The missed tickets set to be revoked.
	NextFinalState     [6]byte          // The calculated state of the lottery for the next block.
}

// newBestState returns a new best stats instance for the given parameters.
func newBestState(node *blockNode, blockSize, numTxns, totalTxns uint64,
	medianTime time.Time, totalSubsidy int64, nextPoolSize uint32,
	nextStakeDiff int64, nextWinners, missed []chainhash.Hash,
	nextFinalState [6]byte) *BestState {
	prevHash := *zeroHash
	if node.parent != nil {
		prevHash = node.parent.hash
	}
	return &BestState{
		Hash:               node.hash,
		PrevHash:           prevHash,
		Height:             node.height,
		Bits:               node.bits,
		NextPoolSize:       nextPoolSize,
		NextStakeDiff:      nextStakeDiff,
		BlockSize:          blockSize,
		NumTxns:            numTxns,
		TotalTxns:          totalTxns,
		MedianTime:         medianTime,
		TotalSubsidy:       totalSubsidy,
		NextWinningTickets: nextWinners,
		MissedTickets:      missed,
		NextFinalState:     nextFinalState,
	}
}

// BlockChain provides functions for working with the Decred block chain.  It
// includes functionality such as rejecting duplicate blocks, ensuring blocks
// follow all rules, checkpoint handling, and best chain selection with
// reorganization.
type BlockChain struct {
	// The following fields are set when the instance is created and can't
	// be changed afterwards, so there is no need to protect them with a
	// separate mutex.
	checkpoints         []chaincfg.Checkpoint
	checkpointsByHeight map[int64]*chaincfg.Checkpoint
	deploymentVers      map[string]uint32
	db                  database.DB
	dbInfo              *databaseInfo
	chainParams         *chaincfg.Params
	timeSource          MedianTimeSource
	notifications       NotificationCallback
	sigCache            *txscript.SigCache
	indexSubscriber     *indexers.IndexSubscriber

	// subsidyCache is the cache that provides quick lookup of subsidy
	// values.
	subsidyCache *standalone.SubsidyCache

	// chainLock protects concurrent access to the vast majority of the
	// fields in this struct below this point.
	chainLock sync.RWMutex

	// This field is a configuration parameter that can be toggled at runtime.
	// It is protected by the chain lock.
	noVerify bool

	// These fields are related to the memory block index.  They both have
	// their own locks, however they are often also protected by the chain
	// lock to help prevent logic races when blocks are being processed.
	//
	// index houses the entire block index in memory.  The block index is
	// a tree-shaped structure.
	//
	// bestChain tracks the current active chain by making use of an
	// efficient chain view into the block index.
	index     *blockIndex
	bestChain *chainView

	// The block cache for main chain blocks to facilitate faster chain reorgs
	// and more efficient recent block serving.
	mainChainBlockCacheLock sync.RWMutex
	mainChainBlockCache     map[chainhash.Hash]*dcrutil.Block

	// These fields house a cached view that represents a block that votes
	// against its parent and therefore contains all changes as a result
	// of disconnecting all regular transactions in its parent.  It is only
	// lazily updated to the current tip when fetching a utxo view via the
	// FetchUtxoView function with the flag indicating the block votes against
	// the parent set.
	disapprovedViewLock sync.Mutex
	disapprovedView     *UtxoViewpoint

	// checkpointNode tracks the most recently known checkpoint.  It will be nil
	// when no checkpoints are known or are disabled.  It is protected by the
	// chain lock.
	checkpointNode *blockNode

	// The state is used as a fairly efficient way to cache information
	// about the current best chain state that is returned to callers when
	// requested.  It operates on the principle of MVCC such that any time a
	// new block becomes the best block, the state pointer is replaced with
	// a new struct and the old state is left untouched.  In this way,
	// multiple callers can be pointing to different best chain states.
	// This is acceptable for most callers because the state is only being
	// queried at a specific point in time.
	//
	// In addition, some of the fields are stored in the database so the
	// chain state can be quickly reconstructed on load.
	stateLock     sync.RWMutex
	stateSnapshot *BestState

	// The following caches are used to efficiently keep track of the
	// current deployment threshold state of each rule change deployment.
	//
	// This information is stored in the database so it can be quickly
	// reconstructed on load.
	//
	// deploymentCaches caches the current deployment threshold state for
	// blocks in each of the actively defined deployments.
	deploymentCaches map[uint32][]thresholdStateCache

	// pruner is the automatic pruner for block nodes and stake nodes,
	// so that the memory may be restored by the garbage collector if
	// it is unlikely to be referenced in the future.
	pruner *chainPruner

	// The following maps are various caches for the stake version/voting
	// system.  The goal of these is to reduce disk access to load blocks
	// from disk.  Measurements indicate that it is slightly more expensive
	// so setup the cache (<10%) vs doing a straight chain walk.  Every
	// other subsequent call is >10x faster.
	isVoterMajorityVersionCache   map[[stakeMajorityCacheKeySize]byte]bool
	isStakeMajorityVersionCache   map[[stakeMajorityCacheKeySize]byte]bool
	calcPriorStakeVersionCache    map[[chainhash.HashSize]byte]uint32
	calcVoterVersionIntervalCache map[[chainhash.HashSize]byte]uint32
	calcStakeVersionCache         map[[chainhash.HashSize]byte]uint32
}

const (
	// stakeMajorityCacheKeySize is comprised of the stake version and the
	// hash size.  The stake version is a little endian uint32, hence we
	// add 4 to the overall size.
	stakeMajorityCacheKeySize = 4 + chainhash.HashSize
)

// StakeVersions is a condensed form of a dcrutil.Block that is used to prevent
// using gigabytes of memory.
type StakeVersions struct {
	Hash         chainhash.Hash
	Height       int64
	BlockVersion int32
	StakeVersion uint32
	Votes        []stake.VoteVersionTuple
}

// GetStakeVersions returns a cooked array of StakeVersions.  We do this in
// order to not bloat memory by returning raw blocks.
func (b *BlockChain) GetStakeVersions(hash *chainhash.Hash, count int32) ([]StakeVersions, error) {
	// NOTE: The requirement for the node being fully validated here is strictly
	// stronger than what is actually required.  In reality, all that is needed
	// is for the block data for the node and all of its ancestors to be
	// available, but there is not currently any tracking to be able to
	// efficiently determine that state.
	startNode := b.index.LookupNode(hash)
	if startNode == nil || !b.index.NodeStatus(startNode).HasValidated() {
		return nil, fmt.Errorf("block %s is not known", hash)
	}

	// Nothing to do if no count requested.
	if count == 0 {
		return nil, nil
	}

	if count < 0 {
		return nil, fmt.Errorf("count must not be less than zero - "+
			"got %d", count)
	}

	// Limit the requested count to the max possible for the requested block.
	if count > int32(startNode.height+1) {
		count = int32(startNode.height + 1)
	}

	result := make([]StakeVersions, 0, count)
	prevNode := startNode
	for i := int32(0); prevNode != nil && i < count; i++ {
		sv := StakeVersions{
			Hash:         prevNode.hash,
			Height:       prevNode.height,
			BlockVersion: prevNode.blockVersion,
			StakeVersion: prevNode.stakeVersion,
			Votes:        prevNode.votes,
		}

		result = append(result, sv)

		prevNode = prevNode.parent
	}

	return result, nil
}

// VoteInfo represents information on agendas and their respective states for
// a consensus deployment.
type VoteInfo struct {
	Agendas      []chaincfg.ConsensusDeployment
	AgendaStatus []ThresholdStateTuple
}

// GetVoteInfo returns information on consensus deployment agendas
// and their respective states at the provided hash, for the provided
// deployment version.
func (b *BlockChain) GetVoteInfo(hash *chainhash.Hash, version uint32) (*VoteInfo, error) {
	deployments, ok := b.chainParams.Deployments[version]
	if !ok {
		return nil, VoteVersionError(version)
	}

	vi := VoteInfo{
		Agendas: make([]chaincfg.ConsensusDeployment,
			0, len(deployments)),
		AgendaStatus: make([]ThresholdStateTuple, 0, len(deployments)),
	}
	for _, deployment := range deployments {
		vi.Agendas = append(vi.Agendas, deployment)
		status, err := b.NextThresholdState(hash, version, deployment.Vote.Id)
		if err != nil {
			return nil, err
		}
		vi.AgendaStatus = append(vi.AgendaStatus, status)
	}

	return &vi, nil
}

// DisableVerify provides a mechanism to disable transaction script validation
// which you DO NOT want to do in production as it could allow double spends
// and other undesirable things.  It is provided only for debug purposes since
// script validation is extremely intensive and when debugging it is sometimes
// nice to quickly get the chain.
//
// This function is safe for concurrent access.
func (b *BlockChain) DisableVerify(disable bool) {
	b.chainLock.Lock()
	b.noVerify = disable
	b.chainLock.Unlock()
}

// HaveBlock returns whether or not the chain instance has the block represented
// by the passed hash.  This includes checking the various places a block can
// be like part of the main chain or on a side chain.
//
// This function is safe for concurrent access.
func (b *BlockChain) HaveBlock(hash *chainhash.Hash) bool {
	return b.index.HaveBlock(hash)
}

// ChainWork returns the total work up to and including the block of the
// provided block hash.
func (b *BlockChain) ChainWork(hash *chainhash.Hash) (*big.Int, error) {
	node := b.index.LookupNode(hash)
	if node == nil {
		return nil, fmt.Errorf("block %s is not known", hash)
	}

	return node.workSum, nil
}

// TipGeneration returns the entire generation of blocks stemming from the
// parent of the current tip.
//
// The function is safe for concurrent access.
func (b *BlockChain) TipGeneration() ([]chainhash.Hash, error) {
	b.chainLock.Lock()
	b.index.RLock()
	nodes := b.index.chainTips[b.bestChain.Tip().height]
	nodeHashes := make([]chainhash.Hash, len(nodes))
	for i, n := range nodes {
		nodeHashes[i] = n.hash
	}
	b.index.RUnlock()
	b.chainLock.Unlock()
	return nodeHashes, nil
}

// fetchMainChainBlockByNode returns the block from the main chain associated
// with the given node.  It first attempts to use cache and then falls back to
// loading it from the database.
//
// An error is returned if the block is either not found or not in the main
// chain.
//
// This function MUST be called with the chain lock held (for reads).
func (b *BlockChain) fetchMainChainBlockByNode(node *blockNode) (*dcrutil.Block, error) {
	// Ensure the block is in the main chain.
	if !b.bestChain.Contains(node) {
		str := fmt.Sprintf("block %s is not in the main chain", node.hash)
		return nil, errNotInMainChain(str)
	}

	b.mainChainBlockCacheLock.RLock()
	block, ok := b.mainChainBlockCache[node.hash]
	b.mainChainBlockCacheLock.RUnlock()
	if ok {
		return block, nil
	}

	// Load the block from the database.
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		block, err = dbFetchBlockByNode(dbTx, node)
		return err
	})
	return block, err
}

// fetchBlockByNode returns the block associated with the given node all known
// sources such as the internal caches and the database.  This function returns
// blocks regardless or whether or not they are part of the main chain.
//
// This function is safe for concurrent access.
func (b *BlockChain) fetchBlockByNode(node *blockNode) (*dcrutil.Block, error) {
	// Check main chain cache.
	b.mainChainBlockCacheLock.RLock()
	block, ok := b.mainChainBlockCache[node.hash]
	b.mainChainBlockCacheLock.RUnlock()
	if ok {
		return block, nil
	}

	// Load the block from the database.
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		block, err = dbFetchBlockByNode(dbTx, node)
		return err
	})
	return block, err
}

// pruneStakeNodes removes references to old stake nodes which should no
// longer be held in memory so as to keep the maximum memory usage down.
// It proceeds from the bestNode back to the determined minimum height node,
// finds all the relevant children, and then drops the stake nodes from
// them by assigning nil and allowing the memory to be recovered by GC.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *BlockChain) pruneStakeNodes() {
	// Find the height to prune to.
	pruneToNode := b.bestChain.Tip()
	for i := int64(0); i < minMemoryStakeNodes-1 && pruneToNode != nil; i++ {
		pruneToNode = pruneToNode.parent
	}

	// Nothing to do if there are not enough nodes.
	if pruneToNode == nil || pruneToNode.parent == nil {
		return
	}

	// Push the nodes to delete on a list. This will typically end up being
	// a single node since pruning is currently done just before each new
	// node is created.  However, that might be tuned later to only prune at
	// intervals, so the code needs to account for the possibility of
	// multiple nodes.
	var deleteNodes []*blockNode
	for node := pruneToNode.parent; node != nil; node = node.parent {
		deleteNodes = append(deleteNodes, node)
	}

	// Loop through each node to prune in reverse, unlink its children, remove
	// it from the dependency index, and remove it from the node index.
	for i := len(deleteNodes) - 1; i >= 0; i-- {
		node := deleteNodes[i]

		// Do not attempt to prune if the node should already have been pruned,
		// for example if you're adding an old side chain block.
		if node.height > b.bestChain.Tip().height-minMemoryNodes {
			node.stakeNode = nil
			node.newTickets = nil
			node.ticketsVoted = nil
			node.ticketsRevoked = nil
		}
	}
}

// isMajorityVersion determines if a previous number of blocks in the chain
// starting with startNode are at least the minimum passed version.
//
// This function MUST be called with the chain state lock held (for reads).
func (b *BlockChain) isMajorityVersion(minVer int32, startNode *blockNode, numRequired uint64) bool {
	numFound := uint64(0)
	iterNode := startNode
	for i := uint64(0); i < b.chainParams.BlockUpgradeNumToCheck &&
		numFound < numRequired && iterNode != nil; i++ {

		// This node has a version that is at least the minimum version.
		if iterNode.blockVersion >= minVer {
			numFound++
		}

		iterNode = iterNode.parent
	}

	return numFound >= numRequired
}

// pushMainChainBlockCache pushes a block onto the main chain block cache and
// removes any old blocks from the cache that might be present.
func (b *BlockChain) pushMainChainBlockCache(block *dcrutil.Block) {
	curHash := block.Hash()
	pruneHeight := block.Height() - mainChainBlockCacheSize
	b.mainChainBlockCacheLock.Lock()
	b.mainChainBlockCache[*curHash] = block
	for hash, bl := range b.mainChainBlockCache {
		if bl.Height() <= pruneHeight {
			delete(b.mainChainBlockCache, hash)
		}
	}
	b.mainChainBlockCacheLock.Unlock()
}

// PrevScripts returns a source of previous transaction scripts and their
// associated versions spent by the given block by using the spend journal.
func (b *BlockChain) PrevScripts(block *dcrutil.Block) (indexers.PrevScripter, error) {
	var stxos []spentTxOut
	err := b.db.View(func(dbTx database.Tx) error {
		var err error

		// Load all of the spent transaction output data from the database.
		stxos, err = dbFetchSpendJournalEntry(dbTx, block)
		return err
	})
	if err != nil {
		return nil, err
	}

	prevScripts := stxosToScriptSource(block, stxos, currentCompressionVersion)
	return prevScripts, nil
}

// Best returns the height and hash of the current best chain tip.
func (b *BlockChain) Best() (int64, *chainhash.Hash) {
	snapshot := b.BestSnapshot()
	return snapshot.Height, &snapshot.Hash
}

// connectBlock handles connecting the passed node/block to the end of the main
// (best) chain.
//
// This passed utxo view must have all referenced txos the block spends marked
// as spent and all of the new txos the block creates added to it.  In addition,
// the passed stxos slice must be populated with all of the information for the
// spent txos.  This approach is used because the connection validation that
// must happen prior to calling this function requires the same details, so
// it would be inefficient to repeat it.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *BlockChain) connectBlock(node *blockNode, block, parent *dcrutil.Block, view *UtxoViewpoint, stxos []spentTxOut, hdrCommitments *headerCommitmentData) error {
	// Make sure it's extending the end of the best chain.
	prevHash := block.MsgBlock().Header.PrevBlock
	tip := b.bestChain.Tip()
	if prevHash != tip.hash {
		panicf("block %v (height %v) connects to block %v instead of "+
			"extending the best chain (hash %v, height %v)", node.hash,
			node.height, prevHash, tip.hash, tip.height)
	}

	// Sanity check the correct number of stxos are provided.
	if len(stxos) != countSpentOutputs(block) {
		panicf("provided %v stxos for block %v (height %v) which spends %v "+
			"outputs", len(stxos), node.hash, node.height,
			countSpentOutputs(block))
	}

	// Write any modified block index entries to the database before
	// updating the best state.
	if err := b.flushBlockIndex(); err != nil {
		return err
	}

	// Get the stake node for this node, filling in any data that
	// may have yet to have been filled in.  In all cases this
	// should simply give a pointer to data already prepared, but
	// run this anyway to be safe.
	stakeNode, err := b.fetchStakeNode(node)
	if err != nil {
		return err
	}

	// Calculate the next stake difficulty.
	nextStakeDiff, err := b.calcNextRequiredStakeDifficulty(node)
	if err != nil {
		return err
	}

	// NOTE: When more header commitments are added, the inclusion proofs
	// will need to be generated and stored to the database here (when not
	// already stored).  There is no need to store them currently because
	// there is only a single commitment which means there are no sibling
	// hashes that typically form the inclusion proofs due to the fact a
	// single leaf merkle tree reduces to having the same root as the leaf
	// and therefore the proof only consists of checking the leaf hash
	// itself against the commitment root.

	// Generate a new best state snapshot that will be used to update the
	// database and later memory if all database updates are successful.
	b.stateLock.RLock()
	curTotalTxns := b.stateSnapshot.TotalTxns
	curTotalSubsidy := b.stateSnapshot.TotalSubsidy
	b.stateLock.RUnlock()
	subsidy := calculateAddedSubsidy(block, parent)
	numTxns := uint64(len(block.Transactions()) + len(block.STransactions()))
	blockSize := uint64(block.MsgBlock().Header.Size)
	state := newBestState(node, blockSize, numTxns, curTotalTxns+numTxns,
		node.CalcPastMedianTime(), curTotalSubsidy+subsidy,
		uint32(node.stakeNode.PoolSize()), nextStakeDiff,
		node.stakeNode.Winners(), node.stakeNode.MissedTickets(),
		node.stakeNode.FinalState())

	// Atomically insert info into the database.
	err = b.db.Update(func(dbTx database.Tx) error {
		// Update best block state.
		err := dbPutBestState(dbTx, state, node.workSum)
		if err != nil {
			return err
		}

		// Update the utxo set using the state of the utxo view.  This
		// entails removing all of the utxos spent and adding the new
		// ones created by the block.
		err = dbPutUtxoView(dbTx, view)
		if err != nil {
			return err
		}

		// Update the transaction spend journal by adding a record for
		// the block that contains all txos spent by it.
		err = dbPutSpendJournalEntry(dbTx, block.Hash(), stxos)
		if err != nil {
			return err
		}

		// Insert the block into the stake database.
		err = stake.WriteConnectedBestNode(dbTx, stakeNode, node.hash)
		if err != nil {
			return err
		}

		// Insert the GCS filter for the block into the database.
		err = dbPutGCSFilter(dbTx, block.Hash(), hdrCommitments.filter)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return err
	}

	// Prune fully spent entries and mark all entries in the view unmodified
	// now that the modifications have been committed to the database.
	view.commit()

	// This node is now the end of the best chain.
	b.bestChain.SetTip(node)

	// Update the state for the best block.  Notice how this replaces the
	// entire struct instead of updating the existing one.  This effectively
	// allows the old version to act as a snapshot which callers can use
	// freely without needing to hold a lock for the duration.  See the
	// comments on the state variable for more details.
	b.stateLock.Lock()
	b.stateSnapshot = state
	b.stateLock.Unlock()

	// Assemble the current block and the parent into a slice.
	blockAndParent := []*dcrutil.Block{block, parent}

	// Notify the caller that the block was connected to the main chain.
	// The caller would typically want to react with actions such as
	// updating wallets.
	b.chainLock.Unlock()
	b.sendNotification(NTBlockConnected, blockAndParent)
	b.chainLock.Lock()

	// Send stake notifications about the new block.
	if node.height >= b.chainParams.StakeEnabledHeight {
		nextStakeDiff, err := b.calcNextRequiredStakeDifficulty(node)
		if err != nil {
			return err
		}

		// Notify of spent and missed tickets
		b.sendNotification(NTSpentAndMissedTickets,
			&TicketNotificationsData{
				Hash:            node.hash,
				Height:          node.height,
				StakeDifficulty: nextStakeDiff,
				TicketsSpent:    node.stakeNode.SpentByBlock(),
				TicketsMissed:   node.stakeNode.MissedByBlock(),
				TicketsNew:      []chainhash.Hash{},
			})
		// Notify of new tickets
		b.sendNotification(NTNewTickets,
			&TicketNotificationsData{
				Hash:            node.hash,
				Height:          node.height,
				StakeDifficulty: nextStakeDiff,
				TicketsSpent:    []chainhash.Hash{},
				TicketsMissed:   []chainhash.Hash{},
				TicketsNew:      node.stakeNode.NewTickets(),
			})
	}

	// Optimization: Before checkpoints, immediately dump the parent's stake
	// node because we no longer need it.
	var latestCheckpointHeight int64
	if len(b.checkpoints) > 0 {
		latestCheckpointHeight = b.checkpoints[len(b.checkpoints)-1].Height
	}
	if node.height < latestCheckpointHeight {
		parent := b.bestChain.Tip().parent
		parent.stakeNode = nil
		parent.newTickets = nil
		parent.ticketsVoted = nil
		parent.ticketsRevoked = nil
	}

	b.pushMainChainBlockCache(block)

	return nil
}

// dropMainChainBlockCache drops a block from the main chain block cache.
func (b *BlockChain) dropMainChainBlockCache(block *dcrutil.Block) {
	curHash := block.Hash()
	b.mainChainBlockCacheLock.Lock()
	delete(b.mainChainBlockCache, *curHash)
	b.mainChainBlockCacheLock.Unlock()
}

// disconnectBlock handles disconnecting the passed node/block from the end of
// the main (best) chain.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *BlockChain) disconnectBlock(node *blockNode, block, parent *dcrutil.Block, view *UtxoViewpoint) error {
	// Make sure the node being disconnected is the end of the best chain.
	tip := b.bestChain.Tip()
	if node.hash != tip.hash {
		panicf("block %v (height %v) is not the end of the best chain "+
			"(hash %v, height %v)", node.hash, node.height, tip.hash,
			tip.height)
	}

	// Write any modified block index entries to the database before
	// updating the best state.
	if err := b.flushBlockIndex(); err != nil {
		return err
	}

	// Prepare the information required to update the stake database
	// contents.
	childStakeNode, err := b.fetchStakeNode(node)
	if err != nil {
		return err
	}
	parentStakeNode, err := b.fetchStakeNode(node.parent)
	if err != nil {
		return err
	}

	// Generate a new best state snapshot that will be used to update the
	// database and later memory if all database updates are successful.
	b.stateLock.RLock()
	curTotalTxns := b.stateSnapshot.TotalTxns
	curTotalSubsidy := b.stateSnapshot.TotalSubsidy
	b.stateLock.RUnlock()
	parentBlockSize := uint64(parent.MsgBlock().Header.Size)
	numParentTxns := uint64(len(parent.Transactions()) + len(parent.STransactions()))
	numBlockTxns := uint64(len(block.Transactions()) + len(block.STransactions()))
	newTotalTxns := curTotalTxns - numBlockTxns
	subsidy := calculateAddedSubsidy(block, parent)
	newTotalSubsidy := curTotalSubsidy - subsidy
	prevNode := node.parent
	state := newBestState(prevNode, parentBlockSize, numParentTxns,
		newTotalTxns, prevNode.CalcPastMedianTime(), newTotalSubsidy,
		uint32(prevNode.stakeNode.PoolSize()), node.sbits,
		prevNode.stakeNode.Winners(), prevNode.stakeNode.MissedTickets(),
		prevNode.stakeNode.FinalState())

	err = b.db.Update(func(dbTx database.Tx) error {
		// Update best block state.
		err := dbPutBestState(dbTx, state, node.workSum)
		if err != nil {
			return err
		}

		// Update the utxo set using the state of the utxo view.  This
		// entails restoring all of the utxos spent and removing the new
		// ones created by the block.
		err = dbPutUtxoView(dbTx, view)
		if err != nil {
			return err
		}

		// Update the transaction spend journal by removing the record
		// that contains all txos spent by the block.
		err = dbRemoveSpendJournalEntry(dbTx, block.Hash())
		if err != nil {
			return err
		}

		err = stake.WriteDisconnectedBestNode(dbTx, parentStakeNode,
			node.parent.hash, childStakeNode.UndoData())
		if err != nil {
			return err
		}

		// NOTE: The GCS filter is intentionally not removed on disconnect to
		// ensure that lightweight clients still have access to them if they
		// happen to be on a side chain after coming back online after a reorg.

		return nil
	})
	if err != nil {
		return err
	}

	// Prune fully spent entries and mark all entries in the view unmodified
	// now that the modifications have been committed to the database.
	view.commit()

	// This node's parent is now the end of the best chain.
	b.bestChain.SetTip(node.parent)

	// Update the state for the best block.  Notice how this replaces the
	// entire struct instead of updating the existing one.  This effectively
	// allows the old version to act as a snapshot which callers can use
	// freely without needing to hold a lock for the duration.  See the
	// comments on the state variable for more details.
	b.stateLock.Lock()
	b.stateSnapshot = state
	b.stateLock.Unlock()

	// Assemble the current block and the parent into a slice.
	blockAndParent := []*dcrutil.Block{block, parent}

	// Notify the caller that the block was disconnected from the main
	// chain.  The caller would typically want to react with actions such as
	// updating wallets.
	b.chainLock.Unlock()
	b.sendNotification(NTBlockDisconnected, blockAndParent)
	b.chainLock.Lock()

	b.dropMainChainBlockCache(block)

	return nil
}

// countSpentRegularOutputs returns the number of utxos the regular transactions
// in the passed block spend.
func countSpentRegularOutputs(block *dcrutil.Block) int {
	// Skip the coinbase since it has no inputs.
	var numSpent int
	for _, tx := range block.MsgBlock().Transactions[1:] {
		numSpent += len(tx.TxIn)
	}
	return numSpent
}

// countSpentStakeOutputs returns the number of utxos the stake transactions in
// the passed block spend.
func countSpentStakeOutputs(block *dcrutil.Block) int {
	var numSpent int
	for _, stx := range block.MsgBlock().STransactions {
		// Exclude the vote stakebase since it has no input.
		if stake.IsSSGen(stx) {
			numSpent++
			continue
		}
		numSpent += len(stx.TxIn)
	}
	return numSpent
}

// countSpentOutputs returns the number of utxos the passed block spends.
func countSpentOutputs(block *dcrutil.Block) int {
	return countSpentRegularOutputs(block) + countSpentStakeOutputs(block)
}

// loadOrCreateFilter attempts to load and return the version 2 GCS filter for
// the given block from the database and falls back to creating a new one in
// the case one has not previously been stored.
func (b *BlockChain) loadOrCreateFilter(block *dcrutil.Block, view *UtxoViewpoint) (*gcs.FilterV2, error) {
	// Attempt to load and return the version 2 block filter for the given block
	// from the database.
	var filter *gcs.FilterV2
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		filter, err = dbFetchGCSFilter(dbTx, block.Hash())
		return err
	})
	if err != nil {
		return nil, err
	}
	if filter != nil {
		return filter, nil
	}

	// At this point the version 2 block filter has not been stored in the
	// database for the block, so create and return one.
	filter, err = blockcf2.Regular(block.MsgBlock(), view)
	if err != nil {
		return nil, ruleError(ErrMissingTxOut, err.Error())
	}

	return filter, nil
}

// reorganizeChainInternal attempts to reorganize the block chain to the
// provided tip without attempting to undo failed reorgs.
//
// Since reorganizing to a new chain tip might involve validating blocks that
// have not previously been validated, or attempting to reorganize to a branch
// that is already known to be invalid, it possible for the reorganize to fail.
// When that is the case, this function will return the error without attempting
// to undo what has already been reorganized to that point.  That means the best
// chain tip will be set to some intermediate block along the reorg path and
// will not actually be the best chain.  This is acceptable because this
// function is only intended to be called from the reorganizeChain function
// which handles reorg failures by reorganizing back to the known good best
// chain tip.
//
// A reorg entails disconnecting all blocks from the current best chain tip back
// to the fork point between it and the provided target tip in reverse order
// (think popping them off the end of the chain) and then connecting the blocks
// on the new branch in forwards order (think pushing them onto the end of the
// chain).
//
// This function may modify the validation state of nodes in the block index
// without flushing in the case the chain is not able to reorganize due to a
// block failing to connect.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *BlockChain) reorganizeChainInternal(targetTip *blockNode) error {
	// Find the fork point adding each block to a slice of blocks to attach
	// below once the current best chain has been disconnected.  They are added
	// to the slice from back to front so that so they are attached in the
	// appropriate order when iterating the slice later.
	//
	// In the case a known invalid block is detected while constructing this
	// list, mark all of its descendants as having an invalid ancestor and
	// prevent the reorganize.
	fork := b.bestChain.FindFork(targetTip)
	attachNodes := make([]*blockNode, targetTip.height-fork.height)
	for n := targetTip; n != nil && n != fork; n = n.parent {
		if b.index.NodeStatus(n).KnownInvalid() {
			for _, dn := range attachNodes[n.height-fork.height:] {
				b.index.SetStatusFlags(dn, statusInvalidAncestor)
			}

			str := fmt.Sprintf("block %s is known to be invalid or a "+
				"descendant of an invalid block", n.hash)
			return ruleError(ErrKnownInvalidBlock, str)
		}

		attachNodes[n.height-fork.height-1] = n
	}

	// Disconnect all of the blocks back to the point of the fork.  This entails
	// loading the blocks and their associated spent txos from the database and
	// using that information to unspend all of the spent txos and remove the
	// utxos created by the blocks.  In addition, if a block votes against its
	// parent, the regular transactions are reconnected.
	tip := b.bestChain.Tip()
	view := NewUtxoViewpoint()
	view.SetBestHash(&tip.hash)
	var nextBlockToDetach *dcrutil.Block
	for tip != nil && tip != fork {
		// Grab the block to detach based on the node.  Use the fact that the
		// blocks are being detached in reverse order, so the parent of the
		// current block being detached is the next one being detached.
		n := tip
		block := nextBlockToDetach
		if block == nil {
			var err error
			block, err = b.fetchMainChainBlockByNode(n)
			if err != nil {
				return err
			}
		}
		if n.hash != *block.Hash() {
			panicf("detach block node hash %v (height %v) does not match "+
				"previous parent block hash %v", &n.hash, n.height,
				block.Hash())
		}

		// Grab the parent of the current block and also save a reference to it
		// as the next block to detach so it doesn't need to be loaded again on
		// the next iteration.
		parent, err := b.fetchMainChainBlockByNode(n.parent)
		if err != nil {
			return err
		}
		nextBlockToDetach = parent

		// Load all of the spent txos for the block from the spend journal.
		var stxos []spentTxOut
		err = b.db.View(func(dbTx database.Tx) error {
			stxos, err = dbFetchSpendJournalEntry(dbTx, block)
			return err
		})
		if err != nil {
			return err
		}

		// Update the view to unspend all of the spent txos and remove the utxos
		// created by the block.  Also, if the block votes against its parent,
		// reconnect all of the regular transactions.
		err = view.disconnectBlock(b.db, block, parent, stxos)
		if err != nil {
			return err
		}

		// Update the database and chain state.
		err = b.disconnectBlock(n, block, parent, view)
		if err != nil {
			return err
		}

		tip = n.parent
	}

	// Load the fork block if there are blocks to attach and it's not already
	// loaded which will be the case if no nodes were detached.  The fork block
	// is used as the parent to the first node to be attached below.
	forkBlock := nextBlockToDetach
	if len(attachNodes) > 0 && forkBlock == nil {
		var err error
		forkBlock, err = b.fetchMainChainBlockByNode(tip)
		if err != nil {
			return err
		}
	}

	// Attempt to connect each block that needs to be attached to the main
	// chain.  This entails performing several checks to verify each block can
	// be connected without violating any consensus rules and updating the
	// relevant information related to the current chain state.
	var prevBlockAttached *dcrutil.Block
	for i, n := range attachNodes {
		// Grab the block to attach based on the node.  Use the fact that the
		// parent of the block is either the fork point for the first node being
		// attached or the previous one that was attached for subsequent blocks
		// to optimize.
		block, err := b.fetchBlockByNode(n)
		if err != nil {
			return err
		}
		parent := forkBlock
		if i > 0 {
			parent = prevBlockAttached
		}
		if n.parent.hash != *parent.Hash() {
			panicf("attach block node hash %v (height %v) parent hash %v does "+
				"not match previous parent block hash %v", &n.hash, n.height,
				&n.parent.hash, parent.Hash())
		}

		// Store the loaded block as parent of next iteration.
		prevBlockAttached = block

		// Skip validation if the block is already known to be valid.  However,
		// the utxo view still needs to be updated and the stxos and header
		// commitment data are still needed.
		stxos := make([]spentTxOut, 0, countSpentOutputs(block))
		var hdrCommitments headerCommitmentData
		if b.index.NodeStatus(n).HasValidated() {
			// Update the view to mark all utxos referenced by the block as
			// spent and add all transactions being created by this block to it.
			// In the case the block votes against the parent, also disconnect
			// all of the regular transactions in the parent block.  Finally,
			// provide an stxo slice so the spent txout details are generated.
			err := view.connectBlock(b.db, block, parent, &stxos)
			if err != nil {
				return err
			}

			filter, err := b.loadOrCreateFilter(block, view)
			if err != nil {
				return err
			}
			hdrCommitments.filter = filter
		} else {
			// In the case the block is determined to be invalid due to a rule
			// violation, mark it as invalid and mark all of its descendants as
			// having an invalid ancestor.
			err = b.checkConnectBlock(n, block, parent, view, &stxos,
				&hdrCommitments)
			if err != nil {
				var rerr RuleError
				if errors.As(err, &rerr) {
					b.index.SetStatusFlags(n, statusValidateFailed)
					for _, dn := range attachNodes[i+1:] {
						b.index.SetStatusFlags(dn, statusInvalidAncestor)
					}
				}
				return err
			}
			b.index.SetStatusFlags(n, statusValidated)
		}

		// Update the database and chain state.
		err = b.connectBlock(n, block, parent, view, stxos, &hdrCommitments)
		if err != nil {
			return err
		}

		tip = n
	}

	return nil
}

// reorganizeChain attempts to reorganize the block chain to the provided tip.
// The tip must have already been determined to be on another branch by the
// caller.  Upon return, the chain will be fully reorganized to the provided tip
// or an appropriate error will be returned and the chain will remain at the
// same tip it was prior to calling this function.
//
// Reorganizing the chain entails disconnecting all blocks from the current best
// chain tip back to the fork point between it and the provided target tip in
// reverse order (think popping them off the end of the chain) and then
// connecting the blocks on the new branch in forwards order (think pushing them
// onto the end of the chain).
//
// This function may modify the validation state of nodes in the block index
// without flushing in the case the chain is not able to reorganize due to a
// block failing to connect.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *BlockChain) reorganizeChain(targetTip *blockNode) error {
	// Nothing to do if there is no target tip or the target tip is already the
	// current tip.
	if targetTip == nil {
		return nil
	}
	origTip := b.bestChain.Tip()
	if origTip == targetTip {
		return nil
	}

	// Send a notification announcing the start of the chain reorganization.
	b.chainLock.Unlock()
	b.sendNotification(NTChainReorgStarted, nil)
	b.chainLock.Lock()

	defer func() {
		// Send a notification announcing the end of the chain reorganization.
		b.chainLock.Unlock()
		b.sendNotification(NTChainReorgDone, nil)
		b.chainLock.Lock()
	}()

	// Attempt to reorganize to the chain to the new tip.  In the case it fails,
	// reorganize back to the original tip.  There is no way to recover if the
	// chain fails to reorganize back to the original tip since something is
	// very wrong if a chain tip that was already known to be valid fails to
	// reconnect.
	//
	// NOTE: The failure handling makes an assumption that a block in the path
	// between the fork point and original tip are not somehow invalidated in
	// between the point a reorged chain fails to connect and the reorg back to
	// the original tip.  That is a safe assumption with the current code due to
	// all modifications which mark blocks invalid being performed under the
	// chain lock, however, this will need to be reworked if that assumption is
	// violated.
	fork := b.bestChain.FindFork(targetTip)
	reorgErr := b.reorganizeChainInternal(targetTip)
	if reorgErr != nil {
		if err := b.reorganizeChainInternal(origTip); err != nil {
			panicf("failed to reorganize back to known good chain tip %s "+
				"(height %d): %v -- probable database corruption", origTip.hash,
				origTip.height, err)
		}

		return reorgErr
	}

	// Send a notification that a blockchain reorganization took place.
	reorgData := &ReorganizationNtfnsData{origTip.hash, origTip.height,
		targetTip.hash, targetTip.height}
	b.chainLock.Unlock()
	b.sendNotification(NTReorganization, reorgData)
	b.chainLock.Lock()

	// Log the point where the chain forked and old and new best chain tips.
	if fork != nil {
		log.Infof("REORGANIZE: Chain forks at %v (height %v)", fork.hash,
			fork.height)
	}
	log.Infof("REORGANIZE: Old best chain tip was %v (height %v)",
		&origTip.hash, origTip.height)
	log.Infof("REORGANIZE: New best chain tip is %v (height %v)",
		targetTip.hash, targetTip.height)

	return nil
}

// forceHeadReorganization forces a reorganization of the block chain to the
// block hash requested, so long as it matches up with the current organization
// of the best chain.
//
// This function may modify the validation state of nodes in the block index
// without flushing.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *BlockChain) forceHeadReorganization(formerBest chainhash.Hash, newBest chainhash.Hash) error {
	if formerBest.IsEqual(&newBest) {
		return fmt.Errorf("can't reorganize to the same block")
	}
	formerBestNode := b.bestChain.Tip()

	// We can't reorganize the chain unless our head block matches up with
	// b.bestChain.
	if !formerBestNode.hash.IsEqual(&formerBest) {
		return ruleError(ErrForceReorgWrongChain, "tried to force reorg "+
			"on wrong chain")
	}

	// Child to reorganize to is missing.
	newBestNode := b.index.LookupNode(&newBest)
	if newBestNode == nil || newBestNode.parent != formerBestNode.parent {
		return ruleError(ErrForceReorgMissingChild, "missing child of "+
			"common parent for forced reorg")
	}

	// Don't allow a reorganize to a known invalid chain.
	newBestNodeStatus := b.index.NodeStatus(newBestNode)
	if newBestNodeStatus.KnownInvalid() {
		return ruleError(ErrKnownInvalidBlock, "block is known to be invalid")
	}

	// Reorganize the chain and flush any potential unsaved changes to the
	// block index to the database.  It is safe to ignore any flushing
	// errors here as the only time the index will be modified is if the
	// block failed to connect.
	err := b.reorganizeChain(newBestNode)
	b.flushBlockIndexWarnOnly()
	return err
}

// ForceHeadReorganization forces a reorganization of the block chain to the
// block hash requested, so long as it matches up with the current organization
// of the best chain.
//
// This function is safe for concurrent access.
func (b *BlockChain) ForceHeadReorganization(formerBest chainhash.Hash, newBest chainhash.Hash) error {
	b.chainLock.Lock()
	err := b.forceHeadReorganization(formerBest, newBest)
	b.chainLock.Unlock()
	return err
}

// flushBlockIndex populates any ticket data that has been pruned from modified
// block nodes, writes those nodes to the database and clears the set of
// modified nodes if it succeeds.
func (b *BlockChain) flushBlockIndex() error {
	b.index.RLock()
	for node := range b.index.modified {
		if err := b.maybeFetchTicketInfo(node); err != nil {
			b.index.RUnlock()
			return err
		}
	}
	b.index.RUnlock()

	return b.index.flush()
}

// flushBlockIndexWarnOnly attempts to flush and modified block index nodes to
// the database and will log a warning if it fails.
//
// NOTE: This MUST only be used in the specific circumstances where failure to
// flush only results in a worst case scenario of requiring one or more blocks
// to be validated again.  All other cases must directly call the function on
// the block index and check the error return accordingly.
func (b *BlockChain) flushBlockIndexWarnOnly() {
	if err := b.flushBlockIndex(); err != nil {
		log.Warnf("Unable to flush block index changes to db: %v", err)
	}
}

// connectBestChain handles connecting the passed block to the chain while
// respecting proper chain selection according to the chain with the most
// proof of work.  In the typical case, the new block simply extends the main
// chain.  However, it may also be extending (or creating) a side chain (fork)
// which may or may not end up becoming the main chain depending on which fork
// cumulatively has the most proof of work.  It returns the resulting fork
// length, that is to say the number of blocks to the fork point from the main
// chain, which will be zero if the block ends up on the main chain (either
// due to extending the main chain or causing a reorganization to become the
// main chain).
//
// The flags modify the behavior of this function as follows:
//  - BFFastAdd: Avoids several expensive transaction validation operations.
//    This is useful when using checkpoints.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *BlockChain) connectBestChain(node *blockNode, block, parent *dcrutil.Block, flags BehaviorFlags) (int64, error) {
	fastAdd := flags&BFFastAdd == BFFastAdd

	// Ensure the passed parent is actually the parent of the block.
	if *parent.Hash() != node.parent.hash {
		panicf("parent block %v (height %v) does not match expected parent %v "+
			"(height %v)", parent.Hash(), parent.MsgBlock().Header.Height,
			node.parent.hash, node.height-1)
	}

	// We are extending the main (best) chain with a new block.  This is the
	// most common case.
	parentHash := &block.MsgBlock().Header.PrevBlock
	tip := b.bestChain.Tip()
	if *parentHash == tip.hash {
		// Skip expensive checks if the block has already been fully
		// validated.
		hasValidated := b.index.NodeStatus(node).HasValidated()
		fastAdd = fastAdd || hasValidated

		// Perform several checks to verify the block can be connected
		// to the main chain without violating any rules and without
		// actually connecting the block.
		//
		// Also, set the applicable status result in the block index,
		// and flush the status changes to the database.  It is safe to
		// ignore any errors when flushing here as the changes will be
		// flushed when a valid block is connected, and the worst case
		// scenario if a block is invalid is it would need to be
		// revalidated after a restart.
		view := NewUtxoViewpoint()
		view.SetBestHash(parentHash)
		var stxos []spentTxOut
		var hdrCommitments headerCommitmentData
		if !fastAdd {
			err := b.checkConnectBlock(node, block, parent, view, &stxos,
				&hdrCommitments)
			if err != nil {
				var rerr RuleError
				if errors.As(err, &rerr) {
					b.index.SetStatusFlags(node, statusValidateFailed)
					b.flushBlockIndexWarnOnly()
				}
				return 0, err
			}
		}
		if !hasValidated {
			b.index.SetStatusFlags(node, statusValidated)
			b.flushBlockIndexWarnOnly()
		}

		// In the fast add case the code to check the block connection
		// was skipped, so the utxo view needs to load the referenced
		// utxos, spend them, and add the new utxos being created by
		// this block.  Also, in the case the block votes against
		// the parent, its regular transaction tree must be
		// disconnected.
		if fastAdd {
			err := view.connectBlock(b.db, block, parent, &stxos)
			if err != nil {
				return 0, err
			}

			// Create a version 2 block filter for the block and store it into
			// the header commitment data.
			filter, err := blockcf2.Regular(block.MsgBlock(), view)
			if err != nil {
				return 0, ruleError(ErrMissingTxOut, err.Error())
			}
			hdrCommitments.filter = filter
		}

		// Connect the block to the main chain.
		err := b.connectBlock(node, block, parent, view, stxos, &hdrCommitments)
		if err != nil {
			return 0, err
		}

		validateStr := "validating"
		if !voteBitsApproveParent(node.voteBits) {
			validateStr = "invalidating"
		}

		log.Debugf("Block %v (height %v) connected to the main chain, "+
			"%v the previous block", node.hash, node.height,
			validateStr)

		// The fork length is zero since the block is now the tip of the
		// best chain.
		return 0, nil
	}
	if fastAdd {
		log.Warnf("fastAdd set in the side chain case? %v\n",
			block.Hash())
	}

	// We're extending (or creating) a side chain, but the cumulative
	// work for this new side chain is not enough to make it the new chain.
	if node.workSum.Cmp(tip.workSum) <= 0 {
		// Log information about how the block is forking the chain.
		fork := b.bestChain.FindFork(node)
		if fork.hash == *parentHash {
			log.Infof("FORK: Block %v (height %v) forks the chain at height "+
				"%d/block %v, but does not cause a reorganize",
				node.hash, node.height, fork.height, fork.hash)
		} else {
			log.Infof("EXTEND FORK: Block %v (height %v) extends a side chain "+
				"which forks the chain at height %d/block %v", node.hash,
				node.height, fork.height, fork.hash)
		}

		forkLen := node.height - fork.height
		return forkLen, nil
	}

	// We're extending (or creating) a side chain and the cumulative work
	// for this new side chain is more than the old best chain, so this side
	// chain needs to become the main chain.  In order to accomplish that,
	// find the common ancestor of both sides of the fork, disconnect the
	// blocks that form the (now) old fork from the main chain, and attach
	// the blocks that form the new chain to the main chain starting at the
	// common ancestor (the point where the chain forked).
	//
	// Reorganize the chain and flush any potential unsaved changes to the
	// block index to the database.  It is safe to ignore any flushing
	// errors here as the only time the index will be modified is if the
	// block failed to connect.
	log.Infof("REORGANIZE: Block %v is causing a reorganize.", node.hash)
	err := b.reorganizeChain(node)
	b.flushBlockIndexWarnOnly()
	if err != nil {
		return 0, err
	}

	// The fork length is zero since the block is now the tip of the best
	// chain.
	return 0, nil
}

// isCurrent returns whether or not the chain believes it is current.  Several
// factors are used to guess, but the key factors that allow the chain to
// believe it is current are:
//  - Total amount of cumulative work is more than the minimum known work
//    specified by the parameters for the network
//  - Latest block has a timestamp newer than 24 hours ago
//
// This function MUST be called with the chain state lock held (for reads).
func (b *BlockChain) isCurrent() bool {
	// Not current if the latest best block has a cumulative work less than the
	// minimum known work specified by the network parameters.
	tip := b.bestChain.Tip()
	minKnownWork := b.chainParams.MinKnownChainWork
	if minKnownWork != nil && tip.workSum.Cmp(minKnownWork) < 0 {
		return false
	}

	// Not current if the latest best block has a timestamp before 24 hours
	// ago.
	//
	// The chain appears to be current if none of the checks reported
	// otherwise.
	minus24Hours := b.timeSource.AdjustedTime().Add(-24 * time.Hour).Unix()
	return tip.timestamp >= minus24Hours
}

// IsCurrent returns whether or not the chain believes it is current.  Several
// factors are used to guess, but the key factors that allow the chain to
// believe it is current are:
//  - Total amount of cumulative work is more than the minimum known work
//    specified by the parameters for the network
//  - Latest block has a timestamp newer than 24 hours ago
//
// This function is safe for concurrent access.
func (b *BlockChain) IsCurrent() bool {
	b.chainLock.RLock()
	defer b.chainLock.RUnlock()

	return b.isCurrent()
}

// BestSnapshot returns information about the current best chain block and
// related state as of the current point in time.  The returned instance must be
// treated as immutable since it is shared by all callers.
//
// This function is safe for concurrent access.
func (b *BlockChain) BestSnapshot() *BestState {
	b.stateLock.RLock()
	snapshot := b.stateSnapshot
	b.stateLock.RUnlock()
	return snapshot
}

// MaximumBlockSize returns the maximum permitted block size for the block
// AFTER the given node.
//
// This function MUST be called with the chain state lock held (for reads).
func (b *BlockChain) maxBlockSize(prevNode *blockNode) (int64, error) {
	// Determine the correct deployment version for the block size consensus
	// vote or treat it as active when voting is not enabled for the current
	// network.
	const deploymentID = chaincfg.VoteIDMaxBlockSize
	deploymentVer, ok := b.deploymentVers[deploymentID]
	if !ok {
		return int64(b.chainParams.MaximumBlockSizes[0]), nil
	}

	// Return the larger block size if the stake vote for the max block size
	// increase agenda is active.
	//
	// NOTE: The choice field of the return threshold state is not examined
	// here because there is only one possible choice that can be active
	// for the agenda, which is yes, so there is no need to check it.
	maxSize := int64(b.chainParams.MaximumBlockSizes[0])
	state, err := b.deploymentState(prevNode, deploymentVer, deploymentID)
	if err != nil {
		return maxSize, err
	}
	if state.State == ThresholdActive {
		return int64(b.chainParams.MaximumBlockSizes[1]), nil
	}

	// The max block size is not changed in any other cases.
	return maxSize, nil
}

// MaxBlockSize returns the maximum permitted block size for the block AFTER
// the end of the current best chain.
//
// This function is safe for concurrent access.
func (b *BlockChain) MaxBlockSize() (int64, error) {
	b.chainLock.Lock()
	maxSize, err := b.maxBlockSize(b.bestChain.Tip())
	b.chainLock.Unlock()
	return maxSize, err
}

// HeaderByHash returns the block header identified by the given hash or an
// error if it doesn't exist.  Note that this will return headers from both the
// main chain and any side chains.
//
// This function is safe for concurrent access.
func (b *BlockChain) HeaderByHash(hash *chainhash.Hash) (wire.BlockHeader, error) {
	node := b.index.LookupNode(hash)
	if node == nil {
		return wire.BlockHeader{}, fmt.Errorf("block %s is not known", hash)
	}

	return node.Header(), nil
}

// HeaderByHeight returns the block header at the given height in the main
// chain.
//
// This function is safe for concurrent access.
func (b *BlockChain) HeaderByHeight(height int64) (wire.BlockHeader, error) {
	node := b.bestChain.NodeByHeight(height)
	if node == nil {
		str := fmt.Sprintf("no block at height %d exists", height)
		return wire.BlockHeader{}, errNotInMainChain(str)
	}

	return node.Header(), nil
}

// BlockByHash searches the internal chain block stores and the database in an
// attempt to find the requested block and returns it.  This function returns
// blocks regardless of whether or not they are part of the main chain.
//
// This function is safe for concurrent access.
func (b *BlockChain) BlockByHash(hash *chainhash.Hash) (*dcrutil.Block, error) {
	node := b.index.LookupNode(hash)
	if node == nil || !b.index.NodeStatus(node).HaveData() {
		return nil, fmt.Errorf("block %s is not known", hash)
	}

	// Return the block from either cache or the database.
	return b.fetchBlockByNode(node)
}

// BlockByHeight returns the block at the given height in the main chain.
//
// This function is safe for concurrent access.
func (b *BlockChain) BlockByHeight(height int64) (*dcrutil.Block, error) {
	// Lookup the block height in the best chain.
	node := b.bestChain.NodeByHeight(height)
	if node == nil {
		str := fmt.Sprintf("no block at height %d exists", height)
		return nil, errNotInMainChain(str)
	}

	// Return the block from either cache or the database.  Note that this is
	// not using fetchMainChainBlockByNode since the main chain check has
	// already been done.
	return b.fetchBlockByNode(node)
}

// MainChainHasBlock returns whether or not the block with the given hash is in
// the main chain.
//
// This function is safe for concurrent access.
func (b *BlockChain) MainChainHasBlock(hash *chainhash.Hash) bool {
	node := b.index.LookupNode(hash)
	return node != nil && b.bestChain.Contains(node)
}

// BlockHeightByHash returns the height of the block with the given hash in the
// main chain.
//
// This function is safe for concurrent access.
func (b *BlockChain) BlockHeightByHash(hash *chainhash.Hash) (int64, error) {
	node := b.index.LookupNode(hash)
	if node == nil || !b.bestChain.Contains(node) {
		str := fmt.Sprintf("block %s is not in the main chain", hash)
		return 0, errNotInMainChain(str)
	}

	return node.height, nil
}

// BlockHashByHeight returns the hash of the block at the given height in the
// main chain.
//
// This function is safe for concurrent access.
func (b *BlockChain) BlockHashByHeight(height int64) (*chainhash.Hash, error) {
	node := b.bestChain.NodeByHeight(height)
	if node == nil {
		str := fmt.Sprintf("no block at height %d exists", height)
		return nil, errNotInMainChain(str)
	}

	return &node.hash, nil
}

// HeightRange returns a range of block hashes for the given start and end
// heights.  It is inclusive of the start height and exclusive of the end
// height.  In other words, it is the half open range [startHeight, endHeight).
//
// The end height will be limited to the current main chain height.
//
// This function is safe for concurrent access.
func (b *BlockChain) HeightRange(startHeight, endHeight int64) ([]chainhash.Hash, error) {
	// Ensure requested heights are sane.
	if startHeight < 0 {
		return nil, fmt.Errorf("start height of fetch range must not "+
			"be less than zero - got %d", startHeight)
	}
	if endHeight < startHeight {
		return nil, fmt.Errorf("end height of fetch range must not "+
			"be less than the start height - got start %d, end %d",
			startHeight, endHeight)
	}

	// There is nothing to do when the start and end heights are the same,
	// so return now to avoid extra work.
	if startHeight == endHeight {
		return nil, nil
	}

	// When the requested start height is after the most recent best chain
	// height, there is nothing to do.
	latestHeight := b.bestChain.Tip().height
	if startHeight > latestHeight {
		return nil, nil
	}

	// Limit the ending height to the latest height of the chain.
	if endHeight > latestHeight+1 {
		endHeight = latestHeight + 1
	}

	// Fetch as many as are available within the specified range.
	hashes := make([]chainhash.Hash, endHeight-startHeight)
	iterNode := b.bestChain.NodeByHeight(endHeight - 1)
	for i := startHeight; i < endHeight; i++ {
		// Since the desired result is from the starting node to the
		// ending node in forward order, but they are iterated in
		// reverse, add them in reverse order.
		hashes[endHeight-i-1] = iterNode.hash
		iterNode = iterNode.parent
	}
	return hashes, nil
}

// locateInventory returns the node of the block after the first known block in
// the locator along with the number of subsequent nodes needed to either reach
// the provided stop hash or the provided max number of entries.
//
// In addition, there are two special cases:
//
// - When no locators are provided, the stop hash is treated as a request for
//   that block, so it will either return the node associated with the stop hash
//   if it is known, or nil if it is unknown
// - When locators are provided, but none of them are known, nodes starting
//   after the genesis block will be returned
//
// This is primarily a helper function for the locateBlocks and locateHeaders
// functions.
//
// This function MUST be called with the chain state lock held (for reads).
func (b *BlockChain) locateInventory(locator BlockLocator, hashStop *chainhash.Hash, maxEntries uint32) (*blockNode, uint32) {
	// There are no block locators so a specific block is being requested
	// as identified by the stop hash.
	stopNode := b.index.LookupNode(hashStop)
	if len(locator) == 0 {
		if stopNode == nil {
			// No blocks with the stop hash were found so there is
			// nothing to do.
			return nil, 0
		}
		return stopNode, 1
	}

	// Find the most recent locator block hash in the main chain.  In the
	// case none of the hashes in the locator are in the main chain, fall
	// back to the genesis block.
	startNode := b.bestChain.Genesis()
	for _, hash := range locator {
		node := b.index.LookupNode(hash)
		if node != nil && b.bestChain.Contains(node) {
			startNode = node
			break
		}
	}

	// Start at the block after the most recently known block.  When there
	// is no next block it means the most recently known block is the tip of
	// the best chain, so there is nothing more to do.
	startNode = b.bestChain.Next(startNode)
	if startNode == nil {
		return nil, 0
	}

	// Calculate how many entries are needed.
	total := uint32((b.bestChain.Tip().height - startNode.height) + 1)
	if stopNode != nil && b.bestChain.Contains(stopNode) &&
		stopNode.height >= startNode.height {

		total = uint32((stopNode.height - startNode.height) + 1)
	}
	if total > maxEntries {
		total = maxEntries
	}

	return startNode, total
}

// locateBlocks returns the hashes of the blocks after the first known block in
// the locator until the provided stop hash is reached, or up to the provided
// max number of block hashes.
//
// See the comment on the exported function for more details on special cases.
//
// This function MUST be called with the chain state lock held (for reads).
func (b *BlockChain) locateBlocks(locator BlockLocator, hashStop *chainhash.Hash, maxHashes uint32) []chainhash.Hash {
	// Find the node after the first known block in the locator and the
	// total number of nodes after it needed while respecting the stop hash
	// and max entries.
	node, total := b.locateInventory(locator, hashStop, maxHashes)
	if total == 0 {
		return nil
	}

	// Populate and return the found hashes.
	hashes := make([]chainhash.Hash, 0, total)
	for i := uint32(0); i < total; i++ {
		hashes = append(hashes, node.hash)
		node = b.bestChain.Next(node)
	}
	return hashes
}

// LocateBlocks returns the hashes of the blocks after the first known block in
// the locator until the provided stop hash is reached, or up to the provided
// max number of block hashes.
//
// In addition, there are two special cases:
//
// - When no locators are provided, the stop hash is treated as a request for
//   that block, so it will either return the stop hash itself if it is known,
//   or nil if it is unknown
// - When locators are provided, but none of them are known, hashes starting
//   after the genesis block will be returned
//
// This function is safe for concurrent access.
func (b *BlockChain) LocateBlocks(locator BlockLocator, hashStop *chainhash.Hash, maxHashes uint32) []chainhash.Hash {
	b.chainLock.RLock()
	hashes := b.locateBlocks(locator, hashStop, maxHashes)
	b.chainLock.RUnlock()
	return hashes
}

// locateHeaders returns the headers of the blocks after the first known block
// in the locator until the provided stop hash is reached, or up to the provided
// max number of block headers.
//
// See the comment on the exported function for more details on special cases.
//
// This function MUST be called with the chain state lock held (for reads).
func (b *BlockChain) locateHeaders(locator BlockLocator, hashStop *chainhash.Hash, maxHeaders uint32) []wire.BlockHeader {
	// Find the node after the first known block in the locator and the
	// total number of nodes after it needed while respecting the stop hash
	// and max entries.
	node, total := b.locateInventory(locator, hashStop, maxHeaders)
	if total == 0 {
		return nil
	}

	// Populate and return the found headers.
	headers := make([]wire.BlockHeader, 0, total)
	for i := uint32(0); i < total; i++ {
		headers = append(headers, node.Header())
		node = b.bestChain.Next(node)
	}
	return headers
}

// LocateHeaders returns the headers of the blocks after the first known block
// in the locator until the provided stop hash is reached, or up to a max of
// wire.MaxBlockHeadersPerMsg headers.
//
// In addition, there are two special cases:
//
// - When no locators are provided, the stop hash is treated as a request for
//   that header, so it will either return the header for the stop hash itself
//   if it is known, or nil if it is unknown
// - When locators are provided, but none of them are known, headers starting
//   after the genesis block will be returned
//
// This function is safe for concurrent access.
func (b *BlockChain) LocateHeaders(locator BlockLocator, hashStop *chainhash.Hash) []wire.BlockHeader {
	b.chainLock.RLock()
	headers := b.locateHeaders(locator, hashStop, wire.MaxBlockHeadersPerMsg)
	b.chainLock.RUnlock()
	return headers
}

// BlockLocatorFromHash returns a block locator for the passed block hash.
// See BlockLocator for details on the algorithm used to create a block locator.
//
// In addition to the general algorithm referenced above, this function will
// return the block locator for the latest known tip of the main (best) chain if
// the passed hash is not currently known.
//
// This function is safe for concurrent access.
func (b *BlockChain) BlockLocatorFromHash(hash *chainhash.Hash) BlockLocator {
	b.chainLock.RLock()
	node := b.index.LookupNode(hash)
	locator := b.bestChain.BlockLocator(node)
	b.chainLock.RUnlock()
	return locator
}

// LatestBlockLocator returns a block locator for the latest known tip of the
// main (best) chain.
//
// This function is safe for concurrent access.
func (b *BlockChain) LatestBlockLocator() (BlockLocator, error) {
	b.chainLock.RLock()
	locator := b.bestChain.BlockLocator(nil)
	b.chainLock.RUnlock()
	return locator, nil
}

// extractDeploymentIDVersions returns a map of all deployment IDs within the
// provided params to the deployment version for which they are defined.  An
// error is returned if a duplicate ID is encountered.
func extractDeploymentIDVersions(params *chaincfg.Params) (map[string]uint32, error) {
	// Generate a deployment ID to version map from the provided params.
	deploymentVers := make(map[string]uint32)
	for version, deployments := range params.Deployments {
		for _, deployment := range deployments {
			id := deployment.Vote.Id
			if _, ok := deploymentVers[id]; ok {
				return nil, DuplicateDeploymentError(id)
			}
			deploymentVers[id] = version
		}
	}

	return deploymentVers, nil
}

// Config is a descriptor which specifies the blockchain instance configuration.
type Config struct {
	// DB defines the database which houses the blocks and will be used to
	// store all metadata created by this package such as the utxo set.
	//
	// This field is required.
	DB database.DB

	// ChainParams identifies which chain parameters the chain is associated
	// with.
	//
	// This field is required.
	ChainParams *chaincfg.Params

	// Checkpoints specifies caller-defined checkpoints that are typically the
	// default checkpoints in ChainParams or additional checkpoints added to
	// them.  Checkpoints must be sorted by height.
	//
	// This field can be nil if the caller does not wish to specify any
	// checkpoints.
	Checkpoints []chaincfg.Checkpoint

	// TimeSource defines the median time source to use for things such as
	// block processing and determining whether or not the chain is current.
	//
	// The caller is expected to keep a reference to the time source as well
	// and add time samples from other peers on the network so the local
	// time is adjusted to be in agreement with other peers.
	TimeSource MedianTimeSource

	// Notifications defines a callback to which notifications will be sent
	// when various events take place.  See the documentation for
	// Notification and NotificationType for details on the types and
	// contents of notifications.
	//
	// This field can be nil if the caller is not interested in receiving
	// notifications.
	Notifications NotificationCallback

	// SigCache defines a signature cache to use when validating signatures.
	// This is typically most useful when individual transactions are
	// already being validated prior to their inclusion in a block such as
	// what is usually done via a transaction memory pool.
	//
	// This field can be nil if the caller is not interested in using a
	// signature cache.
	SigCache *txscript.SigCache

	// SubsidyCache defines a subsidy cache to use when calculating and
	// validating block and vote subsidies.
	//
	// This field can be nil if the caller is not interested in using a
	// subsidy cache.
	SubsidyCache *standalone.SubsidyCache

	// IndexubSubscriber defines a subscriber for relaying updates
	// concerning connected and disconnected blocks to subscribed index clients.
	IndexSubscriber *indexers.IndexSubscriber
}

// New returns a BlockChain instance using the provided configuration details.
func New(ctx context.Context, config *Config) (*BlockChain, error) {
	// Enforce required config fields.
	if config.DB == nil {
		return nil, AssertError("blockchain.New database is nil")
	}
	if config.ChainParams == nil {
		return nil, AssertError("blockchain.New chain parameters nil")
	}

	// Generate a checkpoint by height map from the provided checkpoints.
	params := config.ChainParams
	var checkpointsByHeight map[int64]*chaincfg.Checkpoint
	var prevCheckpointHeight int64
	if len(config.Checkpoints) > 0 {
		checkpointsByHeight = make(map[int64]*chaincfg.Checkpoint)
		for i := range config.Checkpoints {
			checkpoint := &config.Checkpoints[i]
			if checkpoint.Height <= prevCheckpointHeight {
				return nil, AssertError("blockchain.New checkpoints are not " +
					"sorted by height")
			}

			checkpointsByHeight[checkpoint.Height] = checkpoint
			prevCheckpointHeight = checkpoint.Height
		}
	}

	// Generate a deployment ID to version map from the provided params.
	deploymentVers, err := extractDeploymentIDVersions(params)
	if err != nil {
		return nil, err
	}

	// Either use the subsidy cache provided by the caller or create a new
	// one when one was not provided.
	subsidyCache := config.SubsidyCache
	if subsidyCache == nil {
		subsidyCache = standalone.NewSubsidyCache(params)
	}

	b := BlockChain{
		checkpoints:                   config.Checkpoints,
		checkpointsByHeight:           checkpointsByHeight,
		deploymentVers:                deploymentVers,
		db:                            config.DB,
		chainParams:                   params,
		timeSource:                    config.TimeSource,
		notifications:                 config.Notifications,
		sigCache:                      config.SigCache,
		indexSubscriber:               config.IndexSubscriber,
		subsidyCache:                  subsidyCache,
		index:                         newBlockIndex(config.DB),
		bestChain:                     newChainView(nil),
		mainChainBlockCache:           make(map[chainhash.Hash]*dcrutil.Block),
		deploymentCaches:              newThresholdCaches(params),
		isVoterMajorityVersionCache:   make(map[[stakeMajorityCacheKeySize]byte]bool),
		isStakeMajorityVersionCache:   make(map[[stakeMajorityCacheKeySize]byte]bool),
		calcPriorStakeVersionCache:    make(map[[chainhash.HashSize]byte]uint32),
		calcVoterVersionIntervalCache: make(map[[chainhash.HashSize]byte]uint32),
		calcStakeVersionCache:         make(map[[chainhash.HashSize]byte]uint32),
	}
	b.pruner = newChainPruner(&b)

	// Initialize the chain state from the passed database.  When the db
	// does not yet contain any chain state, both it and the chain state
	// will be initialized to contain only the genesis block.
	if err := b.initChainState(ctx); err != nil {
		return nil, err
	}

	// The version 5 database upgrade requires a full reindex.  Perform, or
	// resume, the reindex as needed.
	if err := b.maybeFinishV5Upgrade(ctx); err != nil {
		return nil, err
	}

	log.Infof("Blockchain database version info: chain: %d, compression: "+
		"%d, block index: %d", b.dbInfo.version, b.dbInfo.compVer,
		b.dbInfo.bidxVer)

	tip := b.bestChain.Tip()
	log.Infof("Chain state: height %d, hash %v, total transactions %d, "+
		"work %v, stake version %v", tip.height, tip.hash,
		b.stateSnapshot.TotalTxns, tip.workSum, 0)

	return &b, nil
}
