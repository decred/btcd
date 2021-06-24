// Copyright (c) 2016 The btcsuite developers
// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"fmt"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
)

// ThresholdState define the various threshold states used when voting on
// consensus changes.
type ThresholdState byte

// These constants are used to identify specific threshold states.
//
// NOTE: This section specifically does not use iota for the individual states
// since these values are serialized and must be stable for long-term storage.
const (
	// ThresholdDefined is the first state for each deployment and is the
	// state for the genesis block has by definition for all deployments.
	ThresholdDefined ThresholdState = 0

	// ThresholdStarted is the state for a deployment once its start time
	// has been reached.
	ThresholdStarted ThresholdState = 1

	// ThresholdLockedIn is the state for a deployment during the retarget
	// period which is after the ThresholdStarted state period and the
	// number of blocks that have voted for the deployment equal or exceed
	// the required number of votes for the deployment.
	ThresholdLockedIn ThresholdState = 2

	// ThresholdActive is the state for a deployment for all blocks after a
	// retarget period in which the deployment was in the ThresholdLockedIn
	// state.
	ThresholdActive ThresholdState = 3

	// ThresholdFailed is the state for a deployment once its expiration
	// time has been reached and it did not reach the ThresholdLockedIn
	// state.
	ThresholdFailed ThresholdState = 4

	// ThresholdInvalid is a deployment that does not exist.
	ThresholdInvalid ThresholdState = 5
)

// thresholdStateStrings is a map of ThresholdState values back to their
// constant names for pretty printing.
var thresholdStateStrings = map[ThresholdState]string{
	ThresholdDefined:  "ThresholdDefined",
	ThresholdStarted:  "ThresholdStarted",
	ThresholdLockedIn: "ThresholdLockedIn",
	ThresholdActive:   "ThresholdActive",
	ThresholdFailed:   "ThresholdFailed",
}

// String returns the ThresholdState as a human-readable name.
func (t ThresholdState) String() string {
	if s := thresholdStateStrings[t]; s != "" {
		return s
	}
	return fmt.Sprintf("Unknown ThresholdState (%d)", int(t))
}

const (
	// invalidChoice indicates an invalid choice in the
	// ThresholdStateTuple.
	invalidChoice = uint32(0xffffffff)
)

// ThresholdStateTuple contains the current state and the activated choice,
// when valid.
type ThresholdStateTuple struct {
	// state contains the current ThresholdState.
	State ThresholdState

	// Choice is set to invalidChoice unless state is: ThresholdLockedIn,
	// ThresholdFailed & ThresholdActive.  choice should always be
	// crosschecked with invalidChoice.
	Choice uint32
}

// thresholdStateTupleStrings is a map of ThresholdState values back to their
// constant names for pretty printing.
var thresholdStateTupleStrings = map[ThresholdState]string{
	ThresholdDefined:  "defined",
	ThresholdStarted:  "started",
	ThresholdLockedIn: "lockedin",
	ThresholdActive:   "active",
	ThresholdFailed:   "failed",
}

// String returns the ThresholdStateTuple as a human-readable tuple.
func (t ThresholdStateTuple) String() string {
	if s := thresholdStateTupleStrings[t.State]; s != "" {
		return fmt.Sprintf("%v", s)
	}
	return "invalid"
}

// newThresholdState returns an initialized ThresholdStateTuple.
func newThresholdState(state ThresholdState, choice uint32) ThresholdStateTuple {
	return ThresholdStateTuple{State: state, Choice: choice}
}

// thresholdConditionTally is returned by thresholdConditionChecker.Condition
// to indicate how many votes an option received.  The isAbstain and isNo flags
// are accordingly set.  Note isAbstain and isNo can NOT be both true at the
// same time.
type thresholdConditionTally struct {
	// Vote count
	count uint32

	// isAbstain is the abstain (or zero vote).
	isAbstain bool

	// isNo is the hard no vote.
	isNo bool
}

// thresholdConditionChecker provides a generic interface that is invoked to
// determine when a consensus rule change threshold should be changed.
type thresholdConditionChecker interface {
	// BeginTime returns the unix timestamp for the median block time after
	// which voting on a rule change starts (at the next window).
	BeginTime() uint64

	// EndTime returns the unix timestamp for the median block time after
	// which an attempted rule change fails if it has not already been
	// locked in or activated.
	EndTime() uint64

	// RuleChangeActivationQuorum is the minimum number of votes required
	// in a voting period for before we check
	// RuleChangeActivationThreshold.
	RuleChangeActivationQuorum() uint32

	// RuleChangeActivationThreshold is the number of votes required in
	// order to lock in a rule change.
	RuleChangeActivationThreshold(uint32) uint32

	// RuleChangeActivationInterval is the number of blocks in each threshold
	// state retarget window.
	RuleChangeActivationInterval() uint32

	// StakeValidationHeight is the minimum height required before votes start
	// counting.
	StakeValidationHeight() int64

	// Condition returns an array of thresholdConditionTally that contains
	// all votes.  By convention isAbstain and isNo can not be true at the
	// same time.  The array is always returned in the same order so that
	// the consumer can repeatedly call this function without having to
	// care about said order.  Only 1 isNo vote is allowed.  By convention
	// the zero value of the vote as determined by the mask is an isAbstain
	// vote.
	Condition(*blockNode, uint32) ([]thresholdConditionTally, error)
}

// thresholdStateCache provides a type to cache the threshold states of each
// threshold window for a set of IDs.  It also keeps track of which entries have
// been modified and therefore need to be written to the database.
type thresholdStateCache struct {
	dbUpdates map[chainhash.Hash]ThresholdStateTuple
	entries   map[chainhash.Hash]ThresholdStateTuple
}

// Lookup returns the threshold state associated with the given hash along with
// a boolean that indicates whether or not it is valid.
func (c *thresholdStateCache) Lookup(hash chainhash.Hash) (ThresholdStateTuple, bool) {
	state, ok := c.entries[hash]
	return state, ok
}

// Update updates the cache to contain the provided hash to threshold state
// mapping while properly tracking needed updates flush changes to the database.
func (c *thresholdStateCache) Update(hash chainhash.Hash, state ThresholdStateTuple) {
	if existing, ok := c.entries[hash]; ok && existing == state {
		return
	}

	c.dbUpdates[hash] = state
	c.entries[hash] = state
}

// MarkFlushed marks all of the current updates as flushed to the database.
// This is useful so the caller can ensure the needed database updates are not
// lost until they have successfully been written to the database.
func (c *thresholdStateCache) MarkFlushed() {
	for hash := range c.dbUpdates {
		delete(c.dbUpdates, hash)
	}
}

// newThresholdCaches returns a new array of caches to be used when calculating
// threshold states.
func newThresholdCaches(params *chaincfg.Params) map[uint32][]thresholdStateCache {
	caches := make(map[uint32][]thresholdStateCache)
	for version := range params.Deployments {
		caches[version] = make([]thresholdStateCache,
			len(params.Deployments[version]))
		for k := range caches[version] {
			caches[version][k].entries = make(map[chainhash.Hash]ThresholdStateTuple)
			caches[version][k].dbUpdates = make(map[chainhash.Hash]ThresholdStateTuple)
		}
	}
	return caches
}

// nextThresholdState returns the current rule change threshold state for the
// block AFTER the given node and deployment ID.  The cache is used to ensure
// the threshold states for previous windows are only calculated once.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *BlockChain) nextThresholdState(version uint32, prevNode *blockNode, checker thresholdConditionChecker, cache *thresholdStateCache) (ThresholdStateTuple, error) {
	// The threshold state for the window that contains the genesis block is
	// defined by definition.
	confirmationWindow := int64(checker.RuleChangeActivationInterval())
	svh := checker.StakeValidationHeight()
	if prevNode == nil || prevNode.height+1 < svh+confirmationWindow {
		return newThresholdState(ThresholdDefined, invalidChoice), nil
	}

	// Get the ancestor that is the last block of the previous confirmation
	// window in order to get its threshold state.  This can be done because
	// the state is the same for all blocks within a given window.
	wantHeight := calcWantHeight(svh,
		int64(checker.RuleChangeActivationInterval()),
		prevNode.height+1)
	prevNode = prevNode.Ancestor(wantHeight)

	// Iterate backwards through each of the previous confirmation windows
	// to find the most recently cached threshold state.
	var neededStates []*blockNode
	for prevNode != nil {
		// Nothing more to do if the state of the block is already
		// cached.
		if _, ok := cache.Lookup(prevNode.hash); ok {
			break
		}

		// The start and expiration times are based on the median block
		// time, so calculate it now.
		medianTime := prevNode.CalcPastMedianTime()

		// The state is simply defined if the start time hasn't been
		// been reached yet.
		if uint64(medianTime.Unix()) < checker.BeginTime() {
			cache.Update(prevNode.hash, ThresholdStateTuple{
				State:  ThresholdDefined,
				Choice: invalidChoice,
			})
			break
		}

		// Add this node to the list of nodes that need the state
		// calculated and cached.
		neededStates = append(neededStates, prevNode)

		// Get the ancestor that is the last block of the previous
		// confirmation window.
		prevNode = prevNode.RelativeAncestor(confirmationWindow)
	}

	// Start with the threshold state for the most recent confirmation
	// window that has a cached state.
	stateTuple := newThresholdState(ThresholdDefined, invalidChoice)
	if prevNode != nil {
		var ok bool
		stateTuple, ok = cache.Lookup(prevNode.hash)
		if !ok {
			return newThresholdState(ThresholdFailed,
					invalidChoice), AssertError(fmt.Sprintf(
					"thresholdState: cache lookup failed "+
						"for %v", prevNode.hash))
		}
	}

	// Since each threshold state depends on the state of the previous
	// window, iterate starting from the oldest unknown window.
	for neededNum := len(neededStates) - 1; neededNum >= 0; neededNum-- {
		prevNode := neededStates[neededNum]

		switch stateTuple.State {
		case ThresholdDefined:
			// Ensure we are at the minimal require height.
			if prevNode.height < svh {
				stateTuple.State = ThresholdDefined
				break
			}

			// The deployment of the rule change fails if it expires
			// before it is accepted and locked in.
			medianTime := prevNode.CalcPastMedianTime()
			medianTimeUnix := uint64(medianTime.Unix())
			if medianTimeUnix >= checker.EndTime() {
				stateTuple.State = ThresholdFailed
				break
			}

			// Make sure we are on the correct stake version.
			if b.calcStakeVersion(prevNode) < version {
				stateTuple.State = ThresholdDefined
				break
			}

			// The state must remain in the defined state so long as
			// a majority of the PoW miners have not upgraded.
			if !b.isMajorityVersion(int32(version), prevNode,
				b.chainParams.BlockRejectNumRequired) {

				stateTuple.State = ThresholdDefined
				break
			}

			// The state for the rule moves to the started state
			// once its start time has been reached (and it hasn't
			// already expired per the above).
			if medianTimeUnix >= checker.BeginTime() {
				stateTuple.State = ThresholdStarted
			}

		case ThresholdStarted:
			// The deployment of the rule change fails if it expires
			// before it is accepted and locked in.
			medianTime := prevNode.CalcPastMedianTime()
			if uint64(medianTime.Unix()) >= checker.EndTime() {
				stateTuple.State = ThresholdFailed
				break
			}

			// At this point, the rule change is still being voted
			// on, so iterate backwards through the confirmation
			// window to count all of the votes in it.
			var (
				counts       []thresholdConditionTally
				totalVotes   uint32
				abstainVotes uint32
			)
			countNode := prevNode
			for i := int64(0); i < confirmationWindow; i++ {
				c, err := checker.Condition(countNode, version)
				if err != nil {
					return newThresholdState(
						ThresholdFailed, invalidChoice), err
				}

				// Create array first time around.
				if len(counts) == 0 {
					counts = make([]thresholdConditionTally, len(c))
				}

				// Tally votes.
				for k := range c {
					counts[k].count += c[k].count
					counts[k].isAbstain = c[k].isAbstain
					counts[k].isNo = c[k].isNo
					if c[k].isAbstain {
						abstainVotes += c[k].count
					} else {
						totalVotes += c[k].count
					}
				}

				countNode = countNode.parent
			}

			// Determine if we have reached quorum.
			totalNonAbstainVotes := uint32(0)
			for _, v := range counts {
				if v.isAbstain && !v.isNo {
					continue
				}
				totalNonAbstainVotes += v.count
			}
			if totalNonAbstainVotes < checker.RuleChangeActivationQuorum() {
				break
			}

			// The state is locked in if the number of blocks in the
			// period that voted for the rule change meets the
			// activation threshold.
			for k, v := range counts {
				// We require at least 10% quorum on all votes.
				if v.count < checker.RuleChangeActivationThreshold(totalVotes) {
					continue
				}
				// Something went over the threshold
				switch {
				case !v.isAbstain && !v.isNo:
					// One of the choices has
					// reached majority.
					stateTuple.State = ThresholdLockedIn
					stateTuple.Choice = uint32(k)
				case !v.isAbstain && v.isNo:
					// No choice.  Only 1 No per
					// vote is allowed.  A No vote
					// is required though.
					stateTuple.State = ThresholdFailed
					stateTuple.Choice = uint32(k)
				case v.isAbstain && !v.isNo:
					// This is the abstain case.
					// The statemachine is not
					// supposed to change.
					continue
				case v.isAbstain && v.isNo:
					// Invalid choice.
					stateTuple.State = ThresholdFailed
					stateTuple.Choice = uint32(k)
				}
				break
			}

		case ThresholdLockedIn:
			// The new rule becomes active when its previous state
			// was locked in.
			stateTuple.State = ThresholdActive

		// Nothing to do if the previous state is active or failed since
		// they are both terminal states.
		case ThresholdActive:
		case ThresholdFailed:
		}

		// Update the cache to avoid recalculating the state in the
		// future.
		cache.Update(prevNode.hash, stateTuple)
	}

	return stateTuple, nil
}

// deploymentState returns the current rule change threshold for a given stake
// version and deploymentID.  The threshold is evaluated from the point of view
// of the block node passed in as the first argument to this method.
//
// It is important to note that, as the variable name indicates, this function
// expects the block node prior to the block for which the deployment state is
// desired.  In other words, the returned deployment state is for the block
// AFTER the passed node.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *BlockChain) deploymentState(prevNode *blockNode, version uint32, deploymentID string) (ThresholdStateTuple, error) {
	for k := range b.chainParams.Deployments[version] {
		if b.chainParams.Deployments[version][k].Vote.Id == deploymentID {
			checker := deploymentChecker{
				deployment: &b.chainParams.Deployments[version][k],
				chain:      b,
			}
			cache := &b.deploymentCaches[version][k]
			return b.nextThresholdState(version, prevNode, checker, cache)
		}
	}

	invalidState := ThresholdStateTuple{
		State:  ThresholdInvalid,
		Choice: invalidChoice,
	}
	str := fmt.Sprintf("deployment ID %s does not exist", deploymentID)
	return invalidState, contextError(ErrUnknownDeploymentID, str)
}

// stateLastChanged returns the node at which the provided consensus deployment
// agenda last changed state.  The function will return nil if the state has
// never changed.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *BlockChain) stateLastChanged(version uint32, node *blockNode, checker thresholdConditionChecker, cache *thresholdStateCache) (*blockNode, error) {
	// No state changes are possible if the chain is not yet past stake
	// validation height and had a full interval to change.
	confirmationInterval := int64(checker.RuleChangeActivationInterval())
	svh := checker.StakeValidationHeight()
	if node == nil || node.height < svh+confirmationInterval {
		return nil, nil
	}

	// Determine the current state.  Notice that nextThresholdState always
	// calculates the state for the block after the provided one, so use the
	// parent to get the state for the requested block.
	curState, err := b.nextThresholdState(version, node.parent, checker, cache)
	if err != nil {
		return nil, err
	}

	// Determine the first block of the current confirmation interval in order
	// to determine block at which the state possibly changed.  Since the state
	// can only change at an interval boundary, loop backwards one interval at
	// a time to determine when (and if) the state changed.
	finalNodeHeight := calcWantHeight(svh, confirmationInterval, node.height)
	node = node.Ancestor(finalNodeHeight + 1)
	priorStateChangeNode := node
	for node != nil && node.parent != nil {
		// As previously mentioned, nextThresholdState always calculates the
		// state for the block after the provided one, so use the parent to get
		// the state of the block itself.
		state, err := b.nextThresholdState(version, node.parent, checker, cache)
		if err != nil {
			return nil, err
		}

		if state.State != curState.State {
			return priorStateChangeNode, nil
		}

		// Get the ancestor that is the first block of the previous confirmation
		// interval.
		priorStateChangeNode = node
		node = node.RelativeAncestor(confirmationInterval)
	}

	return nil, nil
}

// StateLastChangedHeight returns the height at which the provided consensus
// deployment agenda last changed state.  Note that, unlike the
// NextThresholdState function, this function returns the information as of the
// passed block hash.
//
// This function is safe for concurrent access.
func (b *BlockChain) StateLastChangedHeight(hash *chainhash.Hash, version uint32, deploymentID string) (int64, error) {
	node := b.index.LookupNode(hash)
	if node == nil || !b.index.CanValidate(node) {
		return 0, unknownBlockError(hash)
	}

	// Fetch the threshold state cache for the provided deployment id as well as
	// the condition checker.
	var cache *thresholdStateCache
	var checker thresholdConditionChecker
	for k := range b.chainParams.Deployments[version] {
		if b.chainParams.Deployments[version][k].Vote.Id == deploymentID {
			checker = deploymentChecker{
				deployment: &b.chainParams.Deployments[version][k],
				chain:      b,
			}
			cache = &b.deploymentCaches[version][k]
			break
		}
	}

	if cache == nil {
		return 0, fmt.Errorf("threshold state cache for agenda with "+
			"deployment id (%s) not found", deploymentID)
	}

	// Find the node at which the current state changed.
	b.chainLock.Lock()
	stateNode, err := b.stateLastChanged(version, node, checker, cache)
	b.chainLock.Unlock()
	if err != nil {
		return 0, err
	}

	var height int64
	if stateNode != nil {
		height = stateNode.height
	}
	return height, nil
}

// NextThresholdState returns the current rule change threshold state of the
// given deployment ID for the block AFTER the provided block hash.
//
// This function is safe for concurrent access.
func (b *BlockChain) NextThresholdState(hash *chainhash.Hash, version uint32, deploymentID string) (ThresholdStateTuple, error) {
	node := b.index.LookupNode(hash)
	if node == nil || !b.index.CanValidate(node) {
		invalidState := ThresholdStateTuple{
			State:  ThresholdInvalid,
			Choice: invalidChoice,
		}
		return invalidState, unknownBlockError(hash)
	}

	b.chainLock.Lock()
	state, err := b.deploymentState(node, version, deploymentID)
	b.chainLock.Unlock()
	return state, err
}

// isLNFeaturesAgendaActive returns whether or not the LN features agenda vote,
// as defined in DCP0002 and DCP0003 has passed and is now active from the point
// of view of the passed block node.
//
// It is important to note that, as the variable name indicates, this function
// expects the block node prior to the block for which the deployment state is
// desired.  In other words, the returned deployment state is for the block
// AFTER the passed node.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *BlockChain) isLNFeaturesAgendaActive(prevNode *blockNode) (bool, error) {
	// Determine the correct deployment version for the LN features consensus
	// vote as defined in DCP0002 and DCP0003 or treat it as active when voting
	// is not enabled for the current network.
	const deploymentID = chaincfg.VoteIDLNFeatures
	deploymentVer, ok := b.deploymentVers[deploymentID]
	if !ok {
		return true, nil
	}

	state, err := b.deploymentState(prevNode, deploymentVer, deploymentID)
	if err != nil {
		return false, err
	}

	// NOTE: The choice field of the return threshold state is not examined
	// here because there is only one possible choice that can be active for
	// the agenda, which is yes, so there is no need to check it.
	return state.State == ThresholdActive, nil
}

// IsLNFeaturesAgendaActive returns whether or not the LN features agenda vote,
// as defined in DCP0002 and DCP0003 has passed and is now active for the block
// AFTER the given block.
//
// This function is safe for concurrent access.
func (b *BlockChain) IsLNFeaturesAgendaActive(prevHash *chainhash.Hash) (bool, error) {
	prevNode := b.index.LookupNode(prevHash)
	if prevNode == nil || !b.index.CanValidate(prevNode) {
		return false, unknownBlockError(prevHash)
	}

	b.chainLock.Lock()
	isActive, err := b.isLNFeaturesAgendaActive(prevNode)
	b.chainLock.Unlock()
	return isActive, err
}

// isHeaderCommitmentsAgendaActive returns whether or not the header commitments
// agenda vote, as defined in DCP0005 has passed and is now active from the
// point of view of the passed block node.
//
// It is important to note that, as the variable name indicates, this function
// expects the block node prior to the block for which the deployment state is
// desired.  In other words, the returned deployment state is for the block
// AFTER the passed node.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *BlockChain) isHeaderCommitmentsAgendaActive(prevNode *blockNode) (bool, error) {
	// Determine the correct deployment version for the header commitments
	// consensus vote as defined in DCP0005 or treat it as active when voting
	// is not enabled for the current network.
	const deploymentID = chaincfg.VoteIDHeaderCommitments
	deploymentVer, ok := b.deploymentVers[deploymentID]
	if !ok {
		return true, nil
	}

	state, err := b.deploymentState(prevNode, deploymentVer, deploymentID)
	if err != nil {
		return false, err
	}

	// NOTE: The choice field of the return threshold state is not examined
	// here because there is only one possible choice that can be active for
	// the agenda, which is yes, so there is no need to check it.
	return state.State == ThresholdActive, nil
}

// IsHeaderCommitmentsAgendaActive returns whether or not the header commitments
// agenda vote, as defined in DCP0005 has passed and is now active for the block
// AFTER the given block.
//
// This function is safe for concurrent access.
func (b *BlockChain) IsHeaderCommitmentsAgendaActive(prevHash *chainhash.Hash) (bool, error) {
	node := b.index.LookupNode(prevHash)
	if node == nil || !b.index.CanValidate(node) {
		return false, unknownBlockError(prevHash)
	}

	b.chainLock.Lock()
	isActive, err := b.isHeaderCommitmentsAgendaActive(node)
	b.chainLock.Unlock()
	return isActive, err
}

// isTreasuryAgendaActive returns whether or not the treasury agenda, as defined
// in DCP0006, has passed and is now active from the point of view of the passed
// block node.
//
// It is important to note that, as the variable name indicates, this function
// expects the block node prior to the block for which the deployment state is
// desired.  In other words, the returned deployment state is for the block
// AFTER the passed node.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *BlockChain) isTreasuryAgendaActive(prevNode *blockNode) (bool, error) {
	// Ignore block 0 and 1 because they are special.
	if prevNode.height == 0 {
		return false, nil
	}
	const deploymentID = chaincfg.VoteIDTreasury
	deploymentVer, ok := b.deploymentVers[deploymentID]
	if !ok {
		return true, nil
	}

	state, err := b.deploymentState(prevNode, deploymentVer, deploymentID)
	if err != nil {
		return false, err
	}

	// NOTE: The choice field of the return threshold state is not examined
	// here because there is only one possible choice that can be active for
	// the agenda, which is yes, so there is no need to check it.
	return state.State == ThresholdActive, nil
}

// IsTreasuryAgendaActive returns whether or not the treasury agenda vote, as
// defined in DCP0006, has passed and is now active for the block AFTER the
// given block.
//
// This function is safe for concurrent access.
func (b *BlockChain) IsTreasuryAgendaActive(prevHash *chainhash.Hash) (bool, error) {
	// The treasury agenda is never active for the genesis block.
	if *prevHash == *zeroHash {
		return false, nil
	}

	prevNode := b.index.LookupNode(prevHash)
	if prevNode == nil || !b.index.CanValidate(prevNode) {
		return false, unknownBlockError(prevHash)
	}

	b.chainLock.Lock()
	isActive, err := b.isTreasuryAgendaActive(prevNode)
	b.chainLock.Unlock()
	return isActive, err
}

// isRevertTreasuryPolicyActive returns whether or not the revert treasury
// expenditure policy agenda, as defined in DCP0007, has passed and is now
// active from the point of view of the passed block node.
//
// It is important to note that, as the variable name indicates, this function
// expects the block node prior to the block for which the deployment state is
// desired.  In other words, the returned deployment state is for the block
// AFTER the passed node.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *BlockChain) isRevertTreasuryPolicyActive(prevNode *blockNode) (bool, error) {
	// Ignore block 0 and 1 because they are special.
	if prevNode.height == 0 {
		return false, nil
	}
	const deploymentID = chaincfg.VoteIDRevertTreasuryPolicy
	deploymentVer, ok := b.deploymentVers[deploymentID]
	if !ok {
		return true, nil
	}

	state, err := b.deploymentState(prevNode, deploymentVer, deploymentID)
	if err != nil {
		return false, err
	}

	// NOTE: The choice field of the return threshold state is not examined
	// here because there is only one possible choice that can be active for
	// the agenda, which is yes, so there is no need to check it.
	return state.State == ThresholdActive, nil
}

// IsRevertTreasuryPolicyActive returns whether or not the revert treasury
// expenditure policy agenda vote, as defined in DCP0007, has passed and is now
// active for the block AFTER the given block.
//
// This function is safe for concurrent access.
func (b *BlockChain) IsRevertTreasuryPolicyActive(prevHash *chainhash.Hash) (bool, error) {
	// The treasury agenda is never active for the genesis block.
	if *prevHash == *zeroHash {
		return false, nil
	}

	prevNode := b.index.LookupNode(prevHash)
	if prevNode == nil || !b.index.CanValidate(prevNode) {
		return false, unknownBlockError(prevHash)
	}

	b.chainLock.Lock()
	isActive, err := b.isRevertTreasuryPolicyActive(prevNode)
	b.chainLock.Unlock()
	return isActive, err
}

// VoteCounts is a compacted struct that is used to message vote counts.
type VoteCounts struct {
	Total        uint32
	TotalAbstain uint32
	VoteChoices  []uint32
}

// getVoteCounts returns the vote counts for the specified version for the
// current rule change activation interval.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *BlockChain) getVoteCounts(node *blockNode, version uint32, d *chaincfg.ConsensusDeployment) (VoteCounts, error) {
	// Don't try to count votes before the stake validation height since there
	// could not possibly have been any.
	svh := b.chainParams.StakeValidationHeight
	if node.height < svh {
		return VoteCounts{
			VoteChoices: make([]uint32, len(d.Vote.Choices)),
		}, nil
	}

	// Calculate the final height of the prior interval.
	rcai := int64(b.chainParams.RuleChangeActivationInterval)
	height := calcWantHeight(svh, rcai, node.height)

	result := VoteCounts{
		VoteChoices: make([]uint32, len(d.Vote.Choices)),
	}
	countNode := node
	for countNode.height > height {
		for _, vote := range countNode.votes {
			// Wrong versions do not count.
			if vote.Version != version {
				continue
			}

			// Increase total votes.
			result.Total++

			index := d.Vote.VoteIndex(vote.Bits)
			if index == -1 {
				// Invalid votes are treated as abstain.
				result.TotalAbstain++
				continue
			} else if d.Vote.Choices[index].IsAbstain {
				result.TotalAbstain++
			}
			result.VoteChoices[index]++
		}

		countNode = countNode.parent
	}

	return result, nil
}

// GetVoteCounts returns the vote counts for the specified version and
// deployment identifier for the current rule change activation interval.
//
// This function is safe for concurrent access.
func (b *BlockChain) GetVoteCounts(version uint32, deploymentID string) (VoteCounts, error) {
	for k := range b.chainParams.Deployments[version] {
		deployment := &b.chainParams.Deployments[version][k]
		if deployment.Vote.Id == deploymentID {
			b.chainLock.Lock()
			counts, err := b.getVoteCounts(b.bestChain.Tip(), version, deployment)
			b.chainLock.Unlock()
			return counts, err
		}
	}
	str := fmt.Sprintf("deployment ID %s does not exist", deploymentID)
	return VoteCounts{}, contextError(ErrUnknownDeploymentID, str)
}

// CountVoteVersion returns the total number of version votes for the current
// rule change activation interval.
//
// This function is safe for concurrent access.
func (b *BlockChain) CountVoteVersion(version uint32) (uint32, error) {
	b.chainLock.Lock()
	defer b.chainLock.Unlock()
	countNode := b.bestChain.Tip()

	// Don't try to count votes before the stake validation height since there
	// could not possibly have been any.
	svh := b.chainParams.StakeValidationHeight
	if countNode.height < svh {
		return 0, nil
	}

	// Calculate the final height of the prior interval.
	rcai := int64(b.chainParams.RuleChangeActivationInterval)
	height := calcWantHeight(svh, rcai, countNode.height)

	total := uint32(0)
	for countNode.height > height {
		for _, vote := range countNode.votes {
			// Wrong versions do not count.
			if vote.Version != version {
				continue
			}

			// Increase total votes.
			total++
		}

		countNode = countNode.parent
	}

	return total, nil
}
