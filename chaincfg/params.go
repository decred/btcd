// Copyright (c) 2014-2016 The btcsuite developers
// Copyright (c) 2015-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chaincfg

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"time"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/wire"
)

// bigOne is 1 represented as a big.Int.  It is defined here to avoid the
// overhead of creating it multiple times.
var bigOne = big.NewInt(1)

// Checkpoint identifies a known good point in the block chain.  Using
// checkpoints allows a few optimizations for old blocks during initial download
// and also prevents forks from old blocks.
//
// Each checkpoint is selected based upon several factors.  See the
// documentation for chain.IsCheckpointCandidate for details on the selection
// criteria.
type Checkpoint struct {
	Height int64
	Hash   *chainhash.Hash
}

// Vote describes a voting instance.  It is self-describing so that the UI can
// be directly implemented using the fields.  Mask determines which bits can be
// used.  Bits are enumerated and must be consecutive.  Each vote requires one
// and only one abstain (bits = 0) and reject vote (IsNo = true).
//
// For example, change block height from int64 to uint64.
// Vote {
//	Id:          "blockheight",
//	Description: "Change block height from int64 to uint64"
//	Mask:        0x0006,
//	Choices:     []Choice{
//		{
//			Id:          "abstain",
//			Description: "abstain voting for change",
//			Bits:        0x0000,
//			IsAbstain:   true,
//			IsNo:        false,
//		},
//		{
//			Id:          "no",
//			Description: "reject changing block height to uint64",
//			Bits:        0x0002,
//			IsAbstain:   false,
//			IsNo:        false,
//		},
//		{
//			Id:          "yes",
//			Description: "accept changing block height to uint64",
//			Bits:        0x0004,
//			IsAbstain:   false,
//			IsNo:        true,
//		},
//	},
// }
//
type Vote struct {
	// Single unique word identifying the vote.
	Id string

	// Longer description of what the vote is about.
	Description string

	// Usable bits for this vote.
	Mask uint16

	Choices []Choice
}

// Choice defines one of the possible Choices that make up a vote. The 0 value
// in Bits indicates the default choice.  Care should be taken not to bias a
// vote with the default choice.
type Choice struct {
	// Single unique word identifying vote (e.g. yes)
	Id string

	// Longer description of the vote.
	Description string

	// Bits used for this vote.
	Bits uint16

	// This is the abstain choice.  By convention this must be the 0 vote
	// (abstain) and exist only once in the Vote.Choices array.
	IsAbstain bool

	// This choice indicates a hard No Vote.  By convention this must exist
	// only once in the Vote.Choices array.
	IsNo bool
}

// VoteIndex compares vote to Choice.Bits and returns the index into the
// Choices array.  If the vote is invalid it returns -1.
func (v *Vote) VoteIndex(vote uint16) int {
	vote &= v.Mask
	for k := range v.Choices {
		if vote == v.Choices[k].Bits {
			return k
		}
	}

	return -1
}

const (
	// VoteIDMaxBlockSize is the vote ID for the maximum block size
	// increase agenda used for the hard fork demo.
	VoteIDMaxBlockSize = "maxblocksize"

	// VoteIDSDiffAlgorithm is the vote ID for the new stake difficulty
	// algorithm (aka ticket price) agenda defined by DCP0001.
	VoteIDSDiffAlgorithm = "sdiffalgorithm"

	// VoteIDLNSupport is the vote ID for determining if the developers
	// should work on integrating Lightning Network support.
	VoteIDLNSupport = "lnsupport"

	// VoteIDLNFeatures is the vote ID for the agenda that introduces
	// features useful for the Lightning Network (among other uses) defined
	// by DCP0002 and DCP0003.
	VoteIDLNFeatures = "lnfeatures"

	// VoteIDFixLNSeqLocks is the vote ID for the agenda that corrects the
	// sequence lock functionality needed for Lightning Network (among other
	// uses) defined by DCP0004.
	VoteIDFixLNSeqLocks = "fixlnseqlocks"

	// VoteIDHeaderCommitments is the vote ID for the agenda that repurposes
	// the stake root header field to support header commitments and provides
	// an initial commitment to version 2 GCS filters defined by DCP0005.
	VoteIDHeaderCommitments = "headercommitments"

	// VoteIDTreasury is the vote ID for the agenda that enables the
	// decentralized treasury opcodes defined by DCP0006.
	VoteIDTreasury = "treasury"

	// VoteIDRevertTreasuryPolicy is the vote ID for the agenda that
	// reverts the maxium expenditure policy of the treasury account as
	// defined by DCP0007.
	VoteIDRevertTreasuryPolicy = "reverttreasurypolicy"
)

// ConsensusDeployment defines details related to a specific consensus rule
// change that is voted in.  This is part of BIP0009.
type ConsensusDeployment struct {
	// Vote describes the what is being voted on and what the choices are.
	// This is sitting in a struct in order to make merging between btcd
	// easier.
	Vote Vote

	// StartTime is the median block time after which voting on the
	// deployment starts.
	StartTime uint64

	// ExpireTime is the median block time after which the attempted
	// deployment expires.
	ExpireTime uint64
}

// TokenPayout is a payout for block 1 which specifies a required script
// version, script, and amount to pay in a transaction output.
type TokenPayout struct {
	ScriptVersion uint16
	Script        []byte
	Amount        int64
}

// DNSSeed identifies a DNS seed.
//
// Deprecated: This will be removed in the next major version bump.
type DNSSeed struct {
	// Host defines the hostname of the seed.
	Host string

	// HasFiltering defines whether the seed supports filtering
	// by service flags (wire.ServiceFlag).
	HasFiltering bool
}

// String returns the hostname of the DNS seed in human-readable form.
func (d DNSSeed) String() string {
	return d.Host
}

// Params defines a Decred network by its parameters.  These parameters may be
// used by Decred applications to differentiate networks as well as addresses
// and keys for one network from those intended for use on another network.
type Params struct {
	// Name defines a human-readable identifier for the network.
	Name string

	// Net defines the magic bytes used to identify the network.
	Net wire.CurrencyNet

	// DefaultPort defines the default peer-to-peer port for the network.
	DefaultPort string

	// DNSSeeds defines a list of DNS seeds for the network that are used
	// as one method to discover peers.
	//
	// Deprecated: This will be removed in the next major version bump.
	DNSSeeds []DNSSeed

	// GenesisBlock defines the first block of the chain.
	GenesisBlock *wire.MsgBlock

	// GenesisHash is the starting block hash.
	GenesisHash chainhash.Hash

	// PowLimit defines the highest allowed proof of work value for a block
	// as a uint256.
	PowLimit *big.Int

	// PowLimitBits defines the highest allowed proof of work value for a
	// block in compact form.
	PowLimitBits uint32

	// ReduceMinDifficulty defines whether the network should reduce the
	// minimum required difficulty after a long enough period of time has
	// passed without finding a block.  This is really only useful for test
	// networks and should not be set on a main network.
	ReduceMinDifficulty bool

	// MinDiffReductionTime is the amount of time after which the minimum
	// required difficulty should be reduced when a block hasn't been found.
	//
	// NOTE: This only applies if ReduceMinDifficulty is true.
	MinDiffReductionTime time.Duration

	// GenerateSupported specifies whether or not CPU mining is allowed.
	GenerateSupported bool

	// MaximumBlockSizes are the maximum sizes of a block that can be
	// generated on the network.  It is an array because the max block size
	// can be different values depending on the results of a voting agenda.
	// The first entry is the initial block size for the network, while the
	// other entries are potential block size changes which take effect when
	// the vote for the associated agenda succeeds.
	MaximumBlockSizes []int

	// MaxTxSize is the maximum number of bytes a serialized transaction can
	// be in order to be considered valid by consensus.
	MaxTxSize int

	// TargetTimePerBlock is the desired amount of time to generate each
	// block.
	TargetTimePerBlock time.Duration

	// WorkDiffAlpha is the stake difficulty EMA calculation alpha (smoothing)
	// value. It is different from a normal EMA alpha. Closer to 1 --> smoother.
	WorkDiffAlpha int64

	// WorkDiffWindowSize is the number of windows (intervals) used for calculation
	// of the exponentially weighted average.
	WorkDiffWindowSize int64

	// WorkDiffWindows is the number of windows (intervals) used for calculation
	// of the exponentially weighted average.
	WorkDiffWindows int64

	// TargetTimespan is the desired amount of time that should elapse
	// before the block difficulty requirement is examined to determine how
	// it should be changed in order to maintain the desired block
	// generation rate.  This value should correspond to the product of
	// WorkDiffWindowSize and TimePerBlock above.
	TargetTimespan time.Duration

	// RetargetAdjustmentFactor is the adjustment factor used to limit
	// the minimum and maximum amount of adjustment that can occur between
	// difficulty retargets.
	RetargetAdjustmentFactor int64

	// Subsidy parameters.
	//
	// Subsidy calculation for exponential reductions:
	// 0 for i in range (0, height / SubsidyReductionInterval):
	// 1     subsidy *= MulSubsidy
	// 2     subsidy /= DivSubsidy
	//
	// NOTE: BaseSubsidy must be a max of 140,739,635,871,744 atoms or incorrect
	// results will occur due to int64 overflow.  This value comes from
	// MaxInt64/MaxUint16 = (2^63 - 1)/(2^16 - 1) = 2^47 + 2^31 + 2^15.

	// BaseSubsidy is the starting subsidy amount for mined blocks.
	BaseSubsidy int64

	// Subsidy reduction multiplier.
	MulSubsidy int64

	// Subsidy reduction divisor.
	DivSubsidy int64

	// SubsidyReductionInterval is the reduction interval in blocks.
	SubsidyReductionInterval int64

	// WorkRewardProportion is the comparative amount of the subsidy given for
	// creating a block.
	WorkRewardProportion uint16

	// StakeRewardProportion is the comparative amount of the subsidy given for
	// casting stake votes (collectively, per block).
	StakeRewardProportion uint16

	// BlockTaxProportion is the inverse of the percentage of funds for each
	// block to allocate to the developer organization.
	// e.g. 10% --> 10 (or 1 / (1/10))
	// Special case: disable taxes with a value of 0
	BlockTaxProportion uint16

	// Checkpoints ordered from oldest to newest.
	Checkpoints []Checkpoint

	// MinKnownChainWork is the minimum amount of known total work for the chain
	// at a given point in time.  This is intended to be updated periodically
	// with new releases.  It may be nil for networks that do not require it.
	MinKnownChainWork *big.Int

	// These fields are related to voting on consensus rule changes as
	// defined by BIP0009.
	//
	// RuleChangeActivationQurom is the number of votes required for a vote
	// to take effect.
	//
	// RuleChangeActivationInterval is the number of blocks in each threshold
	// state retarget window.
	//
	// Deployments define the specific consensus rule changes to be voted
	// on for the stake version (the map key).
	RuleChangeActivationQuorum     uint32
	RuleChangeActivationMultiplier uint32
	RuleChangeActivationDivisor    uint32
	RuleChangeActivationInterval   uint32
	Deployments                    map[uint32][]ConsensusDeployment

	// Enforce current block version once network has upgraded.
	BlockEnforceNumRequired uint64

	// Reject previous block versions once network has upgraded.
	BlockRejectNumRequired uint64

	// The number of nodes to check.
	BlockUpgradeNumToCheck uint64

	// AcceptNonStdTxs is a mempool param to either accept and relay
	// non standard txs to the network or reject them
	AcceptNonStdTxs bool

	// NetworkAddressPrefix is the first letter of the network
	// for any given address encoded as a string.
	NetworkAddressPrefix string

	// Address encoding magics
	PubKeyAddrID     [2]byte // First 2 bytes of a P2PK address
	PubKeyHashAddrID [2]byte // First 2 bytes of a P2PKH address
	PKHEdwardsAddrID [2]byte // First 2 bytes of an Edwards P2PKH address
	PKHSchnorrAddrID [2]byte // First 2 bytes of a secp256k1 Schnorr P2PKH address
	ScriptHashAddrID [2]byte // First 2 bytes of a P2SH address
	PrivateKeyID     [2]byte // First 2 bytes of a WIF private key

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID [4]byte
	HDPublicKeyID  [4]byte

	// SLIP-0044 registered coin type used for BIP44, used in the hierarchical
	// deterministic path for address generation.
	// All SLIP-0044 registered coin types are defined here:
	// https://github.com/satoshilabs/slips/blob/master/slip-0044.md
	SLIP0044CoinType uint32

	// Legacy BIP44 coin type used in the hierarchical deterministic path for
	// address generation. Previous name was HDCoinType, the LegacyCoinType
	// was introduced for backwards compatibility. Usually, SLIP0044CoinType
	// should be used instead.
	LegacyCoinType uint32

	// MinimumStakeDiff if the minimum amount of Atoms required to purchase a
	// stake ticket.
	MinimumStakeDiff int64

	// Ticket pool sizes for Decred PoS. This denotes the number of possible
	// buckets/number of different ticket numbers. It is also the number of
	// possible winner numbers there are.
	TicketPoolSize uint16

	// Average number of tickets per block for Decred PoS.
	TicketsPerBlock uint16

	// Number of blocks for tickets to mature (spendable at TicketMaturity+1).
	TicketMaturity uint16

	// Number of blocks for tickets to expire after they have matured. This MUST
	// be >= (StakeEnabledHeight + StakeValidationHeight).
	TicketExpiry uint32

	// CoinbaseMaturity is the number of blocks required before newly mined
	// coins (coinbase transactions) can be spent.
	CoinbaseMaturity uint16

	// Maturity for spending SStx change outputs.
	SStxChangeMaturity uint16

	// TicketPoolSizeWeight is the multiplicative weight applied to the
	// ticket pool size difference between a window period and its target
	// when determining the stake system.
	TicketPoolSizeWeight uint16

	// StakeDiffAlpha is the stake difficulty EMA calculation alpha (smoothing)
	// value. It is different from a normal EMA alpha. Closer to 1 --> smoother.
	StakeDiffAlpha int64

	// StakeDiffWindowSize is the number of blocks used for each interval in
	// exponentially weighted average.
	StakeDiffWindowSize int64

	// StakeDiffWindows is the number of windows (intervals) used for calculation
	// of the exponentially weighted average.
	StakeDiffWindows int64

	// StakeVersionInterval determines the interval where the stake version
	// is calculated.
	StakeVersionInterval int64

	// MaxFreshStakePerBlock is the maximum number of new tickets that may be
	// submitted per block.
	MaxFreshStakePerBlock uint8

	// StakeEnabledHeight is the height in which the first ticket could possibly
	// mature.
	StakeEnabledHeight int64

	// StakeValidationHeight is the height at which votes (SSGen) are required
	// to add a new block to the top of the blockchain. This height is the
	// first block that will be voted on, but will include in itself no votes.
	StakeValidationHeight int64

	// StakeBaseSigScript is the consensus stakebase signature script for all
	// votes on the network. This isn't signed in any way, so without forcing
	// it to be this value miners/daemons could freely change it.
	StakeBaseSigScript []byte

	// StakeMajorityMultiplier and StakeMajorityDivisor are used
	// to calculate the super majority of stake votes using integer math as
	// such: X*StakeMajorityMultiplier/StakeMajorityDivisor
	StakeMajorityMultiplier int32
	StakeMajorityDivisor    int32

	// OrganizationPkScript is the output script for block taxes to be
	// distributed to in every block's coinbase. It should ideally be a P2SH
	// multisignature address.  OrganizationPkScriptVersion is the version
	// of the output script.  Until PoS hardforking is implemented, this
	// version must always match for a block to validate.
	OrganizationPkScript        []byte
	OrganizationPkScriptVersion uint16

	// BlockOneLedger specifies the list of payouts in the coinbase of
	// block height 1. If there are no payouts to be given, set this
	// to an empty slice.
	BlockOneLedger []TokenPayout

	// PiKeys is the list of sanctioned Politeia keys. There should be at
	// least two of them at any given time. The corresponding private keys
	// for mainnet and testnet must be guarded with extreme prejudice. On
	// the other hand simnet and regnet have these values hardcoded for
	// easier testing.
	PiKeys [][]byte

	// TreasuryVoteInterval dictates when a TSpend transaction is allowed
	// in a block.
	TreasuryVoteInterval uint64

	// TreasuryVoteIntervalMultiplier is the multiplier to the
	// TreasuryVoteInterval that is needed to calculate Expiry.
	TreasuryVoteIntervalMultiplier uint64

	// TreasuryVoteQuorumMultiplier and TreasuryVoteQuorumDivisor are used
	// to calculate the TSpend vote quorum percentage.
	TreasuryVoteQuorumMultiplier uint64
	TreasuryVoteQuorumDivisor    uint64

	// TreasuryVoteRequiredMultiplier and TreasuryVoteRequiredDivisor are
	// used to calculate the required number of votes percentage.
	TreasuryVoteRequiredMultiplier uint64
	TreasuryVoteRequiredDivisor    uint64

	// TreasuryExpenditureWindow is the number of TVI*Multiplier windows
	// that define a single "expenditure window".
	TreasuryExpenditureWindow uint64

	// TreasuryExpenditurePolicy is the number of previous
	// TreasuryExpenditureWindows that defines how far back to calculate
	// the average expenditure of the treasury for an expenditure policy
	// check.
	TreasuryExpenditurePolicy uint64

	// TreasuryExpenditureBootstrap is the value to use as previous average
	// expenditure when there are no treasury spends inside the entire
	// window defined by TreasuryExpenditurePolicy.
	TreasuryExpenditureBootstrap uint64

	// seeders defines a list of seeders for the network that are used
	// as one method to discover peers.
	seeders []string
}

// HDPrivKeyVersion returns the hierarchical deterministic extended private key
// magic version bytes for the network the parameters define.
func (p *Params) HDPrivKeyVersion() [4]byte {
	return p.HDPrivateKeyID
}

// HDPubKeyVersion returns the hierarchical deterministic extended public key
// magic version bytes for the network the parameters define.
func (p *Params) HDPubKeyVersion() [4]byte {
	return p.HDPublicKeyID
}

// AddrIDPubKeyV0 returns the magic prefix bytes for version 0 pay-to-pubkey
// addresses.
func (p *Params) AddrIDPubKeyV0() [2]byte {
	return p.PubKeyAddrID
}

// AddrIDPubKeyHashECDSAV0 returns the magic prefix bytes for version 0
// pay-to-pubkey-hash addresses where the underlying pubkey is secp256k1 and the
// signature algorithm is ECDSA.
func (p *Params) AddrIDPubKeyHashECDSAV0() [2]byte {
	return p.PubKeyHashAddrID
}

// AddrIDPubKeyHashEd25519V0 returns the magic prefix bytes for version 0
// pay-to-pubkey-hash addresses where the underlying pubkey and signature
// algorithm are Ed25519.
func (p *Params) AddrIDPubKeyHashEd25519V0() [2]byte {
	return p.PKHEdwardsAddrID
}

// AddrIDPubKeyHashSchnorrV0 returns the magic prefix bytes for version 0
// pay-to-pubkey-hash addresses where the underlying pubkey is secp256k1 and the
// signature algorithm is Schnorr.
func (p *Params) AddrIDPubKeyHashSchnorrV0() [2]byte {
	return p.PKHSchnorrAddrID
}

// AddrIDScriptHashV0 returns the magic prefix bytes for version 0
// pay-to-script-hash addresses.
func (p *Params) AddrIDScriptHashV0() [2]byte {
	return p.ScriptHashAddrID
}

// BaseSubsidyValue returns the starting base max potential subsidy amount for
// mined blocks.  This value is reduced over time and then split proportionally
// between PoW, PoS, and the Treasury.  The reduction is controlled by the
// SubsidyReductionInterval, SubsidyReductionMultiplier, and
// SubsidyReductionDivisor parameters.
func (p *Params) BaseSubsidyValue() int64 {
	return p.BaseSubsidy
}

// SubsidyReductionMultiplier returns the multiplier to use when performing
// the exponential subsidy reduction.
func (p *Params) SubsidyReductionMultiplier() int64 {
	return p.MulSubsidy
}

// SubsidyReductionDivisor returns the divisor to use when performing the
// exponential subsidy reduction.
func (p *Params) SubsidyReductionDivisor() int64 {
	return p.DivSubsidy
}

// SubsidyReductionIntervalBlocks returns the reduction interval in number of
// blocks.
func (p *Params) SubsidyReductionIntervalBlocks() int64 {
	return p.SubsidyReductionInterval
}

// WorkSubsidyProportion returns the comparative proportion of the subsidy
// generated for creating a block (PoW).
//
// The proportional split between PoW, PoS, and the Treasury is calculated
// by treating each of the proportional parameters as a ratio to the sum of
// the three proportional parameters: WorkSubsidyProportion,
// StakeSubsidyProportion, and TreasurySubsidyProportion.
//
// For example:
// WorkSubsidyProportion:     6 => 6 / (6+3+1) => 6/10 => 60%
// StakeSubsidyProportion:    3 => 3 / (6+3+1) => 3/10 => 30%
// TreasurySubsidyProportion: 1 => 1 / (6+3+1) => 1/10 => 10%
func (p *Params) WorkSubsidyProportion() uint16 {
	return p.WorkRewardProportion
}

// StakeSubsidyProportion returns the comparative proportion of the subsidy
// generated for casting stake votes (collectively, per block).  See the
// documentation for WorkSubsidyProportion for more details on how the
// parameter is used.
func (p *Params) StakeSubsidyProportion() uint16 {
	return p.StakeRewardProportion
}

// TreasurySubsidyProportion returns the comparative proportion of the
// subsidy allocated to the project treasury.  See the documentation for
// WorkSubsidyProportion for more details on how the parameter is used.
func (p *Params) TreasurySubsidyProportion() uint16 {
	return p.BlockTaxProportion
}

// VotesPerBlock returns the maximum number of votes a block must contain to
// receive full subsidy.
func (p *Params) VotesPerBlock() uint16 {
	return p.TicketsPerBlock
}

// StakeValidationBeginHeight returns the height at which votes become required
// to extend a block.  This height is the first that will be voted on, but will
// not include any votes itself.
func (p *Params) StakeValidationBeginHeight() int64 {
	return p.StakeValidationHeight
}

// StakeEnableHeight returns the height at which the first ticket could possibly
// mature.
func (p *Params) StakeEnableHeight() int64 {
	return p.StakeEnabledHeight
}

// TicketExpiryBlocks returns the number of blocks after maturity that tickets
// expire. This will be >= (StakeEnableHeight() + StakeValidationBeginHeight()).
func (p *Params) TicketExpiryBlocks() uint32 {
	return p.TicketExpiry
}

// newHashFromStr converts the passed big-endian hex string into a
// chainhash.Hash.  It only differs from the one available in chainhash in that
// it panics on an error since it will only (and must only) be called with
// hard-coded, and therefore known good, hashes.
func newHashFromStr(hexStr string) *chainhash.Hash {
	hash, err := chainhash.NewHashFromStr(hexStr)
	if err != nil {
		// Ordinarily I don't like panics in library code since it
		// can take applications down without them having a chance to
		// recover which is extremely annoying, however an exception is
		// being made in this case because the only way this can panic
		// is if there is an error in the hard-coded hashes.  Thus it
		// will only ever potentially panic on init and therefore is
		// 100% predictable.
		panic(err)
	}
	return hash
}

// hexDecode decodes the passed hex string and returns the resulting bytes.  It
// panics if an error occurs. This is only provided for the hard-coded constants
// so errors in the source code can be detected. It will only (and must only) be
// called with hard-coded values.
func hexDecode(hexStr string) []byte {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		panic(err)
	}
	return b
}

// hexToBigInt converts the passed hex string into a big integer and will panic
// if there is an error.  This is only provided for the hard-coded constants so
// errors in the source code can be detected. It will only (and must only) be
// called with hard-coded values.
func hexToBigInt(hexStr string) *big.Int {
	val, ok := new(big.Int).SetString(hexStr, 16)
	if !ok {
		panic("failed to parse big integer from hex: " + hexStr)
	}
	return val
}

// BlockOneSubsidy returns the total subsidy of block height 1 for the
// network.
func (p *Params) BlockOneSubsidy() int64 {
	if len(p.BlockOneLedger) == 0 {
		return 0
	}

	sum := int64(0)
	for _, output := range p.BlockOneLedger {
		sum += output.Amount
	}

	return sum
}

// TotalSubsidyProportions is the sum of WorkReward, StakeReward, and BlockTax
// proportions.
func (p *Params) TotalSubsidyProportions() uint16 {
	return p.WorkRewardProportion + p.StakeRewardProportion + p.BlockTaxProportion
}

// LatestCheckpointHeight is the height of the latest checkpoint block in the
// parameters.
func (p *Params) LatestCheckpointHeight() int64 {
	if len(p.Checkpoints) == 0 {
		return 0
	}
	return p.Checkpoints[len(p.Checkpoints)-1].Height
}

// PiKeyExists returns true if the provided key is a sanctioned Pi Key.
func (p *Params) PiKeyExists(key []byte) bool {
	for _, v := range p.PiKeys {
		if bytes.Equal(v, key) {
			return true
		}
	}
	return false
}

// Seeders returns the list of HTTP seeders.
func (p *Params) Seeders() []string {
	return p.seeders
}
