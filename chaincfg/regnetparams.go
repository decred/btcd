// Copyright (c) 2018-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chaincfg

import (
	"math"
	"math/big"
	"time"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/wire"
)

// RegNetParams returns the network parameters for the regression test network.
// This should not be confused with the public test network or the simulation
// test network.  The purpose of this network is primarily for unit tests and
// RPC server tests.  On the other hand, the simulation test network is intended
// for full integration tests between different applications such as wallets,
// voting service providers, mining pools, block explorers, and other services
// that build on Decred.
//
// Since this network is only intended for unit testing, its values are subject
// to change even if it would cause a hard fork.
func RegNetParams() *Params {
	// regNetPowLimit is the highest proof of work value a Decred block
	// can have for the regression test network.  It is the value 2^255 - 1.
	regNetPowLimit := new(big.Int).Sub(new(big.Int).Lsh(bigOne, 255), bigOne)

	// genesisBlock defines the genesis block of the block chain which serves as
	// the public transaction ledger for the regression test network.
	genesisBlock := wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:   1,
			PrevBlock: chainhash.Hash{}, // All zero.
			// MerkleRoot: Calculated below.
			StakeRoot:    chainhash.Hash{}, // All zero.
			VoteBits:     0,
			FinalState:   [6]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Voters:       0,
			FreshStake:   0,
			Revocations:  0,
			Timestamp:    time.Unix(1538524800, 0), // 2018-10-03 00:00:00 +0000 UTC
			PoolSize:     0,
			Bits:         0x207fffff, // 545259519 [7fffff0000000000000000000000000000000000000000000000000000000000]
			SBits:        0,
			Nonce:        0,
			StakeVersion: 0,
			Height:       0,
		},
		Transactions: []*wire.MsgTx{{
			SerType: wire.TxSerializeFull,
			Version: 1,
			TxIn: []*wire.TxIn{{
				// Fully null.
				PreviousOutPoint: wire.OutPoint{
					Hash:  chainhash.Hash{},
					Index: 0xffffffff,
					Tree:  0,
				},
				SignatureScript: hexDecode("0000"),
				Sequence:        0xffffffff,
				BlockHeight:     wire.NullBlockHeight,
				BlockIndex:      wire.NullBlockIndex,
				ValueIn:         wire.NullValueIn,
			}},
			TxOut: []*wire.TxOut{{
				Version: 0x0000,
				Value:   0x00000000,
				PkScript: hexDecode("801679e98561ada96caec2949a5d41c4cab3851e" +
					"b740d951c10ecbcf265c1fd9"),
			}},
			LockTime: 0,
			Expiry:   0,
		}},
	}
	genesisBlock.Header.MerkleRoot = genesisBlock.Transactions[0].TxHashFull()

	return &Params{
		Name:        "regnet",
		Net:         wire.RegNet,
		DefaultPort: "18655",
		DNSSeeds:    nil, // NOTE: There must NOT be any seeds.

		// Chain parameters
		GenesisBlock:             &genesisBlock,
		GenesisHash:              genesisBlock.BlockHash(),
		PowLimit:                 regNetPowLimit,
		PowLimitBits:             0x207fffff,
		ReduceMinDifficulty:      false,
		MinDiffReductionTime:     0, // Does not apply since ReduceMinDifficulty false
		GenerateSupported:        true,
		MaximumBlockSizes:        []int{1000000, 1310720},
		MaxTxSize:                1000000,
		TargetTimePerBlock:       time.Second,
		WorkDiffAlpha:            1,
		WorkDiffWindowSize:       8,
		WorkDiffWindows:          4,
		TargetTimespan:           time.Second * 8, // TimePerBlock * WindowSize
		RetargetAdjustmentFactor: 4,

		// Subsidy parameters.
		BaseSubsidy:              50000000000,
		MulSubsidy:               100,
		DivSubsidy:               101,
		SubsidyReductionInterval: 128,
		WorkRewardProportion:     6,
		StakeRewardProportion:    3,
		BlockTaxProportion:       1,

		// Checkpoints ordered from oldest to newest.
		Checkpoints: nil,

		// MinKnownChainWork is the minimum amount of known total work for the
		// chain at a given point in time.
		//
		// Not set for regression test network since its chain is dynamic.
		MinKnownChainWork: nil,

		// Consensus rule change deployments.
		//
		// The miner confirmation window is defined as:
		//   target proof of work timespan / target proof of work spacing
		RuleChangeActivationQuorum:     160, // 10 % of RuleChangeActivationInterval * TicketsPerBlock
		RuleChangeActivationMultiplier: 3,   // 75%
		RuleChangeActivationDivisor:    4,
		RuleChangeActivationInterval:   320, // Full ticket pool -- 320 seconds
		Deployments: map[uint32][]ConsensusDeployment{
			4: {{
				Vote: Vote{
					Id:          VoteIDMaxBlockSize,
					Description: "Change maximum allowed block size from 1MiB to 1.25MB",
					Mask:        0x0006, // Bits 1 and 2
					Choices: []Choice{{
						Id:          "abstain",
						Description: "abstain voting for change",
						Bits:        0x0000,
						IsAbstain:   true,
						IsNo:        false,
					}, {
						Id:          "no",
						Description: "reject changing max allowed block size",
						Bits:        0x0002, // Bit 1
						IsAbstain:   false,
						IsNo:        true,
					}, {
						Id:          "yes",
						Description: "accept changing max allowed block size",
						Bits:        0x0004, // Bit 2
						IsAbstain:   false,
						IsNo:        false,
					}},
				},
				StartTime:  0,             // Always available for vote
				ExpireTime: math.MaxInt64, // Never expires
			}},
			5: {{
				Vote: Vote{
					Id:          VoteIDSDiffAlgorithm,
					Description: "Change stake difficulty algorithm as defined in DCP0001",
					Mask:        0x0006, // Bits 1 and 2
					Choices: []Choice{{
						Id:          "abstain",
						Description: "abstain voting for change",
						Bits:        0x0000,
						IsAbstain:   true,
						IsNo:        false,
					}, {
						Id:          "no",
						Description: "keep the existing algorithm",
						Bits:        0x0002, // Bit 1
						IsAbstain:   false,
						IsNo:        true,
					}, {
						Id:          "yes",
						Description: "change to the new algorithm",
						Bits:        0x0004, // Bit 2
						IsAbstain:   false,
						IsNo:        false,
					}},
				},
				StartTime:  0,             // Always available for vote
				ExpireTime: math.MaxInt64, // Never expires
			}},
			6: {{
				Vote: Vote{
					Id:          VoteIDLNFeatures,
					Description: "Enable features defined in DCP0002 and DCP0003 necessary to support Lightning Network (LN)",
					Mask:        0x0006, // Bits 1 and 2
					Choices: []Choice{{
						Id:          "abstain",
						Description: "abstain voting for change",
						Bits:        0x0000,
						IsAbstain:   true,
						IsNo:        false,
					}, {
						Id:          "no",
						Description: "keep the existing consensus rules",
						Bits:        0x0002, // Bit 1
						IsAbstain:   false,
						IsNo:        true,
					}, {
						Id:          "yes",
						Description: "change to the new consensus rules",
						Bits:        0x0004, // Bit 2
						IsAbstain:   false,
						IsNo:        false,
					}},
				},
				StartTime:  0,             // Always available for vote
				ExpireTime: math.MaxInt64, // Never expires
			}},
			7: {{
				Vote: Vote{
					Id:          VoteIDFixLNSeqLocks,
					Description: "Modify sequence lock handling as defined in DCP0004",
					Mask:        0x0006, // Bits 1 and 2
					Choices: []Choice{{
						Id:          "abstain",
						Description: "abstain voting for change",
						Bits:        0x0000,
						IsAbstain:   true,
						IsNo:        false,
					}, {
						Id:          "no",
						Description: "keep the existing consensus rules",
						Bits:        0x0002, // Bit 1
						IsAbstain:   false,
						IsNo:        true,
					}, {
						Id:          "yes",
						Description: "change to the new consensus rules",
						Bits:        0x0004, // Bit 2
						IsAbstain:   false,
						IsNo:        false,
					}},
				},
				StartTime:  0,             // Always available for vote
				ExpireTime: math.MaxInt64, // Never expires
			}},
			8: {{
				Vote: Vote{
					Id:          VoteIDHeaderCommitments,
					Description: "Enable header commitments as defined in DCP0005",
					Mask:        0x0006, // Bits 1 and 2
					Choices: []Choice{{
						Id:          "abstain",
						Description: "abstain voting for change",
						Bits:        0x0000,
						IsAbstain:   true,
						IsNo:        false,
					}, {
						Id:          "no",
						Description: "keep the existing consensus rules",
						Bits:        0x0002, // Bit 1
						IsAbstain:   false,
						IsNo:        true,
					}, {
						Id:          "yes",
						Description: "change to the new consensus rules",
						Bits:        0x0004, // Bit 2
						IsAbstain:   false,
						IsNo:        false,
					}},
				},
				StartTime:  0,             // Always available for vote
				ExpireTime: math.MaxInt64, // Never expires
			}},
			9: {{
				Vote: Vote{
					Id:          VoteIDTreasury,
					Description: "Enable decentralized Treasury opcodes as defined in DCP0006",
					Mask:        0x0006, // Bits 1 and 2
					Choices: []Choice{{
						Id:          "abstain",
						Description: "abstain voting for change",
						Bits:        0x0000,
						IsAbstain:   true,
						IsNo:        false,
					}, {
						Id:          "no",
						Description: "keep the existing consensus rules",
						Bits:        0x0002, // Bit 1
						IsAbstain:   false,
						IsNo:        true,
					}, {
						Id:          "yes",
						Description: "change to the new consensus rules",
						Bits:        0x0004, // Bit 2
						IsAbstain:   false,
						IsNo:        false,
					}},
				},
				StartTime:  0,             // Always available for vote
				ExpireTime: math.MaxInt64, // Never expires
			}},
			10: {{
				Vote: Vote{
					Id:          VoteIDRevertTreasuryPolicy,
					Description: "",
					Mask:        0x0006, // Bits 1 and 2
					Choices: []Choice{{
						Id:          "abstain",
						Description: "abstain voting for change",
						Bits:        0x0000,
						IsAbstain:   true,
						IsNo:        false,
					}, {
						Id:          "no",
						Description: "keep the existing consensus rules",
						Bits:        0x0002, // Bit 1
						IsAbstain:   false,
						IsNo:        true,
					}, {
						Id:          "yes",
						Description: "change to the new consensus rules",
						Bits:        0x0004, // Bit 2
						IsAbstain:   false,
						IsNo:        false,
					}},
				},
				StartTime:  0,             // Always available for vote
				ExpireTime: math.MaxInt64, // Never expires
			}},
		},

		// Enforce current block version once majority of the network has
		// upgraded.
		// 51% (51 / 100)
		// Reject previous block versions once a majority of the network has
		// upgraded.
		// 75% (75 / 100)
		BlockEnforceNumRequired: 51,
		BlockRejectNumRequired:  75,
		BlockUpgradeNumToCheck:  100,

		// AcceptNonStdTxs is a mempool param to either accept and relay non
		// standard txs to the network or reject them
		AcceptNonStdTxs: true,

		// Address encoding magics
		NetworkAddressPrefix: "R",
		PubKeyAddrID:         [2]byte{0x25, 0xe5}, // starts with Rk
		PubKeyHashAddrID:     [2]byte{0x0e, 0x00}, // starts with Rs
		PKHEdwardsAddrID:     [2]byte{0x0d, 0xe0}, // starts with Re
		PKHSchnorrAddrID:     [2]byte{0x0d, 0xc2}, // starts with RS
		ScriptHashAddrID:     [2]byte{0x0d, 0xdb}, // starts with Rc
		PrivateKeyID:         [2]byte{0x22, 0xfe}, // starts with Pr

		// BIP32 hierarchical deterministic extended key magics
		HDPrivateKeyID: [4]byte{0xea, 0xb4, 0x04, 0x48}, // starts with rprv
		HDPublicKeyID:  [4]byte{0xea, 0xb4, 0xf9, 0x87}, // starts with rpub

		// BIP44 coin type used in the hierarchical deterministic path for
		// address generation.
		SLIP0044CoinType: 1, // SLIP0044, Testnet (all coins)
		LegacyCoinType:   1,

		// Decred PoS parameters
		MinimumStakeDiff:        20000,
		TicketPoolSize:          64,
		TicketsPerBlock:         5,
		TicketMaturity:          16,
		TicketExpiry:            384, // 6*TicketPoolSize
		CoinbaseMaturity:        16,
		SStxChangeMaturity:      1,
		TicketPoolSizeWeight:    4,
		StakeDiffAlpha:          1,
		StakeDiffWindowSize:     8,
		StakeDiffWindows:        8,
		StakeVersionInterval:    8 * 2 * 7,
		MaxFreshStakePerBlock:   20,            // 4*TicketsPerBlock
		StakeEnabledHeight:      16 + 16,       // CoinbaseMaturity + TicketMaturity
		StakeValidationHeight:   16 + (64 * 2), // CoinbaseMaturity + TicketPoolSize*2
		StakeBaseSigScript:      []byte{0x73, 0x57},
		StakeMajorityMultiplier: 3,
		StakeMajorityDivisor:    4,

		// Decred organization related parameters
		//
		// Treasury address is a 3-of-3 P2SH going to a wallet with seed:
		// aardvark adroitness aardvark adroitness
		// aardvark adroitness aardvark adroitness
		// aardvark adroitness aardvark adroitness
		// aardvark adroitness aardvark adroitness
		// aardvark adroitness aardvark adroitness
		// aardvark adroitness aardvark adroitness
		// aardvark adroitness aardvark adroitness
		// aardvark adroitness aardvark adroitness
		// briefcase
		// (seed 0x0000000000000000000000000000000000000000000000000000000000000000)
		//
		// This same wallet owns the three ledger outputs for regnet.
		//
		// P2SH details for regnet treasury:
		//
		// redeemScript: 53210323c1b9aa4facca85df363fb4abd5c52fe2af4746fbb5f99a6d
		// cc2edb633fe2a62103c2d8a61a2800092ddaf04ba30dfc7cf1ab4130ac1d2398ba15fc
		// 795b11bc690621035fe97a7b2d6b98242f4bfc33d86a564158b44634b93cdefa155909
		// 5d4bf6167853ae
		//   (3-of-3 multisig)
		// Pubkeys used:
		//   Rk8J2ZY5CkDLaBbAYqU7fb1Tr6nSwEACJ1j2oWAwuFZ26PyPeMXiB
		//   Rk8KEdGMGJiF27CZ8rw2gDPD7MkVGSPjHinXjtTZhoH8ZQ6UhJvhV
		//   Rk8JV484ePPX6vWZCfBX2Scme5XriXhzwmyaKSYQT64HTbkkfyzL3
		//
		// Organization address is RcQR65gasxuzf7mUeBXeAux6Z37joPuUwUN
		OrganizationPkScript:        hexDecode("a9146913bcc838bd0087fb3f6b3c868423d5e300078d87"),
		OrganizationPkScriptVersion: 0,
		BlockOneLedger:              tokenPayouts_RegNetParams(),

		// Commands to generate regnet Pi keys:
		// $ treasurykey.go -regnet
		// Private key: 68ab7efdac0eb99b1edf83b23374cc7a9c8d0a4183a2627afc8ea0437b20589e
		// Public  key: 03b459ccf3ce4935a676414fd9ec93ecf7c9dad081a52ed6993bf073c627499388
		// WIF        : Pr9CEpLjchr6eiHGySbR1fu3FJb6NW8JHvdQdbkUs2BN7Qi7h6UuQ
		//
		// $ treasurykey.go -regnet
		// Private key: 2527f13f61024c9b9f4b30186f16e0b0af35b08c54ed2ed67def863b447ea11b
		// Public  key: 02e3af1209f4d39dd8b448ef0a5375befa85bbc50be0aa0936379d67444184a2c3
		// WIF        : Pr9Bj5nkQ3DVPeAyiQUrDD4oL6TBmVLeNbFt3CLQurxSi4sFaPXNk
		PiKeys: [][]byte{
			hexDecode("03b459ccf3ce4935a676414fd9ec93ecf7c9dad081a52ed6993bf073c627499388"),
			hexDecode("02e3af1209f4d39dd8b448ef0a5375befa85bbc50be0aa0936379d67444184a2c3"),
		},
		TreasuryVoteInterval:           4, // every 4 blocks for regnet
		TreasuryVoteIntervalMultiplier: 3, // 3 * 4 block Expiry.

		TreasuryExpenditureWindow:    4,         // 4 * 2 * 4 blocks for policy check
		TreasuryExpenditurePolicy:    3,         // Avg of 3*4*2*4 blocks for policy check
		TreasuryExpenditureBootstrap: 100 * 1e8, // 100 dcr/tew as expense bootstrap

		TreasuryVoteQuorumMultiplier:   1, // 20% quorum required
		TreasuryVoteQuorumDivisor:      5,
		TreasuryVoteRequiredMultiplier: 3, // 60% yes votes required
		TreasuryVoteRequiredDivisor:    5,

		seeders: nil, // NOTE: There must NOT be any seeds.
	}
}
