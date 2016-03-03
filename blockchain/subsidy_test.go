// Copyright (c) 2013-2015 The btcsuite developers
// Copyright (c) 2015 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain_test

import (
	"testing"

	"github.com/decred/dcrd/blockchain"
	"github.com/decred/dcrd/chaincfg"
)

func TestBlockSubsidy(t *testing.T) {
	mainnet := &chaincfg.MainNetParams
	totalSubsidy := mainnet.BlockOneSubsidy()
	for i := int32(0); ; i++ {
		// Genesis block or first block.
		if i == 0 || i == 1 {
			continue
		}

		if i%mainnet.ReductionInterval == 0 {
			numBlocks := mainnet.ReductionInterval
			// First reduction internal, which is reduction interval - 2
			// to skip the genesis block and block one.
			if i == mainnet.ReductionInterval {
				numBlocks -= 2
			}
			height := i - numBlocks

			work := blockchain.CalcBlockWorkSubsidy(height,
				mainnet.TicketsPerBlock, mainnet)
			stake := blockchain.CalcStakeVoteSubsidy(height, mainnet) *
				int64(mainnet.TicketsPerBlock)
			tax := blockchain.CalcBlockTaxSubsidy(height, mainnet.TicketsPerBlock,
				mainnet)
			if (work + stake + tax) == 0 {
				break
			}
			totalSubsidy += ((work + stake + tax) * int64(numBlocks))

			// First reduction internal, subtract the stake subsidy for
			// blocks before the staking system is enabled.
			if i == mainnet.ReductionInterval {
				totalSubsidy -= stake * int64(mainnet.StakeValidationHeight-2)
			}
		}
	}

	if totalSubsidy != 2099999999800912 {
		t.Errorf("Bad total subsidy; want 2099999999800912, got %v", totalSubsidy)
	}
}
