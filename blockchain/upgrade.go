// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"github.com/decred/dcrd/blockchain/internal/progresslog"
	"github.com/decred/dcrd/blockchain/stake"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/database"
)

// upgradeToVersion2 upgrades a version 1 blockchain to version 2, allowing
// use of the new on-disk ticket database.
func (b *BlockChain) upgradeToVersion2() error {
	log.Infof("Initializing upgrade to database version 2")
	best := b.BestSnapshot()
	progressLogger := progresslog.NewBlockProgressLogger("Upgraded", log)

	// The upgrade is atomic, so there is no need to set the flag that
	// the database is undergoing an upgrade here.  Get the stake node
	// for the genesis block, and then begin connecting stake nodes
	// incrementally.
	err := b.db.Update(func(dbTx database.Tx) error {
		bestStakeNode, errLocal := stake.InitTicketDatabaseState(dbTx,
			b.chainParams)
		if errLocal != nil {
			return errLocal
		}

		parent, errLocal := dbFetchBlockByHeight(dbTx, 0)
		if errLocal != nil {
			return errLocal
		}

		for i := int64(1); i <= best.Height; i++ {
			block, errLocal := dbFetchBlockByHeight(dbTx, i)
			if errLocal != nil {
				return errLocal
			}

			// If we need the tickets, fetch them too.
			var newTickets []chainhash.Hash
			if i >= b.chainParams.StakeEnabledHeight {
				matureHeight := i - int64(b.chainParams.TicketMaturity)
				matureBlock, errLocal := dbFetchBlockByHeight(dbTx, matureHeight)
				if errLocal != nil {
					return errLocal
				}
				for _, stx := range matureBlock.MsgBlock().STransactions {
					if is, _ := stake.IsSStx(stx); is {
						h := stx.TxSha()
						newTickets = append(newTickets, h)
					}
				}
			}

			// Iteratively connect the stake nodes in memory.
			header := block.MsgBlock().Header
			bestStakeNode, errLocal = bestStakeNode.ConnectNode(header,
				ticketsSpentInBlock(block), ticketsRevokedInBlock(block),
				newTickets)
			if errLocal != nil {
				return errLocal
			}

			// Write the top block stake node to the database.
			errLocal = stake.WriteConnectedBestNode(dbTx, bestStakeNode,
				*best.Hash)
			if errLocal != nil {
				return errLocal
			}

			// Write the best block node when we reach it.
			if i == best.Height {
				b.bestNode.stakeNode = bestStakeNode
				b.bestNode.stakeUndoData = bestStakeNode.UndoData()
				b.bestNode.newTickets = newTickets
				b.bestNode.ticketsSpent = ticketsSpentInBlock(block)
				b.bestNode.ticketsRevoked = ticketsRevokedInBlock(block)
			}

			progressLogger.LogBlockHeight(block, parent)
			parent = block
		}

		// Write the new database version.
		b.dbInfo.version = 2
		errLocal = dbPutDatabaseInfo(dbTx, b.dbInfo)
		if errLocal != nil {
			return errLocal
		}

		return nil
	})
	if err != nil {
		return err
	}

	log.Infof("Upgrade to new stake ticket database was successful!")

	return nil
}

// upgradeToVersion3 upgrades a version 2 blockchain to version 3, allowing
// use of the new on-disk vote tallying database.
func (b *BlockChain) upgradeToVersion3() error {
	log.Infof("Initializing upgrade to database version 3")
	best := b.BestSnapshot()
	progressLogger := progresslog.NewBlockProgressLogger("Upgraded", log)

	// The upgrade is atomic, so there is no need to set the flag that
	// the database is undergoing an upgrade here.  Get the stake node
	// for the genesis block, and then begin connecting stake nodes
	// incrementally.
	err := b.db.Update(func(dbTx database.Tx) error {
		bestTally, errLocal := stake.InitVotingDatabaseState(dbTx,
			b.chainParams)
		if errLocal != nil {
			return errLocal
		}

		b.rollingTallyCache, errLocal = stake.InitRollingTallyCache(dbTx,
			b.chainParams)
		if errLocal != nil {
			return errLocal
		}

		parent, errLocal := dbFetchBlockByHeight(dbTx, 0)
		if errLocal != nil {
			return errLocal
		}

		for i := int64(1); i <= best.Height; i++ {
			block, errLocal := dbFetchBlockByHeight(dbTx, i)
			if errLocal != nil {
				return errLocal
			}

			// Iteratively connect the tallies in memory.
			blockSha := block.Sha()
			parentSha := parent.Sha()
			var tally stake.RollingVotingPrefixTally
			tally, errLocal = bestTally.ConnectBlockToTally(b.rollingTallyCache,
				dbTx, *blockSha, *parentSha, uint32(block.Height()),
				voteBitsForVotersInBlock(block), b.chainParams)
			if errLocal != nil {
				return errLocal
			}
			bestTally = &tally

			// Write the top block stake node to the database.
			errLocal = stake.WriteConnectedBlockTally(dbTx, *blockSha,
				uint32(block.Height()), bestTally, b.chainParams)
			if errLocal != nil {
				return errLocal
			}

			// Write the best block node when we reach it.
			if i == best.Height {
				b.bestNode.rollingTally = bestTally
			}

			progressLogger.LogBlockHeight(block, parent)
			parent = block
		}

		// Write the new database version.
		b.dbInfo.version = 3
		errLocal = dbPutDatabaseInfo(dbTx, b.dbInfo)
		if errLocal != nil {
			return errLocal
		}

		return nil
	})
	if err != nil {
		return err
	}

	log.Infof("Upgrade to new vote tallying database was successful!")

	return nil
}

// upgrade applies all possible upgrades to the blockchain database iteratively,
// updating old clients to the newest version.
func (b *BlockChain) upgrade() error {
	if b.dbInfo.version == 1 {
		err := b.upgradeToVersion2()
		if err != nil {
			return err
		}
	}
	if b.dbInfo.version == 2 {
		err := b.upgradeToVersion3()
		if err != nil {
			return err
		}
	}

	return nil
}
