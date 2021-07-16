// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"sync"

	"github.com/decred/dcrd/chaincfg/chainhash"
)

// SpendConsumer represents an indexer dependent on
// spend journal entries.
type SpendConsumer struct {
	id      string
	queryer ChainQueryer
	tipHash *chainhash.Hash
	mtx     sync.Mutex
}

// NewSpendConsumer initializes a spend consumer.
func NewSpendConsumer(id string, tipHash *chainhash.Hash, queryer ChainQueryer) *SpendConsumer {
	return &SpendConsumer{
		id:      id,
		queryer: queryer,
		tipHash: tipHash,
	}
}

// ID returns the identifier of the consumer.
func (s *SpendConsumer) ID() string {
	return s.id
}

// UpdateTip sets the tip of the consumer to the provided hash.
func (s *SpendConsumer) UpdateTip(hash *chainhash.Hash) {
	s.mtx.Lock()
	s.tipHash = hash
	s.mtx.Unlock()
}

// NeedSpendData checks whether the associated spend journal entry
// for the provided block hash will be needed by the indexer.
func (s *SpendConsumer) NeedSpendData(hash *chainhash.Hash) (bool, error) {
	// The indexer does not need spend journal data if it has not
	// been initialized.
	s.mtx.Lock()
	tipHash := s.tipHash
	s.mtx.Unlock()
	if tipHash == nil {
		return false, nil
	}

	tipHeader, err := s.queryer.BlockHeaderByHash(tipHash)
	if err != nil {
		return false, err
	}

	header, err := s.queryer.BlockHeaderByHash(hash)
	if err != nil {
		return false, err
	}

	// The spend consumer does not need the spend journal
	// data associated with the provided block hash if
	// its current tip is below the provided hash.
	if header.Height > tipHeader.Height {
		return false, nil
	}

	// The spend consumer does not need the spend data associated
	// with the provided block hash if the block is not an ancestor
	// of the current tip.
	blockHash := s.queryer.Ancestor(tipHash, int64(header.Height))
	if !blockHash.IsEqual(hash) {
		return false, nil
	}

	return true, nil
}
