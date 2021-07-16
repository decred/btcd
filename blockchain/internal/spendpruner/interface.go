// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package spendpruner

import (
	"github.com/decred/dcrd/chaincfg/chainhash"
)

// SpendConsumer describes the requirements for implementing a spend
// journal consumer.
//
// All functions MUST be safe for concurrent access.
type SpendConsumer interface {
	// ID returns the identifier of the consumer.
	ID() string

	// NeedSpendData checks whether the associated spend journal entry
	// for the provided block hash will be needed by the consumer.
	NeedSpendData(hash *chainhash.Hash) (bool, error)
}

// SpendPurger describes blockchain functionality required by the spend pruner.
//
// All functions MUST be safe for concurrent access.
type SpendPurger interface {
	// RemoveSpendEntry purges the associated spend journal entry of the
	// provided block hash.
	RemoveSpendEntry(blockHash *chainhash.Hash) error
}
