// Copyright (c) 2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package rpcserver

import (
	"context"
	"math/big"
	"net"
	"time"

	"github.com/decred/dcrd/addrmgr"
	"github.com/decred/dcrd/blockchain/stake/v4"
	"github.com/decred/dcrd/blockchain/v4"
	"github.com/decred/dcrd/blockchain/v4/indexers"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/database/v2"
	"github.com/decred/dcrd/dcrutil/v4"
	"github.com/decred/dcrd/gcs/v3"
	"github.com/decred/dcrd/internal/mempool"
	"github.com/decred/dcrd/internal/mining"
	"github.com/decred/dcrd/peer/v2"
	"github.com/decred/dcrd/rpc/jsonrpc/types/v3"
	"github.com/decred/dcrd/wire"
)

// Peer represents a peer for use with the RPC server.
//
// The interface contract requires that all of these methods are safe for
// concurrent access.
type Peer interface {
	// Addr returns the peer address.
	Addr() string

	// Connected returns whether or not the peer is currently connected.
	Connected() bool

	// ID returns the peer id.
	ID() int32

	// Inbound returns whether the peer is inbound.
	Inbound() bool

	// StatsSnapshot returns a snapshot of the current peer flags and statistics.
	StatsSnapshot() *peer.StatsSnap

	// LocalAddr returns the local address of the connection or nil if the peer
	// is not currently connected.
	LocalAddr() net.Addr

	// LastPingNonce returns the last ping nonce of the remote peer.
	LastPingNonce() uint64

	// IsTxRelayDisabled returns whether or not the peer has disabled
	// transaction relay.
	IsTxRelayDisabled() bool
}

// AddrManager represents an address manager for use with the RPC server.
//
// The interface contract requires that all of these methods are safe for
// concurrent access.
type AddrManager interface {
	// LocalAddresses returns a summary of local addresses information for
	// the getnetworkinfo rpc.
	LocalAddresses() []addrmgr.LocalAddr
}

// ConnManager represents a connection manager for use with the RPC server.
//
// The interface contract requires that all of these methods are safe for
// concurrent access.
type ConnManager interface {
	// Connect adds the provided address as a new outbound peer.  The
	// permanent flag indicates whether or not to make the peer persistent
	// and reconnect if the connection is lost.  Attempting to connect to an
	// already existing peer will return an error.
	Connect(addr string, permanent bool) error

	// RemoveByID removes the peer associated with the provided id from the
	// list of persistent peers.  Attempting to remove an id that does not
	// exist will return an error.
	RemoveByID(id int32) error

	// RemoveByAddr removes the peer associated with the provided address
	// from the list of persistent peers.  Attempting to remove an address
	// that does not exist will return an error.
	RemoveByAddr(addr string) error

	// DisconnectByID disconnects the peer associated with the provided id.
	// This applies to both inbound and outbound peers.  Attempting to
	// remove an id that does not exist will return an error.
	DisconnectByID(id int32) error

	// DisconnectByAddr disconnects the peer associated with the provided
	// address.  This applies to both inbound and outbound peers.
	// Attempting to remove an address that does not exist will return an
	// error.
	DisconnectByAddr(addr string) error

	// ConnectedCount returns the number of currently connected peers.
	ConnectedCount() int32

	// NetTotals returns the sum of all bytes received and sent across the
	// network for all peers.
	NetTotals() (uint64, uint64)

	// ConnectedPeers returns an array consisting of all connected peers.
	ConnectedPeers() []Peer

	// PersistentPeers returns an array consisting of all the persistent
	// peers.
	PersistentPeers() []Peer

	// BroadcastMessage sends the provided message to all currently
	// connected peers.
	BroadcastMessage(msg wire.Message)

	// AddRebroadcastInventory adds the provided inventory to the list of
	// inventories to be rebroadcast at random intervals until they show up
	// in a block.
	AddRebroadcastInventory(iv *wire.InvVect, data interface{})

	// RelayTransactions generates and relays inventory vectors for all of
	// the passed transactions to all connected peers.
	RelayTransactions(txns []*dcrutil.Tx)

	// AddedNodeInfo returns information describing persistent (added) nodes.
	AddedNodeInfo() []Peer

	// Lookup defines the DNS lookup function to be used.
	Lookup(host string) ([]net.IP, error)
}

// SyncManager represents a sync manager for use with the RPC server.
//
// The interface contract requires that all of these methods are safe for
// concurrent access.
type SyncManager interface {
	// IsCurrent returns whether or not the sync manager believes the chain
	// is current as compared to the rest of the network.
	IsCurrent() bool

	// SubmitBlock submits the provided block to the network after
	// processing it locally.
	SubmitBlock(block *dcrutil.Block, flags blockchain.BehaviorFlags) (bool, error)

	// SyncPeerID returns the id of the current peer being synced with.
	SyncPeerID() int32

	// SyncHeight returns latest known block being synced to.
	SyncHeight() int64

	// ProcessTransaction relays the provided transaction validation and
	// insertion into the memory pool.
	ProcessTransaction(tx *dcrutil.Tx, allowOrphans bool, rateLimit bool,
		allowHighFees bool, tag mempool.Tag) ([]*dcrutil.Tx, error)
}

// UtxoEntry represents a utxo entry for use with the RPC server.
//
// The interface contract does NOT require that these methods are safe for
// concurrent access.
type UtxoEntry interface {
	// ToUtxoEntry returns the underlying UtxoEntry instance.
	ToUtxoEntry() *blockchain.UtxoEntry

	// TransactionType returns the type of the transaction that the output is
	// contained in.
	TransactionType() stake.TxType

	// IsSpent returns whether or not the output has been spent based upon the
	// current state of the unspent transaction output view it was obtained from.
	IsSpent() bool

	// BlockHeight returns the height of the block containing the output.
	BlockHeight() int64

	// Amount returns the amount of the output.
	Amount() int64

	// ScriptVersion returns the public key script version for the output.
	ScriptVersion() uint16

	// PkScript returns the public key script for the output.
	PkScript() []byte

	// IsCoinBase returns whether or not the output was contained in a coinbase
	// transaction.
	IsCoinBase() bool

	// TicketMinimalOutputs returns the minimal outputs for the ticket transaction
	// that the output is contained in.  Note that the ticket minimal outputs are
	// only stored in ticket submission outputs and nil will be returned for all
	// other output types.
	TicketMinimalOutputs() []*stake.MinimalOutput
}

// Chain represents a chain for use with the RPC server.
//
// The interface contract requires that all of these methods are safe for
// concurrent access.
type Chain interface {
	// BestSnapshot returns information about the current best chain block and
	// related state as of the current point in time.  The returned instance must be
	// treated as immutable since it is shared by all callers.
	BestSnapshot() *blockchain.BestState

	// BestHeader returns the header with the most cumulative work that is NOT
	// known to be invalid.
	BestHeader() (chainhash.Hash, int64)

	// BlockByHash returns the block for the given hash, regardless of whether the
	// block is part of the main chain or not.
	BlockByHash(hash *chainhash.Hash) (*dcrutil.Block, error)

	// BlockByHeight returns the block at the given height in the main chain.
	BlockByHeight(height int64) (*dcrutil.Block, error)

	// BlockHashByHeight returns the hash of the block at the given height in the
	// main chain.
	BlockHashByHeight(height int64) (*chainhash.Hash, error)

	// BlockHeightByHash returns the height of the block with the given hash in the
	// main chain.
	BlockHeightByHash(hash *chainhash.Hash) (int64, error)

	// CalcWantHeight calculates the height of the final block of the previous
	// interval given a block height.
	CalcWantHeight(interval, height int64) int64

	// ChainTips returns information, in JSON-RPC format, about all of the currently
	// known chain tips in the block index.
	ChainTips() []blockchain.ChainTipInfo

	// ChainWork returns the total work up to and including the block of the
	// provided block hash.
	ChainWork(hash *chainhash.Hash) (*big.Int, error)

	// CheckExpiredTicket returns whether or not a ticket was ever expired.
	CheckExpiredTickets(hashes []chainhash.Hash) []bool

	// CheckLiveTicket returns whether or not a ticket exists in the live ticket
	// treap of the best node.
	CheckLiveTicket(hash chainhash.Hash) bool

	// CheckLiveTickets returns a slice of bools representing whether each ticket
	// exists in the live ticket treap of the best node.
	CheckLiveTickets(hashes []chainhash.Hash) []bool

	// CheckMissedTickets returns a slice of bools representing whether each ticket
	// hash has been missed in the live ticket treap of the best node.
	CheckMissedTickets(hashes []chainhash.Hash) []bool

	// CountVoteVersion returns the total number of version votes for the current
	// rule change activation interval.
	CountVoteVersion(version uint32) (uint32, error)

	// EstimateNextStakeDifficulty estimates the next stake difficulty by pretending
	// the provided number of tickets will be purchased in the remainder of the
	// interval unless the flag to use max tickets is set in which case it will use
	// the max possible number of tickets that can be purchased in the remainder of
	// the interval.
	EstimateNextStakeDifficulty(hash *chainhash.Hash, newTickets int64, useMaxTickets bool) (int64, error)

	// FetchUtxoEntry loads and returns the requested unspent transaction output
	// from the point of view of the main chain tip.
	//
	// NOTE: Requesting an output for which there is no data will NOT return an
	// error.  Instead both the entry and the error will be nil.  This is done to
	// allow pruning of spent transaction outputs.  In practice this means the
	// caller must check if the returned entry is nil before invoking methods on it.
	//
	// This function is safe for concurrent access however the returned entry (if
	// any) is NOT.
	FetchUtxoEntry(outpoint wire.OutPoint) (UtxoEntry, error)

	// FetchUtxoStats returns statistics on the current utxo set.
	FetchUtxoStats() (*blockchain.UtxoStats, error)

	// GetStakeVersions returns a cooked array of StakeVersions.  We do this in
	// order to not bloat memory by returning raw blocks.
	GetStakeVersions(hash *chainhash.Hash, count int32) ([]blockchain.StakeVersions, error)

	// GetVoteCounts returns the vote counts for the specified version and
	// deployment identifier for the current rule change activation interval.
	GetVoteCounts(version uint32, deploymentID string) (blockchain.VoteCounts, error)

	// GetVoteInfo returns information on consensus deployment agendas
	// and their respective states at the provided hash, for the provided
	// deployment version.
	GetVoteInfo(hash *chainhash.Hash, version uint32) (*blockchain.VoteInfo, error)

	// HeaderByHash returns the block header identified by the given hash or an
	// error if it doesn't exist.  Note that this will return headers from both the
	// main chain and any side chains.
	HeaderByHash(hash *chainhash.Hash) (wire.BlockHeader, error)

	// HeaderByHeight returns the block header at the given height in the main
	// chain.
	HeaderByHeight(height int64) (wire.BlockHeader, error)

	// HeightRange returns a range of block hashes for the given start and end
	// heights.  It is inclusive of the start height and exclusive of the end
	// height.  In other words, it is the half open range [startHeight, endHeight).
	//
	// The end height will be limited to the current main chain height.
	HeightRange(startHeight, endHeight int64) ([]chainhash.Hash, error)

	// IsCurrent returns whether or not the chain believes it is current.  Several
	// factors are used to guess, but the key factors that allow the chain to
	// believe it is current are:
	//  - Total amount of cumulative work is more than the minimum known work
	//    specified by the parameters for the network
	//  - Latest block has a timestamp newer than 24 hours ago
	IsCurrent() bool

	// LiveTickets returns all currently live tickets.
	LiveTickets() ([]chainhash.Hash, error)

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
	LocateHeaders(locator blockchain.BlockLocator, hashStop *chainhash.Hash) []wire.BlockHeader

	// LotteryDataForBlock returns lottery data for a given block in the block
	// chain, including side chain blocks.
	LotteryDataForBlock(hash *chainhash.Hash) ([]chainhash.Hash, int, [6]byte, error)

	// MainChainHasBlock returns whether or not the block with the given hash is in
	// the main chain.
	MainChainHasBlock(hash *chainhash.Hash) bool

	// MaxBlockSize returns the maximum permitted block size for the block AFTER
	// the provided block hash.
	MaxBlockSize(hash *chainhash.Hash) (int64, error)

	// MissedTickets returns all currently missed tickets.
	MissedTickets() ([]chainhash.Hash, error)

	// NextThresholdState returns the current rule change threshold state of the
	// given deployment ID for the block AFTER the provided block hash.
	NextThresholdState(hash *chainhash.Hash, version uint32, deploymentID string) (blockchain.ThresholdStateTuple, error)

	// StateLastChangedHeight returns the height at which the provided consensus
	// deployment agenda last changed state.  Note that, unlike the
	// NextThresholdState function, this function returns the information as of the
	// passed block hash.
	StateLastChangedHeight(hash *chainhash.Hash, version uint32, deploymentID string) (int64, error)

	// TicketPoolValue returns the current value of all the locked funds in the
	// ticket pool.
	TicketPoolValue() (dcrutil.Amount, error)

	// TicketsWithAddress returns a slice of ticket hashes that are currently
	// live corresponding to the given address.
	TicketsWithAddress(address dcrutil.Address, isTreasuryEnabled bool) ([]chainhash.Hash, error)

	// TipGeneration returns the entire generation of blocks stemming from the
	// parent of the current tip.
	TipGeneration() ([]chainhash.Hash, error)

	// TreasuryBalance returns the treasury balance at the provided block.
	TreasuryBalance(*chainhash.Hash) (*blockchain.TreasuryBalanceInfo, error)

	// IsTreasuryAgendaActive returns whether or not the treasury agenda vote, as
	// defined in DCP0006, has passed and is now active for the block AFTER the
	// given block.
	IsTreasuryAgendaActive(*chainhash.Hash) (bool, error)

	// FetchTSpend returns all blocks where the treasury spend tx
	// identified by the specified hash can be found.
	FetchTSpend(chainhash.Hash) ([]chainhash.Hash, error)

	// TSpendCountVotes returns the votes for the specified tspend up to
	// the specified block.
	TSpendCountVotes(*chainhash.Hash, *dcrutil.Tx) (int64, int64, error)

	// InvalidateBlock manually invalidates the provided block as if the block
	// had violated a consensus rule and marks all of its descendants as having
	// a known invalid ancestor.  It then reorganizes the chain as necessary so
	// the branch with the most cumulative proof of work that is still valid
	// becomes the main chain.
	InvalidateBlock(*chainhash.Hash) error

	// ReconsiderBlock removes the known invalid status of the provided block
	// and all of its ancestors along with the known invalid ancestor status
	// from all of its descendants that are neither themselves marked as having
	// failed validation nor descendants of another such block.  Therefore, it
	// allows the affected blocks to be reconsidered under the current consensus
	// rules.  It then potentially reorganizes the chain as necessary so the
	// block with the most cumulative proof of work that is valid becomes the
	// tip of the main chain.
	ReconsiderBlock(*chainhash.Hash) error
}

// Clock represents a clock for use with the RPC server. The purpose of this
// interface is to allow an alternative implementation to be used for testing.
//
// The interface contract requires that all of these methods are safe for
// concurrent access.
type Clock interface {
	// Now returns the current local time.
	Now() time.Time

	// Since returns the time elapsed since t.
	Since(t time.Time) time.Duration
}

// FeeEstimator provides an interface that tracks historical data for published
// and mined transactions in order to estimate fees to be used in new
// transactions for confirmation within a target block window.
//
// The interface contract requires that all of these methods are safe for
// concurrent access.
type FeeEstimator interface {
	// EstimateFee calculates the suggested fee for a transaction to be
	// confirmed in at most `targetConfs` blocks after publishing with a
	// high degree of certainty.
	EstimateFee(targetConfs int32) (dcrutil.Amount, error)
}

// LogManager represents a log manager for use with the RPC server.
//
// The interface contract does NOT require that these methods are safe for
// concurrent access.
type LogManager interface {
	// SupportedSubsystems returns a sorted slice of the supported subsystems for
	// logging purposes.
	SupportedSubsystems() []string

	// ParseAndSetDebugLevels attempts to parse the specified debug level and set
	// the levels accordingly.  An appropriate error must be returned if anything
	// is invalid.
	ParseAndSetDebugLevels(debugLevel string) error
}

// SanityChecker represents a block sanity checker for use with the RPC server.
//
// The interface contract requires that all of these methods are safe for
// concurrent access.
type SanityChecker interface {
	// CheckBlockSanity checks the correctness of the provided block
	// per consensus.
	CheckBlockSanity(block *dcrutil.Block) error
}

// CPUMiner represents a CPU miner for use with the RPC server. The purpose of
// this interface is to allow an alternative implementation to be used for
// testing.
//
// The interface contract requires that all of these methods are safe for
// concurrent access.
type CPUMiner interface {
	// GenerateNBlocks generates the requested number of blocks.
	GenerateNBlocks(ctx context.Context, n uint32) ([]*chainhash.Hash, error)

	// IsMining returns whether or not the CPU miner has been started and is
	// therefore currently mining.
	IsMining() bool

	// HashesPerSecond returns the number of hashes per second the mining process
	// is performing.
	HashesPerSecond() float64

	// NumWorkers returns the number of workers which are running to solve blocks.
	NumWorkers() int32

	// SetNumWorkers sets the number of workers to create which solve blocks.
	SetNumWorkers(numWorkers int32)
}

// TemplaterSubber represents a block template subscription.
//
// The interface contract requires that all these methods are safe for
// concurrent access.
type TemplateSubber interface {
	// C returns a channel that produces a stream of block templates as
	// each new template is generated.
	C() <-chan *mining.TemplateNtfn

	// Stop prevents any future template updates from being delivered and
	// unsubscribes the associated subscription.
	Stop()
}

// BlockTemplater represents a source of block templates for use with the
// RPC server.
//
// The interface contract requires that all of these methods are safe for
// concurrent access.
type BlockTemplater interface {
	// ForceRegen asks the block templater to generate a new template immediately.
	ForceRegen()

	// Subscribe subscribes a client for block template updates.  The returned
	// template subscription contains functions to retrieve a channel that produces
	// the stream of block templates and to stop the stream when the caller no
	// longer wishes to receive new templates.
	Subscribe() TemplateSubber

	// CurrentTemplate returns the current template associated with the block
	// templater along with any associated error.
	CurrentTemplate() (*mining.BlockTemplate, error)

	// UpdateBlockTime updates the timestamp in the passed header to the current
	// time while taking into account the consensus rules.
	UpdateBlockTime(header *wire.BlockHeader) error
}

// FiltererV2 provides an interface for retrieving a block's version 2 GCS
// filter.
//
// The interface contract requires that all of these methods are safe for
// concurrent access.
type FiltererV2 interface {
	// FilterByBlockHash returns the version 2 GCS filter for the given block
	// hash when it exists.  This function returns the filters regardless of
	// whether or not their associated block is part of the main chain.
	//
	// An error of type blockchain.ErrNoFilter must be returned when the filter
	// for the given block hash does not exist.
	FilterByBlockHash(hash *chainhash.Hash) (*gcs.FilterV2, error)
}

// ExistsAddresser represents a source of exists address methods for the RPC
// server. These methods return whether or not an address or addresses have
// been seen on the blockchain.
//
// The interface contract requires that all of these methods are safe for
// concurrent access.
//
// ExistsAddresser may be nil. The RPC server must check for the presence of an
// ExistsAddresser before calling methods associated with it.
type ExistsAddresser interface {
	// ExistsAddress returns whether or not an address has been seen before.
	ExistsAddress(addr dcrutil.Address) (bool, error)

	// ExistsAddresses returns whether or not each address in a slice of
	// addresses has been seen before.
	ExistsAddresses(addrs []dcrutil.Address) ([]bool, error)
}

// TxMempooler represents a source of mempool transaction data for the RPC
// server. Methods assume the existence of a main pool and an orphans pool.
//
// The interface contract requires that all of these methods are safe for
// concurrent access.
type TxMempooler interface {
	// HaveTransactions returns whether or not the passed transactions
	// already exist in the main pool or in the orphan pool.
	HaveTransactions(hashes []*chainhash.Hash) []bool

	// TxDescs returns a slice of descriptors for all the transactions in
	// the pool. The descriptors must be treated as read only.
	TxDescs() []*mempool.TxDesc

	// VerboseTxDescs returns a slice of verbose descriptors for all the
	// transactions in the pool. The descriptors must be treated as read
	// only.
	VerboseTxDescs() []*mempool.VerboseTxDesc

	// Count returns the number of transactions in the main pool. It does
	// not include the orphan pool.
	Count() int

	// FetchTransaction returns the requested transaction from the
	// transaction pool. This only fetches from the main transaction pool
	// and does not include orphans.
	FetchTransaction(txHash *chainhash.Hash) (*dcrutil.Tx, error)

	// TSpendHashes returns the hashes of the treasury spend transactions
	// currently in the mempool.
	TSpendHashes() []chainhash.Hash
}

// AddrIndexer provides an interface for retrieving transactions for a given
// address.
//
// The interface contract requires that all of these methods are safe for
// concurrent access.
type AddrIndexer interface {
	// EntriesForAddress returns a slice of details which identify each transaction,
	// including a block region, that involves the passed address according to the
	// specified number to skip, number requested, and whether or not the results
	// should be reversed.  It also returns the number actually skipped since it
	// could be less in the case where there are not enough entries.
	//
	// NOTE: These results only include transactions confirmed in blocks.  See the
	// UnconfirmedTxnsForAddress method for obtaining unconfirmed transactions
	// that involve a given address.
	EntriesForAddress(dbTx database.Tx, addr dcrutil.Address, numToSkip,
		numRequested uint32, reverse bool) ([]indexers.TxIndexEntry, uint32, error)

	// UnconfirmedTxnsForAddress returns all transactions currently in the
	// unconfirmed (memory-only) address index that involve the passed address.
	// Unsupported address types are ignored and will result in no results.
	UnconfirmedTxnsForAddress(addr dcrutil.Address) []*dcrutil.Tx
}

// TxIndexer provides an interface for retrieving details for a given
// transaction hash.
//
// The interface contract requires that all of these methods are safe for
// concurrent access.
type TxIndexer interface {
	// Entry returns details for the provided transaction hash from the transaction
	// index.  The block region contained in the result can in turn be used to load
	// the raw transaction bytes.  When there is no entry for the provided hash, nil
	// must be returned for the both the entry and the error.
	Entry(hash *chainhash.Hash) (*indexers.TxIndexEntry, error)
}

// NtfnManager provides an interface for processing and sending chain
// notifications.
//
// The interface contract requires that all of these methods are safe for
// concurrent access.
type NtfnManager interface {
	// NotifyBlockConnected passes a block newly-connected to the manager
	// for processing.
	NotifyBlockConnected(block *dcrutil.Block)

	// NotifyBlockDisconnected passes a block disconnected to the manager
	// for processing.
	NotifyBlockDisconnected(block *dcrutil.Block)

	// NotifyWork passes new mining work to the manager for processing.
	NotifyWork(templateNtfn *mining.TemplateNtfn)

	// NotifyTSpend passes new tspends to the manager for processing.
	NotifyTSpend(tx *dcrutil.Tx)

	// NotifyReorganization passes a blockchain reorganization notification to
	// the manager for processing.
	NotifyReorganization(rd *blockchain.ReorganizationNtfnsData)

	// NotifyWinningTickets passes newly winning tickets to the manager for
	// processing.
	NotifyWinningTickets(wtnd *WinningTicketsNtfnData)

	// NotifySpentAndMissedTickets passes ticket spend and missing data for an
	// incoming block to the manager for processing.
	NotifySpentAndMissedTickets(tnd *blockchain.TicketNotificationsData)

	// NotifyNewTickets passes a new ticket data for an incoming block to the
	// manager for processing.
	NotifyNewTickets(tnd *blockchain.TicketNotificationsData)

	// NotifyMempoolTx passes a transaction accepted by mempool to the
	// manager for processing.
	NotifyMempoolTx(tx *dcrutil.Tx, isNew bool)

	// NumClients returns the number of clients actively being served.
	NumClients() int

	// RegisterBlockUpdates requests block update notifications to the passed
	// websocket client.
	RegisterBlockUpdates(wsc *wsClient)

	// UnregisterBlockUpdates removes block update notifications for the passed
	// websocket client.
	UnregisterBlockUpdates(wsc *wsClient)

	// RegisterWorkUpdates requests work update notifications to the passed
	// websocket client.
	RegisterWorkUpdates(wsc *wsClient)

	// UnregisterWorkUpdates removes work update notifications for the passed
	// websocket client.
	UnregisterWorkUpdates(wsc *wsClient)

	// RegisterTSpendUpdates requests tspend update notifications to the passed
	// websocket client.
	RegisterTSpendUpdates(wsc *wsClient)

	// UnregisterTSpendUpdates removes tspend update notifications for the passed
	// websocket client.
	UnregisterTSpendUpdates(wsc *wsClient)

	// RegisterWinningTickets requests winning tickets update notifications
	// to the passed websocket client.
	RegisterWinningTickets(wsc *wsClient)

	// UnregisterWinningTickets removes winning ticket notifications for
	// the passed websocket client.
	UnregisterWinningTickets(wsc *wsClient)

	// RegisterSpentAndMissedTickets requests spent/missed tickets update notifications
	// to the passed websocket client.
	RegisterSpentAndMissedTickets(wsc *wsClient)

	// UnregisterSpentAndMissedTickets removes spent/missed ticket notifications for
	// the passed websocket client.
	UnregisterSpentAndMissedTickets(wsc *wsClient)

	// RegisterNewTickets requests spent/missed tickets update notifications
	// to the passed websocket client.
	RegisterNewTickets(wsc *wsClient)

	// UnregisterNewTickets removes spent/missed ticket notifications for
	// the passed websocket client.
	UnregisterNewTickets(wsc *wsClient)

	// RegisterNewMempoolTxsUpdates requests notifications to the passed websocket
	// client when new transactions are added to the memory pool.
	RegisterNewMempoolTxsUpdates(wsc *wsClient)

	// UnregisterNewMempoolTxsUpdates removes notifications to the passed websocket
	// client when new transaction are added to the memory pool.
	UnregisterNewMempoolTxsUpdates(wsc *wsClient)

	// AddClient adds the passed websocket client to the notification manager.
	AddClient(wsc *wsClient)

	// RemoveClient removes the passed websocket client and all notifications
	// registered for it.
	RemoveClient(wsc *wsClient)

	// Run starts the goroutines required for the manager to queue and process
	// websocket client notifications. It blocks until the provided context is
	// cancelled.
	Run(ctx context.Context)
}

// RPCHelpCacher represents a cacher that provides help and usage text for RPC
// server commands and caches the results.
//
// The interface contract requires that all of these methods are safe for
// concurrent access.
type RPCHelpCacher interface {
	// RPCMethodHelp returns an RPC help string for the provided method.
	RPCMethodHelp(method types.Method) (string, error)

	// RPCUsage returns one-line usage for all supported RPC commands.
	RPCUsage(includeWebsockets bool) (string, error)
}
