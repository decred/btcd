// Copyright (c) 2017 The btcsuite developers
// Copyright (c) 2015-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/decred/dcrd/blockchain/v4"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/dcrutil/v4"
	"github.com/decred/dcrd/internal/mempool"
	"github.com/decred/dcrd/internal/mining"
	"github.com/decred/dcrd/internal/mining/cpuminer"
	"github.com/decred/dcrd/internal/netsync"
	"github.com/decred/dcrd/internal/rpcserver"
	"github.com/decred/dcrd/peer/v3"
	"github.com/decred/dcrd/wire"
)

// rpcPeer provides a peer for use with the RPC server and implements the
// rpcserver.Peer interface.
type rpcPeer serverPeer

// Ensure rpcPeer implements the rpcserver.Peer interface.
var _ rpcserver.Peer = (*rpcPeer)(nil)

// Addr returns the peer address.
//
// This function is safe for concurrent access and is part of the rpcserver.Peer
// interface implementation.
func (p *rpcPeer) Addr() string {
	return (*serverPeer)(p).Peer.Addr()
}

// Connected returns whether or not the peer is currently connected.
//
// This function is safe for concurrent access and is part of the rpcserver.Peer
// interface implementation.
func (p *rpcPeer) Connected() bool {
	return (*serverPeer)(p).Peer.Connected()
}

// ID returns the peer id.
//
// This function is safe for concurrent access and is part of the rpcserver.Peer
// interface implementation.
func (p *rpcPeer) ID() int32 {
	return (*serverPeer)(p).Peer.ID()
}

// Inbound returns whether the peer is inbound.
//
// This function is safe for concurrent access and is part of the rpcserver.Peer
// interface implementation.
func (p *rpcPeer) Inbound() bool {
	return (*serverPeer)(p).Peer.Inbound()
}

// StatsSnapshot returns a snapshot of the current peer flags and statistics.
//
// This function is safe for concurrent access and is part of the rpcserver.Peer
// interface implementation.
func (p *rpcPeer) StatsSnapshot() *peer.StatsSnap {
	return (*serverPeer)(p).Peer.StatsSnapshot()
}

// LocalAddr returns the local address of the connection or nil if the peer is
// not currently connected.
//
// This function is safe for concurrent access and is part of the rpcserver.Peer
// interface implementation.
func (p *rpcPeer) LocalAddr() net.Addr {
	return (*serverPeer)(p).Peer.LocalAddr()
}

// LastPingNonce returns the last ping nonce of the remote peer.
//
// This function is safe for concurrent access and is part of the rpcserver.Peer
// interface implementation.
func (p *rpcPeer) LastPingNonce() uint64 {
	return (*serverPeer)(p).Peer.LastPingNonce()
}

// IsTxRelayDisabled returns whether or not the peer has disabled transaction
// relay.
//
// This function is safe for concurrent access and is part of the rpcserver.Peer
// interface implementation.
func (p *rpcPeer) IsTxRelayDisabled() bool {
	return (*serverPeer)(p).relayTxDisabled()
}

// BanScore returns the current integer value that represents how close the peer
// is to being banned.
//
// This function is safe for concurrent access and is part of the rpcserver.Peer
// interface implementation.
func (p *rpcPeer) BanScore() uint32 {
	return (*serverPeer)(p).banScore.Int()
}

// rpcConnManager provides a connection manager for use with the RPC server and
// implements the rpcserver.ConnManager interface.
type rpcConnManager struct {
	server *server
}

// Ensure rpcConnManager implements the rpcserver.ConnManager interface.
var _ rpcserver.ConnManager = (*rpcConnManager)(nil)

// Connect adds the provided address as a new outbound peer.  The permanent flag
// indicates whether or not to make the peer persistent and reconnect if the
// connection is lost.  Attempting to connect to an already existing peer will
// return an error.
//
// This function is safe for concurrent access and is part of the
// rpcserver.ConnManager interface implementation.
func (cm *rpcConnManager) Connect(addr string, permanent bool) error {
	replyChan := make(chan error)
	cm.server.query <- connectNodeMsg{
		addr:      addr,
		permanent: permanent,
		reply:     replyChan,
	}
	return <-replyChan
}

// RemoveByID removes the peer associated with the provided id from the list of
// persistent peers.  Attempting to remove an id that does not exist will return
// an error.
//
// This function is safe for concurrent access and is part of the
// rpcserver.ConnManager interface implementation.
func (cm *rpcConnManager) RemoveByID(id int32) error {
	replyChan := make(chan error)
	cm.server.query <- removeNodeMsg{
		cmp:   func(sp *serverPeer) bool { return sp.ID() == id },
		reply: replyChan,
	}
	return <-replyChan
}

// RemoveByAddr removes the peer associated with the provided address from the
// list of persistent peers.  Attempting to remove an address that does not
// exist will return an error.
//
// This function is safe for concurrent access and is part of the
// rpcserver.ConnManager interface implementation.
func (cm *rpcConnManager) RemoveByAddr(addr string) error {
	replyChan := make(chan error)
	cm.server.query <- removeNodeMsg{
		cmp:   func(sp *serverPeer) bool { return sp.Addr() == addr },
		reply: replyChan,
	}

	// Cancel the connection if it could still be pending.
	err := <-replyChan
	if err != nil {
		cm.server.query <- cancelPendingMsg{
			addr:  addr,
			reply: replyChan,
		}

		return <-replyChan
	}
	return nil
}

// DisconnectByID disconnects the peer associated with the provided id.  This
// applies to both inbound and outbound peers.  Attempting to remove an id that
// does not exist will return an error.
//
// This function is safe for concurrent access and is part of the
// rpcserver.ConnManager interface implementation.
func (cm *rpcConnManager) DisconnectByID(id int32) error {
	replyChan := make(chan error)
	cm.server.query <- disconnectNodeMsg{
		cmp:   func(sp *serverPeer) bool { return sp.ID() == id },
		reply: replyChan,
	}
	return <-replyChan
}

// DisconnectByAddr disconnects the peer associated with the provided address.
// This applies to both inbound and outbound peers.  Attempting to remove an
// address that does not exist will return an error.
//
// This function is safe for concurrent access and is part of the
// rpcserver.ConnManager interface implementation.
func (cm *rpcConnManager) DisconnectByAddr(addr string) error {
	replyChan := make(chan error)
	cm.server.query <- disconnectNodeMsg{
		cmp:   func(sp *serverPeer) bool { return sp.Addr() == addr },
		reply: replyChan,
	}
	return <-replyChan
}

// ConnectedCount returns the number of currently connected peers.
//
// This function is safe for concurrent access and is part of the
// rpcserver.ConnManager interface implementation.
func (cm *rpcConnManager) ConnectedCount() int32 {
	return cm.server.ConnectedCount()
}

// NetTotals returns the sum of all bytes received and sent across the network
// for all peers.
//
// This function is safe for concurrent access and is part of the
// rpcserver.ConnManager interface implementation.
func (cm *rpcConnManager) NetTotals() (uint64, uint64) {
	return cm.server.NetTotals()
}

// ConnectedPeers returns an array consisting of all connected peers.
//
// This function is safe for concurrent access and is part of the
// rpcserver.ConnManager interface implementation.
func (cm *rpcConnManager) ConnectedPeers() []rpcserver.Peer {
	replyChan := make(chan []*serverPeer)
	cm.server.query <- getPeersMsg{reply: replyChan}
	serverPeers := <-replyChan

	// Convert to RPC server peers.
	peers := make([]rpcserver.Peer, 0, len(serverPeers))
	for _, sp := range serverPeers {
		peers = append(peers, (*rpcPeer)(sp))
	}
	return peers
}

// PersistentPeers returns an array consisting of all the added persistent
// peers.
//
// This function is safe for concurrent access and is part of the
// rpcserver.ConnManager interface implementation.
func (cm *rpcConnManager) PersistentPeers() []rpcserver.Peer {
	replyChan := make(chan []*serverPeer)
	cm.server.query <- getAddedNodesMsg{reply: replyChan}
	serverPeers := <-replyChan

	// Convert to generic peers.
	peers := make([]rpcserver.Peer, 0, len(serverPeers))
	for _, sp := range serverPeers {
		peers = append(peers, (*rpcPeer)(sp))
	}
	return peers
}

// BroadcastMessage sends the provided message to all currently connected peers.
//
// This function is safe for concurrent access and is part of the
// rpcserver.ConnManager interface implementation.
func (cm *rpcConnManager) BroadcastMessage(msg wire.Message) {
	cm.server.BroadcastMessage(msg)
}

// AddRebroadcastInventory adds the provided inventory to the list of
// inventories to be rebroadcast at random intervals until they show up in a
// block.
//
// This function is safe for concurrent access and is part of the
// rpcserver.ConnManager interface implementation.
func (cm *rpcConnManager) AddRebroadcastInventory(iv *wire.InvVect, data interface{}) {
	cm.server.AddRebroadcastInventory(iv, data)
}

// RelayTransactions generates and relays inventory vectors for all of the
// passed transactions to all connected peers.
//
// This function is safe for concurrent access and is part of the
// rpcserver.ConnManager interface implementation.
func (cm *rpcConnManager) RelayTransactions(txns []*dcrutil.Tx) {
	cm.server.relayTransactions(txns)
}

// AddedNodeInfo returns information describing persistent (added) nodes.
//
// This function is safe for concurrent access and is part of the
// rpcserver.ConnManager interface implementation.
func (cm *rpcConnManager) AddedNodeInfo() []rpcserver.Peer {
	serverPeers := cm.server.AddedNodeInfo()

	// Convert to RPC server peers.
	peers := make([]rpcserver.Peer, 0, len(serverPeers))
	for _, sp := range serverPeers {
		peers = append(peers, (*rpcPeer)(sp))
	}

	return peers
}

// Lookup defines the DNS lookup function to be used.
//
// This function is safe for concurrent access and is part of the
// rpcserver.ConnManager interface implementation.
func (*rpcConnManager) Lookup(host string) ([]net.IP, error) {
	return cfg.dcrdLookup(host)
}

// rpcSyncMgr provides an adaptor for use with the RPC server and implements the
// rpcserver.SyncManager interface.
type rpcSyncMgr struct {
	server  *server
	syncMgr *netsync.SyncManager
}

// Ensure rpcSyncMgr implements the rpcserver.SyncManager interface.
var _ rpcserver.SyncManager = (*rpcSyncMgr)(nil)

// IsCurrent returns whether or not the net sync manager believes the chain is
// current as compared to the rest of the network.
//
// This function is safe for concurrent access and is part of the
// rpcserver.SyncManager interface implementation.
func (b *rpcSyncMgr) IsCurrent() bool {
	return b.syncMgr.IsCurrent()
}

// SubmitBlock submits the provided block to the network after processing it
// locally.
//
// This function is safe for concurrent access and is part of the
// rpcserver.SyncManager interface implementation.
func (b *rpcSyncMgr) SubmitBlock(block *dcrutil.Block) error {
	return b.syncMgr.ProcessBlock(block, blockchain.BFNone)
}

// SyncPeer returns the id of the current peer being synced with.
//
// This function is safe for concurrent access and is part of the
// rpcserver.SyncManager interface implementation.
func (b *rpcSyncMgr) SyncPeerID() int32 {
	return b.syncMgr.SyncPeerID()
}

// SyncHeight returns latest known block being synced to.
func (b *rpcSyncMgr) SyncHeight() int64 {
	return b.syncMgr.SyncHeight()
}

// ProcessTransaction relays the provided transaction validation and insertion
// into the memory pool.
func (b *rpcSyncMgr) ProcessTransaction(tx *dcrutil.Tx, allowOrphans bool,
	rateLimit bool, allowHighFees bool, tag mempool.Tag) ([]*dcrutil.Tx, error) {
	return b.syncMgr.ProcessTransaction(tx, allowOrphans,
		rateLimit, allowHighFees, tag)
}

// rpcUtxoEntry represents a utxo entry for use with the RPC server and
// implements the rpcserver.UtxoEntry interface.
type rpcUtxoEntry struct {
	*blockchain.UtxoEntry
}

// Ensure rpcUtxoEntry implements the rpcserver.UtxoEntry interface.
var _ rpcserver.UtxoEntry = (*rpcUtxoEntry)(nil)

// ToUtxoEntry returns the underlying UtxoEntry instance.
func (u *rpcUtxoEntry) ToUtxoEntry() *blockchain.UtxoEntry {
	return u.UtxoEntry
}

// rpcChain provides a chain for use with the RPC server and
// implements the rpcserver.Chain interface.
type rpcChain struct {
	*blockchain.BlockChain
}

// Ensure rpcChain implements the rpcserver.Chain interface.
var _ rpcserver.Chain = (*rpcChain)(nil)

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
func (c *rpcChain) FetchUtxoEntry(outpoint wire.OutPoint) (rpcserver.UtxoEntry, error) {
	utxo, err := c.BlockChain.FetchUtxoEntry(outpoint)
	if utxo == nil || err != nil {
		return nil, err
	}
	return &rpcUtxoEntry{UtxoEntry: utxo}, nil
}

// rpcClock provides a clock for use with the RPC server and
// implements the rpcserver.Clock interface.
type rpcClock struct{}

// Ensure rpcClock implements the rpcserver.Clock interface.
var _ rpcserver.Clock = (*rpcClock)(nil)

// Now returns the current local time.
//
// This function is safe for concurrent access and is part of the
// rpcserver.Clock interface implementation.
func (*rpcClock) Now() time.Time {
	return time.Now()
}

// Since returns the time elapsed since t.
//
// This function is safe for concurrent access and is part of the
// rpcserver.Clock interface implementation.
func (*rpcClock) Since(t time.Time) time.Duration {
	return time.Since(t)
}

// rpcLogManager provides a log manager for use with the RPC server and
// implements the rpcserver.LogManager interface.
type rpcLogManager struct{}

// Ensure rpcLogManager implements the rpcserver.LogManager interface.
var _ rpcserver.LogManager = (*rpcLogManager)(nil)

// SupportedSubsystems returns a sorted slice of the supported subsystems for
// logging purposes.
//
// This function is part of the rpcserver.LogManager interface implementation.
func (*rpcLogManager) SupportedSubsystems() []string {
	return supportedSubsystems()
}

// ParseAndSetDebugLevels attempts to parse the specified debug level and set
// the levels accordingly.  An appropriate error is returned if anything is
// invalid.
//
// This function is part of the rpcserver.LogManager interface implementation.
func (*rpcLogManager) ParseAndSetDebugLevels(debugLevel string) error {
	return parseAndSetDebugLevels(debugLevel)
}

// rpcSanityChecker provides a block sanity checker for use with the RPC and
// implements the rpcserver.SanityChecker interface.
type rpcSanityChecker struct {
	chain       *blockchain.BlockChain
	timeSource  blockchain.MedianTimeSource
	chainParams *chaincfg.Params
}

// Ensure rpcSanityChecker implements the rpcserver.SanityChecker interface.
var _ rpcserver.SanityChecker = (*rpcSanityChecker)(nil)

// CheckBlockSanity checks the correctness of the provided block
// per consensus.  An appropriate error is returned if anything is
// invalid.
//
// This function is part of the rpcserver.SanityChecker interface implementation.
func (s *rpcSanityChecker) CheckBlockSanity(block *dcrutil.Block) error {
	return blockchain.CheckBlockSanity(block, s.timeSource, s.chainParams)
}

// rpcBlockTemplater provides a block template generator for use with the
// RPC server and implements the rpcserver.BlockTemplater interface.
type rpcBlockTemplater struct {
	*mining.BgBlkTmplGenerator
}

// Ensure rpcBlockTemplater implements the rpcserver.BlockTemplater interface.
var _ rpcserver.BlockTemplater = (*rpcBlockTemplater)(nil)

// Subscribe returns a TemplateSubber which has functions to retrieve
// a channel that produces the stream of block templates and to stop
// the stream when the caller no longer wishes to receive new templates.
func (t *rpcBlockTemplater) Subscribe() rpcserver.TemplateSubber {
	return t.BgBlkTmplGenerator.Subscribe()
}

// rpcCPUMiner provides a CPU miner for use with the RPC and implements the
// rpcserver.CPUMiner interface.
type rpcCPUMiner struct {
	miner *cpuminer.CPUMiner
}

// Ensure rpcCPUMiner implements the rpcserver.CPUMiner interface.
var _ rpcserver.CPUMiner = (*rpcCPUMiner)(nil)

// GenerateNBlocks generates the requested number of blocks.
func (c *rpcCPUMiner) GenerateNBlocks(ctx context.Context, n uint32) ([]*chainhash.Hash, error) {
	if c.miner == nil {
		return nil, errors.New("Block generation is disallowed without a " +
			"CPU miner.")
	}

	return c.miner.GenerateNBlocks(ctx, n)
}

// IsMining returns whether or not the CPU miner has been started and is
// therefore currently mining.
func (c *rpcCPUMiner) IsMining() bool {
	if c.miner == nil {
		return false
	}

	return c.miner.IsMining()
}

// HashesPerSecond returns the number of hashes per second the mining process
// is performing.
func (c *rpcCPUMiner) HashesPerSecond() float64 {
	if c.miner == nil {
		return 0
	}

	return c.miner.HashesPerSecond()
}

// NumWorkers returns the number of workers which are running to solve blocks.
func (c *rpcCPUMiner) NumWorkers() int32 {
	if c.miner == nil {
		return 0
	}

	return c.miner.NumWorkers()
}

// SetNumWorkers sets the number of workers to create which solve blocks.
func (c *rpcCPUMiner) SetNumWorkers(numWorkers int32) {
	if c.miner != nil {
		c.miner.SetNumWorkers(numWorkers)
	}
}
