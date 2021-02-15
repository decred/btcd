// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2015-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/decred/dcrd/addrmgr/v2"
	"github.com/decred/dcrd/blockchain/stake/v4"
	"github.com/decred/dcrd/blockchain/standalone/v2"
	"github.com/decred/dcrd/blockchain/v4"
	"github.com/decred/dcrd/blockchain/v4/indexers"
	"github.com/decred/dcrd/certgen"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/connmgr/v3"
	"github.com/decred/dcrd/container/apbf"
	"github.com/decred/dcrd/database/v2"
	"github.com/decred/dcrd/dcrutil/v4"
	"github.com/decred/dcrd/internal/fees"
	"github.com/decred/dcrd/internal/mempool"
	"github.com/decred/dcrd/internal/mining"
	"github.com/decred/dcrd/internal/mining/cpuminer"
	"github.com/decred/dcrd/internal/netsync"
	"github.com/decred/dcrd/internal/rpcserver"
	"github.com/decred/dcrd/internal/version"
	"github.com/decred/dcrd/peer/v3"
	"github.com/decred/dcrd/txscript/v4"
	"github.com/decred/dcrd/wire"
)

const (
	// defaultServices describes the default services that are supported by
	// the server.
	defaultServices = wire.SFNodeNetwork

	// defaultRequiredServices describes the default services that are
	// required to be supported by outbound peers.
	defaultRequiredServices = wire.SFNodeNetwork

	// defaultTargetOutbound is the default number of outbound peers to
	// target.
	defaultTargetOutbound = 8

	// defaultMaximumVoteAge is the threshold of blocks before the tip
	// that can be voted on.
	defaultMaximumVoteAge = 1440

	// connectionRetryInterval is the base amount of time to wait in between
	// retries when connecting to persistent peers.  It is adjusted by the
	// number of retries such that there is a retry backoff.
	connectionRetryInterval = time.Second * 5

	// maxProtocolVersion is the max protocol version the server supports.
	maxProtocolVersion = wire.InitStateVersion

	// These fields are used to track known addresses on a per-peer basis.
	//
	// maxKnownAddrsPerPeer is the maximum number of items to track.
	//
	// knownAddrsFPRate is the false positive rate for the APBF used to track
	// them.  It is set to a rate of 1 per 1000 since addresses are not very
	// large and they only need to be filtered once per connection, so an extra
	// 10 of them being sent (on average) again even though they technically
	// wouldn't need to is a good tradeoff.
	//
	// These values result in about 40 KiB memory usage including overhead.
	maxKnownAddrsPerPeer = 10000
	knownAddrsFPRate     = 0.001

	// maxCachedNaSubmissions is the maximum number of network address
	// submissions cached.
	maxCachedNaSubmissions = 20

	// maxReorgDepthNotify specifies the maximum reorganization depth for which
	// winning ticket notifications will be sent over RPC.  The reorg depth is
	// the number of blocks that would be reorganized out of the current best
	// chain if a side chain being considered for notifications were to
	// ultimately be extended to be longer than the current one.
	//
	// In effect, this helps to prevent large reorgs by refusing to send the
	// winning ticket information to RPC clients, such as voting wallets, which
	// depend on it to cast votes.
	//
	// This check also doubles to help reduce exhaustion attacks that could
	// otherwise arise from sending old orphan blocks and forcing nodes to do
	// expensive lottery data calculations for them.
	maxReorgDepthNotify = 6

	// These fields are used to track recently confirmed transactions.
	//
	// maxRecentlyConfirmedTxns specifies the maximum number to track and is set
	// to target tracking the maximum number transactions of the minimum
	// realistic size (~206 bytes) in approximately one hour of blocks on the
	// main network.
	//
	// recentlyConfirmedTxnsFPRate is the false positive rate for the APBF used
	// to track them and is set to a rate of 1 per 1 million which supports up
	// to ~11.5 transactions/s before a single false positive would be seen on
	// average and thus allows for plenty of future growth.
	//
	// These values result in about 183 KiB memory usage including overhead.
	maxRecentlyConfirmedTxns    = 23000
	recentlyConfirmedTxnsFPRate = 0.000001
)

var (
	// userAgentName is the user agent name and is used to help identify
	// ourselves to other Decred peers.
	userAgentName = "dcrd"

	// userAgentVersion is the user agent version and is used to help
	// identify ourselves to other peers.
	userAgentVersion = fmt.Sprintf("%d.%d.%d", version.Major, version.Minor,
		version.Patch)
)

// simpleAddr implements the net.Addr interface with two struct fields
type simpleAddr struct {
	net, addr string
}

// String returns the address.
//
// This is part of the net.Addr interface.
func (a simpleAddr) String() string {
	return a.addr
}

// Network returns the network.
//
// This is part of the net.Addr interface.
func (a simpleAddr) Network() string {
	return a.net
}

// Ensure simpleAddr implements the net.Addr interface.
var _ net.Addr = simpleAddr{}

// broadcastMsg provides the ability to house a Decred message to be broadcast
// to all connected peers except specified excluded peers.
type broadcastMsg struct {
	message      wire.Message
	excludePeers []*serverPeer
}

// broadcastInventoryAdd is a type used to declare that the InvVect it contains
// needs to be added to the rebroadcast map
type broadcastInventoryAdd relayMsg

// broadcastInventoryDel is a type used to declare that the InvVect it contains
// needs to be removed from the rebroadcast map
type broadcastInventoryDel *wire.InvVect

// broadcastPruneInventory is a type used to declare that rebroadcast
// inventory entries need to be filtered and removed where necessary
type broadcastPruneInventory struct{}

// relayMsg packages an inventory vector along with the newly discovered
// inventory and a flag that determines if the relay should happen immediately
// (it will be put into a trickle queue if false) so the relay has access to
// that information.
type relayMsg struct {
	invVect   *wire.InvVect
	data      interface{}
	immediate bool
}

// naSubmission represents a network address submission from an outbound peer.
type naSubmission struct {
	na           *wire.NetAddress
	netType      addrmgr.NetworkAddress
	reach        int
	score        uint32
	lastAccessed int64
}

// naSubmissionCache represents a bounded map for network address submisions.
type naSubmissionCache struct {
	cache map[string]*naSubmission
	limit int
	mtx   sync.Mutex
}

// add caches the provided address submission.
func (sc *naSubmissionCache) add(sub *naSubmission) error {
	if sub == nil {
		return fmt.Errorf("submission cannot be nil")
	}

	key := sub.na.IP.String()
	if key == "" {
		return fmt.Errorf("submission key cannot be an empty string")
	}

	sc.mtx.Lock()
	defer sc.mtx.Unlock()

	// Remove the oldest submission if cache limit has been reached.
	if len(sc.cache) == sc.limit {
		var oldestSub *naSubmission
		for _, sub := range sc.cache {
			if oldestSub == nil {
				oldestSub = sub
				continue
			}

			if sub.lastAccessed < oldestSub.lastAccessed {
				oldestSub = sub
			}
		}

		if oldestSub != nil {
			delete(sc.cache, oldestSub.na.IP.String())
		}
	}

	sub.score = 1
	sub.lastAccessed = time.Now().Unix()
	sc.cache[key] = sub
	return nil
}

// exists returns true if the provided key exist in the submissions cache.
func (sc *naSubmissionCache) exists(key string) bool {
	if key == "" {
		return false
	}

	sc.mtx.Lock()
	_, ok := sc.cache[key]
	sc.mtx.Unlock()
	return ok
}

// incrementScore increases the score of address submission referenced by
// the provided key by one.
func (sc *naSubmissionCache) incrementScore(key string) error {
	if key == "" {
		return fmt.Errorf("submission key cannot be an empty string")
	}

	sc.mtx.Lock()
	defer sc.mtx.Unlock()

	sub, ok := sc.cache[key]
	if !ok {
		return fmt.Errorf("submission key not found: %s", key)
	}

	sub.score++
	sub.lastAccessed = time.Now().Unix()
	sc.cache[key] = sub
	return nil
}

// bestSubmission fetches the best scoring submission of the provided
// network interface.
func (sc *naSubmissionCache) bestSubmission(net addrmgr.NetworkAddress) *naSubmission {
	sc.mtx.Lock()
	defer sc.mtx.Unlock()

	var best *naSubmission
	for _, sub := range sc.cache {
		if sub.netType != net {
			continue
		}

		if best == nil {
			best = sub
			continue
		}

		if sub.score > best.score {
			best = sub
		}
	}

	return best
}

// peerState maintains state of inbound, persistent, outbound peers as well
// as banned peers and outbound groups.
type peerState struct {
	inboundPeers    map[int32]*serverPeer
	outboundPeers   map[int32]*serverPeer
	persistentPeers map[int32]*serverPeer
	banned          map[string]time.Time
	outboundGroups  map[string]int
	subCache        *naSubmissionCache
}

// ConnectionsWithIP returns the number of connections with the given IP.
func (ps *peerState) ConnectionsWithIP(ip net.IP) int {
	var total int
	for _, p := range ps.inboundPeers {
		if ip.Equal(p.NA().IP) {
			total++
		}
	}
	for _, p := range ps.outboundPeers {
		if ip.Equal(p.NA().IP) {
			total++
		}
	}
	for _, p := range ps.persistentPeers {
		if ip.Equal(p.NA().IP) {
			total++
		}
	}
	return total
}

// Count returns the count of all known peers.
func (ps *peerState) Count() int {
	return len(ps.inboundPeers) + len(ps.outboundPeers) +
		len(ps.persistentPeers)
}

// forAllOutboundPeers is a helper function that runs closure on all outbound
// peers known to peerState.
func (ps *peerState) forAllOutboundPeers(closure func(sp *serverPeer)) {
	for _, e := range ps.outboundPeers {
		closure(e)
	}
	for _, e := range ps.persistentPeers {
		closure(e)
	}
}

// forAllPeers is a helper function that runs closure on all peers known to
// peerState.
func (ps *peerState) forAllPeers(closure func(sp *serverPeer)) {
	for _, e := range ps.inboundPeers {
		closure(e)
	}
	ps.forAllOutboundPeers(closure)
}

// ResolveLocalAddress picks the best suggested network address from available
// options, per the network interface key provided. The best suggestion, if
// found, is added as a local address.
func (ps *peerState) ResolveLocalAddress(netType addrmgr.NetworkAddress, addrMgr *addrmgr.AddrManager, services wire.ServiceFlag) {
	best := ps.subCache.bestSubmission(netType)
	if best == nil {
		return
	}

	targetOutbound := defaultTargetOutbound
	if cfg.MaxPeers < targetOutbound {
		targetOutbound = cfg.MaxPeers
	}

	// A valid best address suggestion must have a majority
	// (60 percent majority) of outbound peers concluding on
	// the same result.
	if best.score < uint32(math.Ceil(float64(targetOutbound)*0.6)) {
		return
	}

	addLocalAddress := func(bestSuggestion string, port uint16, services wire.ServiceFlag) {
		na, err := addrMgr.HostToNetAddress(bestSuggestion, port, services)
		if err != nil {
			amgrLog.Errorf("unable to generate network address using host %v: "+
				"%v", bestSuggestion, err)
			return
		}

		if !addrMgr.HasLocalAddress(na) {
			err := addrMgr.AddLocalAddress(na, addrmgr.ManualPrio)
			if err != nil {
				amgrLog.Errorf("unable to add local address: %v", err)
				return
			}
		}
	}

	stripIPv6Zone := func(ip string) string {
		// Strip IPv6 zone id if present.
		zoneIndex := strings.LastIndex(ip, "%")
		if zoneIndex > 0 {
			return ip[:zoneIndex]
		}

		return ip
	}

	for _, listener := range cfg.Listeners {
		host, portStr, err := net.SplitHostPort(listener)
		if err != nil {
			amgrLog.Errorf("unable to split network address: %v", err)
			return
		}

		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			amgrLog.Errorf("unable to parse port: %v", err)
			return
		}

		host = stripIPv6Zone(host)

		// Add a local address if the best suggestion is referenced by a
		// listener.
		if best.na.IP.String() == host {
			addLocalAddress(best.na.IP.String(), uint16(port), services)
			continue
		}

		// Add a local address if the listener is generic (applies
		// for both IPv4 and IPv6).
		if host == "" || (host == "*" && runtime.GOOS == "plan9") {
			addLocalAddress(best.na.IP.String(), uint16(port), services)
			continue
		}

		listenerIP := net.ParseIP(host)
		if listenerIP == nil {
			amgrLog.Errorf("unable to parse listener: %v", host)
			return
		}

		// Add a local address if the network address is a probable external
		// endpoint of the listener.
		lNa := wire.NewNetAddressIPPort(listenerIP, uint16(port), services)
		lNet := addrmgr.IPv4Address
		if lNa.IP.To4() == nil {
			lNet = addrmgr.IPv6Address
		}

		validExternal := (lNet == addrmgr.IPv4Address &&
			best.reach == addrmgr.Ipv4) || lNet == addrmgr.IPv6Address &&
			(best.reach == addrmgr.Ipv6Weak || best.reach == addrmgr.Ipv6Strong ||
				best.reach == addrmgr.Teredo)

		if validExternal {
			addLocalAddress(best.na.IP.String(), uint16(port), services)
			continue
		}
	}
}

// server provides a Decred server for handling communications to and from
// Decred peers.
type server struct {
	// The following variables must only be used atomically.
	// Putting the uint64s first makes them 64-bit aligned for 32-bit systems.
	bytesReceived uint64 // Total bytes received from all peers since start.
	bytesSent     uint64 // Total bytes sent by all peers since start.
	shutdown      int32

	chainParams          *chaincfg.Params
	addrManager          *addrmgr.AddrManager
	connManager          *connmgr.ConnManager
	sigCache             *txscript.SigCache
	subsidyCache         *standalone.SubsidyCache
	rpcServer            *rpcserver.Server
	syncManager          *netsync.SyncManager
	bg                   *mining.BgBlkTmplGenerator
	chain                *blockchain.BlockChain
	txMemPool            *mempool.TxPool
	feeEstimator         *fees.Estimator
	cpuMiner             *cpuminer.CPUMiner
	modifyRebroadcastInv chan interface{}
	newPeers             chan *serverPeer
	donePeers            chan *serverPeer
	banPeers             chan *serverPeer
	query                chan interface{}
	relayInv             chan relayMsg
	broadcast            chan broadcastMsg
	wg                   sync.WaitGroup
	nat                  *upnpNAT
	db                   database.DB
	timeSource           blockchain.MedianTimeSource
	services             wire.ServiceFlag

	// The following fields are used for optional indexes.  They will be nil
	// if the associated index is not enabled.  These fields are set during
	// initial creation of the server and never changed afterwards, so they
	// do not need to be protected for concurrent access.
	txIndex         *indexers.TxIndex
	addrIndex       *indexers.AddrIndex
	existsAddrIndex *indexers.ExistsAddrIndex

	// The following fields are used to filter duplicate block announcements.
	announcedBlockMtx sync.Mutex
	announcedBlock    *chainhash.Hash

	// These following fields are used to filter duplicate block lottery data
	// anouncements.
	lotteryDataBroadcastMtx sync.RWMutex
	lotteryDataBroadcast    map[chainhash.Hash]struct{}

	// recentlyConfirmedTxns tracks transactions that have been confirmed in the
	// most recent blocks.
	recentlyConfirmedTxns *apbf.Filter
}

// serverPeer extends the peer to maintain state shared by the server.
type serverPeer struct {
	*peer.Peer

	connReq        *connmgr.ConnReq
	server         *server
	persistent     bool
	continueHash   *chainhash.Hash
	relayMtx       sync.Mutex
	disableRelayTx bool
	isWhitelisted  bool
	knownAddresses *apbf.Filter
	banScore       connmgr.DynamicBanScore
	quit           chan struct{}

	// addrsSent, getMiningStateSent and initState all track whether or not
	// the peer has already sent the respective request.  It is used to
	// prevent more than one response per connection.
	addrsSent          bool
	getMiningStateSent bool
	initStateSent      bool

	// The following fields are used to synchronize the net sync manager and
	// server.
	syncNotified   bool
	txProcessed    chan struct{}
	blockProcessed chan struct{}

	// peerNa is network address of the peer connected to.
	peerNa    *wire.NetAddress
	peerNaMtx sync.Mutex
}

// newServerPeer returns a new serverPeer instance. The peer needs to be set by
// the caller.
func newServerPeer(s *server, isPersistent bool) *serverPeer {
	return &serverPeer{
		server:         s,
		persistent:     isPersistent,
		knownAddresses: apbf.NewFilter(maxKnownAddrsPerPeer, knownAddrsFPRate),
		quit:           make(chan struct{}),
		txProcessed:    make(chan struct{}, 1),
		blockProcessed: make(chan struct{}, 1),
	}
}

// newestBlock returns the current best block hash and height using the format
// required by the configuration for the peer package.
func (sp *serverPeer) newestBlock() (*chainhash.Hash, int64, error) {
	best := sp.server.chain.BestSnapshot()
	return &best.Hash, best.Height, nil
}

// addKnownAddresses adds the given addresses to the set of known addresses to
// the peer to prevent sending duplicate addresses.
func (sp *serverPeer) addKnownAddresses(addresses []*wire.NetAddress) {
	for _, na := range addresses {
		sp.knownAddresses.Add([]byte(addrmgr.NetAddressKey(na)))
	}
}

// addressKnown true if the given address is already known to the peer.
func (sp *serverPeer) addressKnown(na *wire.NetAddress) bool {
	return sp.knownAddresses.Contains([]byte(addrmgr.NetAddressKey(na)))
}

// setDisableRelayTx toggles relaying of transactions for the given peer.
// It is safe for concurrent access.
func (sp *serverPeer) setDisableRelayTx(disable bool) {
	sp.relayMtx.Lock()
	sp.disableRelayTx = disable
	sp.relayMtx.Unlock()
}

// relayTxDisabled returns whether or not relaying of transactions for the given
// peer is disabled.
// It is safe for concurrent access.
func (sp *serverPeer) relayTxDisabled() bool {
	sp.relayMtx.Lock()
	isDisabled := sp.disableRelayTx
	sp.relayMtx.Unlock()

	return isDisabled
}

// pushAddrMsg sends an addr message to the connected peer using the provided
// addresses.
func (sp *serverPeer) pushAddrMsg(addresses []*wire.NetAddress) {
	// Filter addresses already known to the peer.
	addrs := make([]*wire.NetAddress, 0, len(addresses))
	for _, addr := range addresses {
		if !sp.addressKnown(addr) {
			addrs = append(addrs, addr)
		}
	}
	known, err := sp.PushAddrMsg(addrs)
	if err != nil {
		peerLog.Errorf("Can't push address message to %s: %v", sp.Peer, err)
		sp.Disconnect()
		return
	}
	sp.addKnownAddresses(known)
}

// addBanScore increases the persistent and decaying ban score fields by the
// values passed as parameters. If the resulting score exceeds half of the ban
// threshold, a warning is logged including the reason provided. Further, if
// the score is above the ban threshold, the peer will be banned and
// disconnected.
func (sp *serverPeer) addBanScore(persistent, transient uint32, reason string) bool {
	// No warning is logged and no score is calculated if banning is disabled.
	if cfg.DisableBanning {
		return false
	}
	if sp.isWhitelisted {
		peerLog.Debugf("Misbehaving whitelisted peer %s: %s", sp, reason)
		return false
	}

	warnThreshold := cfg.BanThreshold >> 1
	if transient == 0 && persistent == 0 {
		// The score is not being increased, but a warning message is still
		// logged if the score is above the warn threshold.
		score := sp.banScore.Int()
		if score > warnThreshold {
			peerLog.Warnf("Misbehaving peer %s: %s -- ban score is %d, "+
				"it was not increased this time", sp, reason, score)
		}
		return false
	}
	score := sp.banScore.Increase(persistent, transient)
	if score > warnThreshold {
		peerLog.Warnf("Misbehaving peer %s: %s -- ban score increased to %d",
			sp, reason, score)
		if score > cfg.BanThreshold {
			peerLog.Warnf("Misbehaving peer %s -- banning and disconnecting",
				sp)
			sp.server.BanPeer(sp)
			sp.Disconnect()
			return true
		}
	}
	return false
}

// hasServices returns whether or not the provided advertised service flags have
// all of the provided desired service flags set.
func hasServices(advertised, desired wire.ServiceFlag) bool {
	return advertised&desired == desired
}

// OnVersion is invoked when a peer receives a version wire message and is used
// to negotiate the protocol version details as well as kick start the
// communications.
func (sp *serverPeer) OnVersion(_ *peer.Peer, msg *wire.MsgVersion) {
	// Update the address manager with the advertised services for outbound
	// connections in case they have changed.  This is not done for inbound
	// connections to help prevent malicious behavior and is skipped when
	// running on the simulation and regression test networks since they are
	// only intended to connect to specified peers and actively avoid
	// advertising and connecting to discovered peers.
	//
	// NOTE: This is done before rejecting peers that are too old to ensure
	// it is updated regardless in the case a new minimum protocol version is
	// enforced and the remote node has not upgraded yet.
	isInbound := sp.Inbound()
	remoteAddr := sp.NA()
	addrManager := sp.server.addrManager
	if !cfg.SimNet && !cfg.RegNet && !isInbound {
		err := addrManager.SetServices(remoteAddr, msg.Services)
		if err != nil {
			srvrLog.Errorf("Setting services for address failed: %v", err)
		}
	}

	// Reject peers that have a protocol version that is too old.
	if msg.ProtocolVersion < int32(wire.SendHeadersVersion) {
		srvrLog.Debugf("Rejecting peer %s with protocol version %d prior to "+
			"the required version %d", sp.Peer, msg.ProtocolVersion,
			wire.SendHeadersVersion)
		sp.Disconnect()
		return
	}

	// Reject outbound peers that are not full nodes.
	wantServices := wire.SFNodeNetwork
	if !isInbound && !hasServices(msg.Services, wantServices) {
		missingServices := wantServices & ^msg.Services
		srvrLog.Debugf("Rejecting peer %s with services %v due to not "+
			"providing desired services %v", sp.Peer, msg.Services,
			missingServices)
		sp.Disconnect()
		return
	}

	// Update the address manager and request known addresses from the
	// remote peer for outbound connections.  This is skipped when running
	// on the simulation and regression test networks since they are only
	// intended to connect to specified peers and actively avoid advertising
	// and connecting to discovered peers.
	if !cfg.SimNet && !cfg.RegNet && !isInbound {
		// Advertise the local address when the server accepts incoming
		// connections and it believes itself to be close to the best
		// known tip.
		if !cfg.DisableListen && sp.server.syncManager.IsCurrent() {
			// Get address that best matches.
			lna := addrManager.GetBestLocalAddress(remoteAddr)
			if addrmgr.IsRoutable(lna) {
				// Filter addresses the peer already knows about.
				addresses := []*wire.NetAddress{lna}
				sp.pushAddrMsg(addresses)
			}
		}

		// Request known addresses if the server address manager needs
		// more.
		if addrManager.NeedMoreAddresses() {
			sp.QueueMessage(wire.NewMsgGetAddr(), nil)
		}

		// Mark the address as a known good address.
		err := addrManager.Good(remoteAddr)
		if err != nil {
			srvrLog.Errorf("Marking address as good failed: %v", err)
		}
	}

	sp.peerNaMtx.Lock()
	sp.peerNa = &msg.AddrYou
	sp.peerNaMtx.Unlock()

	// Choose whether or not to relay transactions.
	sp.setDisableRelayTx(msg.DisableRelayTx)

	// Add the remote peer time as a sample for creating an offset against
	// the local clock to keep the network time in sync.
	sp.server.timeSource.AddTimeSample(sp.Addr(), msg.Timestamp)

	// Add valid peer to the server.
	sp.server.AddPeer(sp)
}

// OnVerAck is invoked when a peer receives a verack wire message.  It creates
// and sends a sendheaders message to request all block annoucements are made
// via full headers instead of the inv message.
func (sp *serverPeer) OnVerAck(_ *peer.Peer, msg *wire.MsgVerAck) {
	sp.QueueMessage(wire.NewMsgSendHeaders(), nil)
}

// OnMemPool is invoked when a peer receives a mempool wire message.  It creates
// and sends an inventory message with the contents of the memory pool up to the
// maximum inventory allowed per message.
func (sp *serverPeer) OnMemPool(p *peer.Peer, msg *wire.MsgMemPool) {
	// A decaying ban score increase is applied to prevent flooding.
	// The ban score accumulates and passes the ban threshold if a burst of
	// mempool messages comes from a peer. The score decays each minute to
	// half of its value.
	if sp.addBanScore(0, 33, "mempool") {
		return
	}

	// Generate inventory message with the available transactions in the
	// transaction memory pool.  Limit it to the max allowed inventory
	// per message.  The NewMsgInvSizeHint function automatically limits
	// the passed hint to the maximum allowed, so it's safe to pass it
	// without double checking it here.
	txMemPool := sp.server.txMemPool
	txDescs := txMemPool.TxDescs()

	// Send the inventory message if there is anything to send.
	for _, txDesc := range txDescs {
		iv := wire.NewInvVect(wire.InvTypeTx, txDesc.Tx.Hash())
		sp.QueueInventory(iv)
	}
}

// pushMiningStateMsg pushes a mining state message to the queue for a
// requesting peer.
func (sp *serverPeer) pushMiningStateMsg(height uint32, blockHashes []chainhash.Hash, voteHashes []chainhash.Hash) error {
	// Nothing to send, abort.
	if len(blockHashes) == 0 {
		return nil
	}

	// Construct the mining state request and queue it to be sent.
	msg := wire.NewMsgMiningState()
	msg.Height = height
	for i := range blockHashes {
		err := msg.AddBlockHash(&blockHashes[i])
		if err != nil {
			return err
		}
	}
	for i := range voteHashes {
		err := msg.AddVoteHash(&voteHashes[i])
		if err != nil {
			return err
		}
		if i+1 >= wire.MaxMSBlocksAtHeadPerMsg {
			break
		}
	}

	sp.QueueMessage(msg, nil)

	return nil
}

// OnGetMiningState is invoked when a peer receives a getminings wire message.
// It constructs a list of the current best blocks and votes that should be
// mined on and pushes a miningstate wire message back to the requesting peer.
func (sp *serverPeer) OnGetMiningState(p *peer.Peer, msg *wire.MsgGetMiningState) {
	if sp.getMiningStateSent {
		peerLog.Tracef("Ignoring getminingstate from %v - already sent", sp.Peer)
		return
	}
	sp.getMiningStateSent = true

	// Send out blank mining states if it's early in the blockchain.
	best := sp.server.chain.BestSnapshot()
	if best.Height < sp.server.chainParams.StakeValidationHeight-1 {
		err := sp.pushMiningStateMsg(0, nil, nil)
		if err != nil {
			peerLog.Warnf("unexpected error while pushing data for "+
				"mining state request: %v", err.Error())
		}

		return
	}

	// Obtain the entire generation of blocks stemming from the parent of
	// the current tip.
	children, err := sp.server.chain.TipGeneration()
	if err != nil {
		peerLog.Warnf("failed to access sync manager to get the generation "+
			"for a mining state request (block: %v): %v", best.Hash, err)
		return
	}

	// Get the list of blocks that are eligible to build on and limit the
	// list to the maximum number of allowed eligible block hashes per
	// mining state message.  There is nothing to send when there are no
	// eligible blocks.
	mp := sp.server.txMemPool
	blockHashes := mining.SortParentsByVotes(mp, best.Hash, children,
		sp.server.chainParams)
	numBlocks := len(blockHashes)
	if numBlocks == 0 {
		return
	}
	if numBlocks > wire.MaxMSBlocksAtHeadPerMsg {
		blockHashes = blockHashes[:wire.MaxMSBlocksAtHeadPerMsg]
	}

	// Construct the set of votes to send.
	voteHashes := make([]chainhash.Hash, 0, wire.MaxMSVotesAtHeadPerMsg)
	for i := range blockHashes {
		// Fetch the vote hashes themselves and append them.
		bh := &blockHashes[i]
		vhsForBlock := mp.VoteHashesForBlock(bh)
		if len(vhsForBlock) == 0 {
			peerLog.Warnf("unexpected error while fetching vote hashes "+
				"for block %v for a mining state request: no vote "+
				"metadata for block", bh)
			return
		}
		voteHashes = append(voteHashes, vhsForBlock...)
	}

	err = sp.pushMiningStateMsg(uint32(best.Height), blockHashes, voteHashes)
	if err != nil {
		peerLog.Warnf("unexpected error while pushing data for "+
			"mining state request: %v", err.Error())
	}
}

// OnMiningState is invoked when a peer receives a miningstate wire message.  It
// requests the data advertised in the message from the peer.
func (sp *serverPeer) OnMiningState(p *peer.Peer, msg *wire.MsgMiningState) {
	err := sp.server.syncManager.RequestFromPeer(sp.Peer, msg.BlockHashes,
		msg.VoteHashes, nil)
	if err != nil {
		peerLog.Warnf("couldn't handle mining state message: %v",
			err.Error())
	}
}

// OnGetInitState is invoked when a peer receives a getinitstate wire message.
// It sends the available requested info the the remote peer.
func (sp *serverPeer) OnGetInitState(p *peer.Peer, msg *wire.MsgGetInitState) {
	if sp.initStateSent {
		peerLog.Tracef("Ignoring getinitstate from %v - already sent", sp.Peer)
		return
	}
	sp.initStateSent = true

	// Send out blank mining states if it's early in the blockchain.
	best := sp.server.chain.BestSnapshot()
	if best.Height < sp.server.chainParams.StakeValidationHeight-1 {
		sp.QueueMessage(wire.NewMsgInitState(), nil)
		return
	}

	// Response data.
	var blockHashes, voteHashes, tspendHashes []chainhash.Hash

	// Map from the types slice into a map for easier checking.
	types := make(map[string]struct{}, len(msg.Types))
	for _, typ := range msg.Types {
		types[typ] = struct{}{}
	}
	_, wantBlocks := types[wire.InitStateHeadBlocks]
	_, wantVotes := types[wire.InitStateHeadBlockVotes]
	_, wantTSpends := types[wire.InitStateTSpends]

	// Fetch head block hashes if we need to send either them or their
	// votes.
	mp := sp.server.txMemPool
	if wantBlocks || wantVotes {
		// Obtain the entire generation of blocks stemming from the
		// parent of the current tip.
		children, err := sp.server.chain.TipGeneration()
		if err != nil {
			peerLog.Warnf("Failed to access sync manager to get the generation "+
				"for a init state request (block: %v): %v", best.Hash, err)
			return
		}

		// Get the list of blocks that are eligible to build on and
		// limit the list to the maximum number of allowed eligible
		// block hashes per init state message.  There is nothing to
		// send when there are no eligible blocks.
		blockHashes = mining.SortParentsByVotes(mp, best.Hash, children,
			sp.server.chainParams)
		if len(blockHashes) > wire.MaxISBlocksAtHeadPerMsg {
			blockHashes = blockHashes[:wire.MaxISBlocksAtHeadPerMsg]
		}
	}

	// Construct the set of votes to send.
	if wantVotes {
		for i := range blockHashes {
			// Fetch the vote hashes themselves and append them.
			bh := &blockHashes[i]
			vhsForBlock := mp.VoteHashesForBlock(bh)
			voteHashes = append(voteHashes, vhsForBlock...)
		}
	}

	// Construct tspends to send.
	if wantTSpends {
		tspendHashes = mp.TSpendHashes()
	}

	// Clear out block hashes to be sent if they weren't requested.
	if !wantBlocks {
		blockHashes = nil
	}

	// Build and push the response.
	initMsg, err := wire.NewMsgInitStateFilled(blockHashes, voteHashes, tspendHashes)
	if err != nil {
		peerLog.Warnf("Unexpected error while building initstate msg: %v", err)
		return
	}
	sp.QueueMessage(initMsg, nil)
}

// OnInitState is invoked when a peer receives a initstate wire message.  It
// requests the data advertised in the message from the peer.
func (sp *serverPeer) OnInitState(p *peer.Peer, msg *wire.MsgInitState) {
	blockHashes := make([]*chainhash.Hash, 0, len(msg.BlockHashes))
	voteHashes := make([]*chainhash.Hash, 0, len(msg.VoteHashes))
	tSpendHashes := make([]*chainhash.Hash, 0, len(msg.TSpendHashes))

	for i := range msg.BlockHashes {
		blockHashes = append(blockHashes, &msg.BlockHashes[i])
	}
	for i := range msg.VoteHashes {
		voteHashes = append(voteHashes, &msg.VoteHashes[i])
	}
	for i := range msg.TSpendHashes {
		tSpendHashes = append(tSpendHashes, &msg.TSpendHashes[i])
	}

	err := sp.server.syncManager.RequestFromPeer(sp.Peer, blockHashes,
		voteHashes, tSpendHashes)
	if err != nil {
		peerLog.Warnf("couldn't handle init state message: %v", err)
	}
}

// OnTx is invoked when a peer receives a tx wire message.  It blocks until the
// transaction has been fully processed.  Unlock the block handler this does not
// serialize all transactions through a single thread transactions don't rely on
// the previous one in a linear fashion like blocks.
func (sp *serverPeer) OnTx(p *peer.Peer, msg *wire.MsgTx) {
	if cfg.BlocksOnly {
		peerLog.Tracef("Ignoring tx %v from %v - blocksonly enabled",
			msg.TxHash(), p)
		return
	}

	// Add the transaction to the known inventory for the peer.
	// Convert the raw MsgTx to a dcrutil.Tx which provides some convenience
	// methods and things such as hash caching.
	tx := dcrutil.NewTx(msg)
	iv := wire.NewInvVect(wire.InvTypeTx, tx.Hash())
	p.AddKnownInventory(iv)

	// Queue the transaction up to be handled by the net sync manager and
	// intentionally block further receives until the transaction is fully
	// processed and known good or bad.  This helps prevent a malicious peer
	// from queuing up a bunch of bad transactions before disconnecting (or
	// being disconnected) and wasting memory.
	sp.server.syncManager.QueueTx(tx, sp.Peer, sp.txProcessed)
	<-sp.txProcessed
}

// OnBlock is invoked when a peer receives a block wire message.  It blocks
// until the network block has been fully processed.
func (sp *serverPeer) OnBlock(p *peer.Peer, msg *wire.MsgBlock, buf []byte) {
	// Convert the raw MsgBlock to a dcrutil.Block which provides some
	// convenience methods and things such as hash caching.
	block := dcrutil.NewBlockFromBlockAndBytes(msg, buf)

	// Add the block to the known inventory for the peer.
	iv := wire.NewInvVect(wire.InvTypeBlock, block.Hash())
	p.AddKnownInventory(iv)

	// Queue the block up to be handled by the net sync manager and
	// intentionally block further receives until the network block is fully
	// processed and known good or bad.  This helps prevent a malicious peer
	// from queuing up a bunch of bad blocks before disconnecting (or being
	// disconnected) and wasting memory.  Additionally, this behavior is
	// depended on by at least the block acceptance test tool as the reference
	// implementation processes blocks in the same thread and therefore blocks
	// further messages until the network block has been fully processed.
	sp.server.syncManager.QueueBlock(block, sp.Peer, sp.blockProcessed)
	<-sp.blockProcessed
}

// OnInv is invoked when a peer receives an inv wire message and is used to
// examine the inventory being advertised by the remote peer and react
// accordingly.  We pass the message down to the net sync manager which will
// call QueueMessage with any appropriate responses.
func (sp *serverPeer) OnInv(p *peer.Peer, msg *wire.MsgInv) {
	// Ban peers sending empty inventory requests.
	if len(msg.InvList) == 0 {
		sp.server.BanPeer(sp)
		return
	}

	if !cfg.BlocksOnly {
		sp.server.syncManager.QueueInv(msg, sp.Peer)
		return
	}

	newInv := wire.NewMsgInvSizeHint(uint(len(msg.InvList)))
	for _, invVect := range msg.InvList {
		if invVect.Type == wire.InvTypeTx {
			peerLog.Infof("Peer %v is announcing transactions -- "+
				"disconnecting", p)
			p.Disconnect()
			return
		}
		err := newInv.AddInvVect(invVect)
		if err != nil {
			peerLog.Errorf("Failed to add inventory vector: %v", err)
			break
		}
	}

	sp.server.syncManager.QueueInv(newInv, sp.Peer)
}

// OnHeaders is invoked when a peer receives a headers wire message.  The
// message is passed down to the net sync manager.
func (sp *serverPeer) OnHeaders(_ *peer.Peer, msg *wire.MsgHeaders) {
	sp.server.syncManager.QueueHeaders(msg, sp.Peer)
}

// handleGetData is invoked when a peer receives a getdata wire message and is
// used to deliver block and transaction information.
func (sp *serverPeer) OnGetData(p *peer.Peer, msg *wire.MsgGetData) {
	// Ban peers sending empty getdata requests.
	if len(msg.InvList) == 0 {
		sp.server.BanPeer(sp)
		return
	}

	numAdded := 0
	notFound := wire.NewMsgNotFound()

	length := len(msg.InvList)
	// A decaying ban score increase is applied to prevent exhausting resources
	// with unusually large inventory queries.
	// Requesting more than the maximum inventory vector length within a short
	// period of time yields a score above the default ban threshold. Sustained
	// bursts of small requests are not penalized as that would potentially ban
	// peers performing IBD.
	// This incremental score decays each minute to half of its value.
	if sp.addBanScore(0, uint32(length)*99/wire.MaxInvPerMsg, "getdata") {
		return
	}

	// We wait on this wait channel periodically to prevent queuing
	// far more data than we can send in a reasonable time, wasting memory.
	// The waiting occurs after the database fetch for the next one to
	// provide a little pipelining.
	var waitChan chan struct{}
	doneChan := make(chan struct{}, 1)

	for i, iv := range msg.InvList {
		var c chan struct{}
		// If this will be the last message we send.
		if i == length-1 && len(notFound.InvList) == 0 {
			c = doneChan
		} else if (i+1)%3 == 0 {
			// Buffered so as to not make the send goroutine block.
			c = make(chan struct{}, 1)
		}
		var err error
		switch iv.Type {
		case wire.InvTypeTx:
			err = sp.server.pushTxMsg(sp, &iv.Hash, c, waitChan)
		case wire.InvTypeBlock:
			err = sp.server.pushBlockMsg(sp, &iv.Hash, c, waitChan)
		default:
			peerLog.Warnf("Unknown type '%d' in inventory request from %s",
				iv.Type, sp)
			continue
		}
		if err != nil {
			notFound.AddInvVect(iv)

			// When there is a failure fetching the final entry
			// and the done channel was sent in due to there
			// being no outstanding not found inventory, consume
			// it here because there is now not found inventory
			// that will use the channel momentarily.
			if i == len(msg.InvList)-1 && c != nil {
				<-c
			}
		}
		numAdded++
		waitChan = c
	}
	if len(notFound.InvList) != 0 {
		p.QueueMessage(notFound, doneChan)
	}

	// Wait for messages to be sent. We can send quite a lot of data at this
	// point and this will keep the peer busy for a decent amount of time.
	// We don't process anything else by them in this time so that we
	// have an idea of when we should hear back from them - else the idle
	// timeout could fire when we were only half done sending the blocks.
	if numAdded > 0 {
		<-doneChan
	}
}

// OnGetBlocks is invoked when a peer receives a getblocks wire message.
func (sp *serverPeer) OnGetBlocks(p *peer.Peer, msg *wire.MsgGetBlocks) {
	// Find the most recent known block in the best chain based on the block
	// locator and fetch all of the block hashes after it until either
	// wire.MaxBlocksPerMsg have been fetched or the provided stop hash is
	// encountered.
	//
	// Use the block after the genesis block if no other blocks in the
	// provided locator are known.  This does mean the client will start
	// over with the genesis block if unknown block locators are provided.
	chain := sp.server.chain
	hashList := chain.LocateBlocks(msg.BlockLocatorHashes, &msg.HashStop,
		wire.MaxBlocksPerMsg)

	// Generate inventory message.
	invMsg := wire.NewMsgInv()
	for i := range hashList {
		iv := wire.NewInvVect(wire.InvTypeBlock, &hashList[i])
		if sp.IsKnownInventory(iv) {
			// TODO: Increase ban score
			continue
		}
		invMsg.AddInvVect(iv)
	}

	// Send the inventory message if there is anything to send.
	if len(invMsg.InvList) > 0 {
		invListLen := len(invMsg.InvList)
		if invListLen == wire.MaxBlocksPerMsg {
			// Intentionally use a copy of the final hash so there
			// is not a reference into the inventory slice which
			// would prevent the entire slice from being eligible
			// for GC as soon as it's sent.
			continueHash := invMsg.InvList[invListLen-1].Hash
			sp.continueHash = &continueHash
		}
		p.QueueMessage(invMsg, nil)
	}
}

// OnGetHeaders is invoked when a peer receives a getheaders wire message.
func (sp *serverPeer) OnGetHeaders(p *peer.Peer, msg *wire.MsgGetHeaders) {
	// Ignore getheaders requests if not in sync unless the local best chain
	// is exactly at the same tip as the requesting peer.
	locatorHashes := msg.BlockLocatorHashes
	chain := sp.server.chain
	if !sp.server.syncManager.IsCurrent() && (len(locatorHashes) == 0 ||
		*locatorHashes[0] != chain.BestSnapshot().PrevHash) {

		return
	}

	// Find the most recent known block in the best chain based on the block
	// locator and fetch all of the headers after it until either
	// wire.MaxBlockHeadersPerMsg have been fetched or the provided stop
	// hash is encountered.
	//
	// Use the block after the genesis block if no other blocks in the
	// provided locator are known.  This does mean the client will start
	// over with the genesis block if unknown block locators are provided.
	headers := chain.LocateHeaders(locatorHashes, &msg.HashStop)

	// Send found headers to the requesting peer.
	blockHeaders := make([]*wire.BlockHeader, len(headers))
	for i := range headers {
		blockHeaders[i] = &headers[i]
	}
	p.QueueMessage(&wire.MsgHeaders{Headers: blockHeaders}, nil)
}

// enforceNodeCFFlag bans the peer if it has negotiated to a protocol version
// that is high enough to observe the committed filter service support bit since
// it is intentionally violating the protocol by requesting one from when the
// server does not advertise support for it.
//
// It disconnects the peer when it has negotiated to a protocol version prior to
// being able to understand the service bit.
func (sp *serverPeer) enforceNodeCFFlag(cmd string) {
	// Ban the peer if the protocol version is high enough that the peer is
	// knowingly violating the protocol and banning is enabled.
	//
	// NOTE: Even though the addBanScore function already examines whether
	// or not banning is enabled, it is checked here as well to ensure the
	// violation is logged and the peer is disconnected regardless.
	if sp.ProtocolVersion() >= wire.NodeCFVersion && !cfg.DisableBanning {
		// Disconnect the peer regardless of whether it was banned.
		sp.addBanScore(100, 0, cmd)
		sp.Disconnect()
		return
	}

	// Disconnect the peer regardless of protocol version or banning state.
	peerLog.Debugf("%s sent an unsupported %s request -- disconnecting", sp,
		cmd)
	sp.Disconnect()
}

// OnGetCFilter is invoked when a peer receives a getcfilter wire message.
func (sp *serverPeer) OnGetCFilter(p *peer.Peer, msg *wire.MsgGetCFilter) {
	// Disconnect and/or ban depending on the node cf services flag and
	// negotiated protocol version.
	sp.enforceNodeCFFlag(msg.Command())
}

// OnGetCFilterV2 is invoked when a peer receives a getcfilterv2 wire message.
func (sp *serverPeer) OnGetCFilterV2(_ *peer.Peer, msg *wire.MsgGetCFilterV2) {
	// Ignore request if the chain is not yet synced.
	if !sp.server.syncManager.IsCurrent() {
		return
	}

	// Attempt to obtain the requested filter.
	//
	// Ignore request for unknown block or otherwise missing filters.
	chain := sp.server.chain
	filter, err := chain.FilterByBlockHash(&msg.BlockHash)
	if err != nil {
		return
	}

	// NOTE: When more header commitments are added, this will need to load the
	// inclusion proof for the filter from the database.  However, since there
	// is only currently a single commitment, there is only a single leaf in the
	// commitment merkle tree, and hence the proof hashes will always be empty
	// given there are no siblings.  Adding an additional header commitment will
	// require a consensus vote anyway and this can be updated at that time.
	cfilterMsg := wire.NewMsgCFilterV2(&msg.BlockHash, filter.Bytes(),
		blockchain.HeaderCmtFilterIndex, nil)
	sp.QueueMessage(cfilterMsg, nil)
}

// OnGetCFHeaders is invoked when a peer receives a getcfheader wire message.
func (sp *serverPeer) OnGetCFHeaders(p *peer.Peer, msg *wire.MsgGetCFHeaders) {
	// Disconnect and/or ban depending on the node cf services flag and
	// negotiated protocol version.
	sp.enforceNodeCFFlag(msg.Command())
}

// OnGetCFTypes is invoked when a peer receives a getcftypes wire message.
func (sp *serverPeer) OnGetCFTypes(p *peer.Peer, msg *wire.MsgGetCFTypes) {
	// Disconnect and/or ban depending on the node cf services flag and
	// negotiated protocol version.
	sp.enforceNodeCFFlag(msg.Command())
}

// OnGetAddr is invoked when a peer receives a getaddr wire message and is used
// to provide the peer with known addresses from the address manager.
func (sp *serverPeer) OnGetAddr(p *peer.Peer, msg *wire.MsgGetAddr) {
	// Don't return any addresses when running on the simulation and regression
	// test networks.  This helps prevent the networks from becoming another
	// public test network since they will not be able to learn about other
	// peers that have not specifically been provided.
	if cfg.SimNet || cfg.RegNet {
		return
	}

	// Do not accept getaddr requests from outbound peers.  This reduces
	// fingerprinting attacks.
	if !p.Inbound() {
		return
	}

	// Only respond with addresses once per connection.  This helps reduce
	// traffic and further reduces fingerprinting attacks.
	if sp.addrsSent {
		peerLog.Tracef("Ignoring getaddr from %v - already sent", sp.Peer)
		return
	}
	sp.addrsSent = true

	// Get the current known addresses from the address manager.
	addrCache := sp.server.addrManager.AddressCache()

	// Push the addresses.
	sp.pushAddrMsg(addrCache)
}

// OnAddr is invoked when a peer receives an addr wire message and is used to
// notify the server about advertised addresses.
func (sp *serverPeer) OnAddr(p *peer.Peer, msg *wire.MsgAddr) {
	// Ignore addresses when running on the simulation and regression test
	// networks.  This helps prevent the networks from becoming another public
	// test network since they will not be able to learn about other peers that
	// have not specifically been provided.
	if cfg.SimNet || cfg.RegNet {
		return
	}

	// A message that has no addresses is invalid.
	if len(msg.AddrList) == 0 {
		peerLog.Errorf("Command [%s] from %s does not contain any addresses",
			msg.Command(), p)

		// Ban peers sending empty address requests.
		sp.server.BanPeer(sp)
		return
	}

	now := time.Now()
	for _, na := range msg.AddrList {
		// Don't add more address if we're disconnecting.
		if !p.Connected() {
			return
		}

		// Set the timestamp to 5 days ago if it's more than 24 hours
		// in the future so this address is one of the first to be
		// removed when space is needed.
		if na.Timestamp.After(now.Add(time.Minute * 10)) {
			na.Timestamp = now.Add(-1 * time.Hour * 24 * 5)
		}

		// Add address to known addresses for this peer.
		sp.addKnownAddresses([]*wire.NetAddress{na})
	}

	// Add addresses to server address manager.  The address manager handles
	// the details of things such as preventing duplicate addresses, max
	// addresses, and last seen updates.
	// XXX bitcoind gives a 2 hour time penalty here, do we want to do the
	// same?
	sp.server.addrManager.AddAddresses(msg.AddrList, p.NA())
}

// OnRead is invoked when a peer receives a message and it is used to update
// the bytes received by the server.
func (sp *serverPeer) OnRead(p *peer.Peer, bytesRead int, msg wire.Message, err error) {
	// Ban peers sending messages that do not conform to the wire protocol.
	var errCode wire.ErrorCode
	if errors.As(err, &errCode) {
		peerLog.Errorf("Unable to read wire message from %s: %v", sp, err)
		sp.server.BanPeer(sp)
	}

	sp.server.AddBytesReceived(uint64(bytesRead))
}

// OnWrite is invoked when a peer sends a message and it is used to update
// the bytes sent by the server.
func (sp *serverPeer) OnWrite(p *peer.Peer, bytesWritten int, msg wire.Message, err error) {
	sp.server.AddBytesSent(uint64(bytesWritten))
}

// OnNotFound is invoked when a peer sends a notfound message.
func (sp *serverPeer) OnNotFound(p *peer.Peer, msg *wire.MsgNotFound) {
	if !sp.Connected() {
		return
	}

	var numBlocks, numTxns uint32
	for _, inv := range msg.InvList {
		switch inv.Type {
		case wire.InvTypeBlock:
			numBlocks++
		case wire.InvTypeTx:
			numTxns++
		default:
			peerLog.Debugf("Invalid inv type '%d' in notfound message from %s",
				inv.Type, sp)
			sp.Disconnect()
			return
		}
	}
	if numBlocks > 0 {
		blockStr := pickNoun(uint64(numBlocks), "block", "blocks")
		reason := fmt.Sprintf("%d %v not found", numBlocks, blockStr)
		if sp.addBanScore(20*numBlocks, 0, reason) {
			return
		}
	}
	if numTxns > 0 {
		txStr := pickNoun(uint64(numTxns), "transaction", "transactions")
		reason := fmt.Sprintf("%d %v not found", numBlocks, txStr)
		if sp.addBanScore(0, 10*numTxns, reason) {
			return
		}
	}
	sp.server.syncManager.QueueNotFound(msg, p)
}

// randomUint16Number returns a random uint16 in a specified input range.  Note
// that the range is in zeroth ordering; if you pass it 1800, you will get
// values from 0 to 1800.
func randomUint16Number(max uint16) uint16 {
	// In order to avoid modulo bias and ensure every possible outcome in
	// [0, max) has equal probability, the random number must be sampled
	// from a random source that has a range limited to a multiple of the
	// modulus.
	var randomNumber uint16
	var limitRange = (math.MaxUint16 / max) * max
	for {
		binary.Read(rand.Reader, binary.LittleEndian, &randomNumber)
		if randomNumber < limitRange {
			return (randomNumber % max)
		}
	}
}

// AddRebroadcastInventory adds 'iv' to the list of inventories to be
// rebroadcasted at random intervals until they show up in a block.
func (s *server) AddRebroadcastInventory(iv *wire.InvVect, data interface{}) {
	// Ignore if shutting down.
	if atomic.LoadInt32(&s.shutdown) != 0 {
		return
	}

	s.modifyRebroadcastInv <- broadcastInventoryAdd{invVect: iv, data: data}
}

// RemoveRebroadcastInventory removes 'iv' from the list of items to be
// rebroadcasted if present.
func (s *server) RemoveRebroadcastInventory(iv *wire.InvVect) {
	// Ignore if shutting down.
	if atomic.LoadInt32(&s.shutdown) != 0 {
		return
	}

	s.modifyRebroadcastInv <- broadcastInventoryDel(iv)
}

// PruneRebroadcastInventory filters and removes rebroadcast inventory entries
// where necessary.
func (s *server) PruneRebroadcastInventory() {
	// Ignore if shutting down.
	if atomic.LoadInt32(&s.shutdown) != 0 {
		return
	}

	s.modifyRebroadcastInv <- broadcastPruneInventory{}
}

// relayTransactions generates and relays inventory vectors for all of the
// passed transactions to all connected peers.
func (s *server) relayTransactions(txns []*dcrutil.Tx) {
	for _, tx := range txns {
		iv := wire.NewInvVect(wire.InvTypeTx, tx.Hash())
		s.RelayInventory(iv, tx, false)
	}
}

// AnnounceNewTransactions generates and relays inventory vectors and notifies
// websocket clients of the passed transactions.  This function should be
// called whenever new transactions are added to the mempool.
func (s *server) AnnounceNewTransactions(txns []*dcrutil.Tx) {
	// Generate and relay inventory vectors for all newly accepted
	// transactions.
	s.relayTransactions(txns)

	// Notify websocket clients of all newly accepted transactions.
	if s.rpcServer != nil {
		s.rpcServer.NotifyNewTransactions(txns)
	}
}

// TransactionConfirmed marks the provided single confirmation transaction as
// no longer needing rebroadcasting and keeps track of it for use when avoiding
// requests for recently confirmed transactions.
func (s *server) TransactionConfirmed(tx *dcrutil.Tx) {
	txHash := tx.Hash()
	s.recentlyConfirmedTxns.Add(txHash[:])

	// Rebroadcasting is only necessary when the RPC server is active.
	if s.rpcServer != nil {
		iv := wire.NewInvVect(wire.InvTypeTx, txHash)
		s.RemoveRebroadcastInventory(iv)
	}
}

// pushTxMsg sends a tx message for the provided transaction hash to the
// connected peer.  An error is returned if the transaction hash is not known.
func (s *server) pushTxMsg(sp *serverPeer, hash *chainhash.Hash, doneChan chan<- struct{}, waitChan <-chan struct{}) error {
	// Attempt to fetch the requested transaction from the pool.  A
	// call could be made to check for existence first, but simply trying
	// to fetch a missing transaction results in the same behavior.
	// Do not allow peers to request transactions already in a block
	// but are unconfirmed, as they may be expensive. Restrict that
	// to the authenticated RPC only.
	tx, err := s.txMemPool.FetchTransaction(hash)
	if err != nil {
		peerLog.Tracef("Unable to fetch tx %v from transaction "+
			"pool: %v", hash, err)

		if doneChan != nil {
			doneChan <- struct{}{}
		}
		return err
	}

	// Once we have fetched data wait for any previous operation to finish.
	if waitChan != nil {
		<-waitChan
	}

	sp.QueueMessage(tx.MsgTx(), doneChan)

	return nil
}

// pushBlockMsg sends a block message for the provided block hash to the
// connected peer.  An error is returned if the block hash is not known.
func (s *server) pushBlockMsg(sp *serverPeer, hash *chainhash.Hash, doneChan chan<- struct{}, waitChan <-chan struct{}) error {
	block, err := sp.server.chain.BlockByHash(hash)
	if err != nil {
		peerLog.Tracef("Unable to fetch requested block hash %v: %v",
			hash, err)

		if doneChan != nil {
			doneChan <- struct{}{}
		}
		return err
	}

	// Once we have fetched data wait for any previous operation to finish.
	if waitChan != nil {
		<-waitChan
	}

	// We only send the channel for this message if we aren't sending
	// an inv straight after.
	var dc chan<- struct{}
	continueHash := sp.continueHash
	sendInv := continueHash != nil && continueHash.IsEqual(hash)
	if !sendInv {
		dc = doneChan
	}
	sp.QueueMessage(block.MsgBlock(), dc)

	// When the peer requests the final block that was advertised in
	// response to a getblocks message which requested more blocks than
	// would fit into a single message, send it a new inventory message
	// to trigger it to issue another getblocks message for the next
	// batch of inventory.
	if sendInv {
		best := sp.server.chain.BestSnapshot()
		invMsg := wire.NewMsgInvSizeHint(1)
		iv := wire.NewInvVect(wire.InvTypeBlock, &best.Hash)
		invMsg.AddInvVect(iv)
		sp.QueueMessage(invMsg, doneChan)
		sp.continueHash = nil
	}
	return nil
}

// handleAddPeerMsg deals with adding new peers.  It is invoked from the
// peerHandler goroutine.
func (s *server) handleAddPeerMsg(state *peerState, sp *serverPeer) bool {
	if sp == nil {
		return false
	}

	// Ignore new peers if we're shutting down.
	if atomic.LoadInt32(&s.shutdown) != 0 {
		srvrLog.Infof("New peer %s ignored - server is shutting down", sp)
		sp.Disconnect()
		return false
	}

	// Disconnect banned peers.
	host, _, err := net.SplitHostPort(sp.Addr())
	if err != nil {
		srvrLog.Debugf("can't split hostport %v", err)
		sp.Disconnect()
		return false
	}
	if banEnd, ok := state.banned[host]; ok {
		if time.Now().Before(banEnd) {
			srvrLog.Debugf("Peer %s is banned for another %v - disconnecting",
				host, time.Until(banEnd))
			sp.Disconnect()
			return false
		}

		srvrLog.Infof("Peer %s is no longer banned", host)
		delete(state.banned, host)
	}

	// Limit max number of connections from a single IP.  However, allow
	// whitelisted inbound peers and localhost connections regardless.
	isInboundWhitelisted := sp.isWhitelisted && sp.Inbound()
	peerIP := sp.NA().IP
	if cfg.MaxSameIP > 0 && !isInboundWhitelisted && !peerIP.IsLoopback() &&
		state.ConnectionsWithIP(peerIP)+1 > cfg.MaxSameIP {
		srvrLog.Infof("Max connections with %s reached [%d] - "+
			"disconnecting peer", sp, cfg.MaxSameIP)
		sp.Disconnect()
		return false
	}

	// Limit max number of total peers.  However, allow whitelisted inbound
	// peers regardless.
	if state.Count()+1 > cfg.MaxPeers && !isInboundWhitelisted {
		srvrLog.Infof("Max peers reached [%d] - disconnecting peer %s",
			cfg.MaxPeers, sp)
		sp.Disconnect()
		// TODO: how to handle permanent peers here?
		// they should be rescheduled.
		return false
	}

	sp.peerNaMtx.Lock()
	na := sp.peerNa
	sp.peerNaMtx.Unlock()

	// Add the new peer and start it.
	srvrLog.Debugf("New peer %s", sp)
	if sp.Inbound() {
		state.inboundPeers[sp.ID()] = sp

		if na != nil {
			id := na.IP.String()

			// Inbound peers can only corroborate existing address submissions.
			if state.subCache.exists(id) {
				err := state.subCache.incrementScore(id)
				if err != nil {
					srvrLog.Errorf("unable to increment submission score: %v", err)
					return true
				}
			}
		}
	} else {
		state.outboundGroups[addrmgr.GroupKey(sp.NA())]++
		if sp.persistent {
			state.persistentPeers[sp.ID()] = sp
		} else {
			state.outboundPeers[sp.ID()] = sp
		}

		// Fetch the suggested public ip from the outbound peer if
		// there are no prevailing conditions to disable automatic
		// network address discovery.
		//
		// The conditions to disable automatic network address
		// discovery are:
		//	- If there is a proxy set (--proxy, --onion).
		//	- If automatic network address discovery is explicitly
		//		disabled (--nodiscoverip).
		//	- If there is an external ip explicitly set (--externalip).
		//	- If listening has been disabled (--nolisten, listen
		//	disabled because of --connect, etc).
		//	- If Universal Plug and Play is enabled (--upnp).
		//	- If the active network is simnet or regnet.
		if (cfg.Proxy != "" || cfg.OnionProxy != "") ||
			cfg.NoDiscoverIP || len(cfg.ExternalIPs) > 0 ||
			(cfg.DisableListen || len(cfg.Listeners) == 0) || cfg.Upnp ||
			s.chainParams.Name == simNetParams.Name ||
			s.chainParams.Name == regNetParams.Name {
			return true
		}

		if na != nil {
			net := addrmgr.IPv4Address
			if na.IP.To4() == nil {
				net = addrmgr.IPv6Address
			}

			valid, reach := s.addrManager.ValidatePeerNa(na, sp.NA())
			if !valid {
				return true
			}

			id := na.IP.String()
			if state.subCache.exists(id) {
				// Increment the submission score if it already exists.
				err := state.subCache.incrementScore(id)
				if err != nil {
					srvrLog.Errorf("unable to increment submission score: %v", err)
					return true
				}
			} else {
				// Create a cache entry for a new submission.
				sub := &naSubmission{
					na:      na,
					netType: net,
					reach:   reach,
				}

				err := state.subCache.add(sub)
				if err != nil {
					srvrLog.Errorf("unable to add submission: %v", err)
					return true
				}
			}

			// Pick the local address for the provided network based on
			// submission scores.
			state.ResolveLocalAddress(net, s.addrManager, s.services)
		}
	}

	return true
}

// handleDonePeerMsg deals with peers that have signalled they are done.  It is
// invoked from the peerHandler goroutine.
func (s *server) handleDonePeerMsg(state *peerState, sp *serverPeer) {
	var list map[int32]*serverPeer
	if sp.persistent {
		list = state.persistentPeers
	} else if sp.Inbound() {
		list = state.inboundPeers
	} else {
		list = state.outboundPeers
	}
	if _, ok := list[sp.ID()]; ok {
		if !sp.Inbound() && sp.VersionKnown() {
			state.outboundGroups[addrmgr.GroupKey(sp.NA())]--
		}
		if !sp.Inbound() && sp.connReq != nil {
			s.connManager.Disconnect(sp.connReq.ID())
		}
		delete(list, sp.ID())
		srvrLog.Debugf("Removed peer %s", sp)
		return
	}

	if sp.connReq != nil {
		s.connManager.Disconnect(sp.connReq.ID())
	}

	// Update the address' last seen time if the peer has acknowledged
	// our version and has sent us its version as well.
	if sp.VerAckReceived() && sp.VersionKnown() && sp.NA() != nil {
		err := s.addrManager.Connected(sp.NA())
		if err != nil {
			srvrLog.Debugf("Marking address as connected failed: %v", err)
		}
	}

	// If we get here it means that either we didn't know about the peer
	// or we purposefully deleted it.
}

// handleBanPeerMsg deals with banning peers.  It is invoked from the
// peerHandler goroutine.
func (s *server) handleBanPeerMsg(state *peerState, sp *serverPeer) {
	host, _, err := net.SplitHostPort(sp.Addr())
	if err != nil {
		srvrLog.Debugf("can't split ban peer %s %v", sp.Addr(), err)
		return
	}
	direction := directionString(sp.Inbound())
	srvrLog.Infof("Banned peer %s (%s) for %v", host, direction,
		cfg.BanDuration)
	state.banned[host] = time.Now().Add(cfg.BanDuration)
}

// handleRelayInvMsg deals with relaying inventory to peers that are not already
// known to have it.  It is invoked from the peerHandler goroutine.
func (s *server) handleRelayInvMsg(state *peerState, msg relayMsg) {
	state.forAllPeers(func(sp *serverPeer) {
		if !sp.Connected() {
			return
		}

		// If the inventory is a block and the peer prefers headers,
		// generate and send a headers message instead of an inventory
		// message.
		if msg.invVect.Type == wire.InvTypeBlock && sp.WantsHeaders() {
			blockHeader, ok := msg.data.(wire.BlockHeader)
			if !ok {
				peerLog.Warnf("Underlying data for headers" +
					" is not a block header")
				return
			}
			msgHeaders := wire.NewMsgHeaders()
			if err := msgHeaders.AddBlockHeader(&blockHeader); err != nil {
				peerLog.Errorf("Failed to add block"+
					" header: %v", err)
				return
			}
			sp.QueueMessage(msgHeaders, nil)
			return
		}

		if msg.invVect.Type == wire.InvTypeTx {
			// Don't relay the transaction to the peer when it has
			// transaction relaying disabled.
			if sp.relayTxDisabled() {
				return
			}
		}

		// Either queue the inventory to be relayed immediately or with
		// the next batch depending on the immediate flag.
		//
		// It will be ignored in either case if the peer is already
		// known to have the inventory.
		if msg.immediate {
			sp.QueueInventoryImmediate(msg.invVect)
		} else {
			sp.QueueInventory(msg.invVect)
		}
	})
}

// handleBroadcastMsg deals with broadcasting messages to peers.  It is invoked
// from the peerHandler goroutine.
func (s *server) handleBroadcastMsg(state *peerState, bmsg *broadcastMsg) {
	state.forAllPeers(func(sp *serverPeer) {
		if !sp.Connected() {
			return
		}

		for _, ep := range bmsg.excludePeers {
			if sp == ep {
				return
			}
		}

		sp.QueueMessage(bmsg.message, nil)
	})
}

type getConnCountMsg struct {
	reply chan int32
}

type getPeersMsg struct {
	reply chan []*serverPeer
}

type getOutboundGroup struct {
	key   string
	reply chan int
}

type getAddedNodesMsg struct {
	reply chan []*serverPeer
}

type disconnectNodeMsg struct {
	cmp   func(*serverPeer) bool
	reply chan error
}

type connectNodeMsg struct {
	addr      string
	permanent bool
	reply     chan error
}

type removeNodeMsg struct {
	cmp   func(*serverPeer) bool
	reply chan error
}

type cancelPendingMsg struct {
	addr  string
	reply chan error
}

// handleQuery is the central handler for all queries and commands from other
// goroutines related to peer state.
func (s *server) handleQuery(state *peerState, querymsg interface{}) {
	switch msg := querymsg.(type) {
	case getConnCountMsg:
		nconnected := int32(0)
		state.forAllPeers(func(sp *serverPeer) {
			if sp.Connected() {
				nconnected++
			}
		})
		msg.reply <- nconnected

	case getPeersMsg:
		peers := make([]*serverPeer, 0, state.Count())
		state.forAllPeers(func(sp *serverPeer) {
			if !sp.Connected() {
				return
			}
			peers = append(peers, sp)
		})
		msg.reply <- peers

	case connectNodeMsg:
		// XXX duplicate oneshots?
		// Limit max number of total peers.
		if state.Count() >= cfg.MaxPeers {
			msg.reply <- errors.New("max peers reached")
			return
		}
		err := s.connManager.ForEachConnReq(func(c *connmgr.ConnReq) error {
			if c.Addr != nil && c.Addr.String() == msg.addr {
				if c.Permanent {
					return errors.New("peer exists as a permanent peer")
				}

				switch c.State() {
				case connmgr.ConnPending:
					return errors.New("peer pending connection")
				case connmgr.ConnEstablished:
					return errors.New("peer already connected")

				}
			}
			return nil
		})
		if err != nil {
			msg.reply <- err
			return
		}

		netAddr, err := addrStringToNetAddr(msg.addr)
		if err != nil {
			msg.reply <- err
			return
		}

		// TODO: if too many, nuke a non-perm peer.
		go s.connManager.Connect(context.Background(),
			&connmgr.ConnReq{
				Addr:      netAddr,
				Permanent: msg.permanent,
			})
		msg.reply <- nil

	case removeNodeMsg:
		found := disconnectPeer(state.persistentPeers, msg.cmp, func(sp *serverPeer) {
			// Keep group counts ok since we remove from
			// the list now.
			state.outboundGroups[addrmgr.GroupKey(sp.NA())]--

			peerLog.Debugf("Removing persistent peer %s:%d (reqid %d)",
				sp.NA().IP, sp.NA().Port, sp.connReq.ID())
			connReq := sp.connReq

			// Mark the peer's connReq as nil to prevent it from scheduling a
			// re-connect attempt.
			sp.connReq = nil
			s.connManager.Remove(connReq.ID())
		})

		if found {
			msg.reply <- nil
		} else {
			msg.reply <- errors.New("peer not found")
		}

	case cancelPendingMsg:
		netAddr, err := addrStringToNetAddr(msg.addr)
		if err != nil {
			msg.reply <- err
			return
		}
		msg.reply <- s.connManager.CancelPending(netAddr)

	case getOutboundGroup:
		count, ok := state.outboundGroups[msg.key]
		if ok {
			msg.reply <- count
		} else {
			msg.reply <- 0
		}

	case getAddedNodesMsg:
		// Respond with a slice of the relevant peers.
		peers := make([]*serverPeer, 0, len(state.persistentPeers))
		for _, sp := range state.persistentPeers {
			peers = append(peers, sp)
		}
		msg.reply <- peers

	case disconnectNodeMsg:
		// Check inbound peers. We pass a nil callback since we don't
		// require any additional actions on disconnect for inbound peers.
		found := disconnectPeer(state.inboundPeers, msg.cmp, nil)
		if found {
			msg.reply <- nil
			return
		}

		// Check outbound peers.
		found = disconnectPeer(state.outboundPeers, msg.cmp, func(sp *serverPeer) {
			// Keep group counts ok since we remove from
			// the list now.
			state.outboundGroups[addrmgr.GroupKey(sp.NA())]--
		})
		if found {
			// If there are multiple outbound connections to the same
			// ip:port, continue disconnecting them all until no such
			// peers are found.
			for found {
				found = disconnectPeer(state.outboundPeers, msg.cmp, func(sp *serverPeer) {
					state.outboundGroups[addrmgr.GroupKey(sp.NA())]--
				})
			}
			msg.reply <- nil
			return
		}

		msg.reply <- errors.New("peer not found")
	}
}

// disconnectPeer attempts to drop the connection of a targeted peer in the
// passed peer list. Targets are identified via usage of the passed
// `compareFunc`, which should return `true` if the passed peer is the target
// peer. This function returns true on success and false if the peer is unable
// to be located. If the peer is found, and the passed callback: `whenFound'
// isn't nil, we call it with the peer as the argument before it is removed
// from the peerList, and is disconnected from the server.
func disconnectPeer(peerList map[int32]*serverPeer, compareFunc func(*serverPeer) bool, whenFound func(*serverPeer)) bool {
	for addr, peer := range peerList {
		if compareFunc(peer) {
			if whenFound != nil {
				whenFound(peer)
			}

			// This is ok because we are not continuing
			// to iterate so won't corrupt the loop.
			delete(peerList, addr)
			peer.Disconnect()
			return true
		}
	}
	return false
}

// newPeerConfig returns the configuration for the given serverPeer.
func newPeerConfig(sp *serverPeer) *peer.Config {
	var userAgentComments []string
	if version.PreRelease != "" {
		userAgentComments = append(userAgentComments, version.PreRelease)
	}

	return &peer.Config{
		Listeners: peer.MessageListeners{
			OnVersion:        sp.OnVersion,
			OnVerAck:         sp.OnVerAck,
			OnMemPool:        sp.OnMemPool,
			OnGetMiningState: sp.OnGetMiningState,
			OnMiningState:    sp.OnMiningState,
			OnGetInitState:   sp.OnGetInitState,
			OnInitState:      sp.OnInitState,
			OnTx:             sp.OnTx,
			OnBlock:          sp.OnBlock,
			OnInv:            sp.OnInv,
			OnHeaders:        sp.OnHeaders,
			OnGetData:        sp.OnGetData,
			OnGetBlocks:      sp.OnGetBlocks,
			OnGetHeaders:     sp.OnGetHeaders,
			OnGetCFilter:     sp.OnGetCFilter,
			OnGetCFilterV2:   sp.OnGetCFilterV2,
			OnGetCFHeaders:   sp.OnGetCFHeaders,
			OnGetCFTypes:     sp.OnGetCFTypes,
			OnGetAddr:        sp.OnGetAddr,
			OnAddr:           sp.OnAddr,
			OnRead:           sp.OnRead,
			OnWrite:          sp.OnWrite,
			OnNotFound:       sp.OnNotFound,
		},
		NewestBlock:       sp.newestBlock,
		HostToNetAddress:  sp.server.addrManager.HostToNetAddress,
		Proxy:             cfg.Proxy,
		UserAgentName:     userAgentName,
		UserAgentVersion:  userAgentVersion,
		UserAgentComments: userAgentComments,
		Net:               sp.server.chainParams.Net,
		Services:          sp.server.services,
		DisableRelayTx:    cfg.BlocksOnly,
		ProtocolVersion:   maxProtocolVersion,
		IdleTimeout:       cfg.PeerIdleTimeout,
	}
}

// inboundPeerConnected is invoked by the connection manager when a new inbound
// connection is established.  It initializes a new inbound server peer
// instance, associates it with the connection, and starts a goroutine to wait
// for disconnection.
func (s *server) inboundPeerConnected(conn net.Conn) {
	sp := newServerPeer(s, false)
	sp.isWhitelisted = isWhitelisted(conn.RemoteAddr())
	sp.Peer = peer.NewInboundPeer(newPeerConfig(sp))
	sp.AssociateConnection(conn)
	go s.peerDoneHandler(sp)
}

// outboundPeerConnected is invoked by the connection manager when a new
// outbound connection is established.  It initializes a new outbound server
// peer instance, associates it with the relevant state such as the connection
// request instance and the connection itself, and finally notifies the address
// manager of the attempt.
func (s *server) outboundPeerConnected(c *connmgr.ConnReq, conn net.Conn) {
	sp := newServerPeer(s, c.Permanent)
	p, err := peer.NewOutboundPeer(newPeerConfig(sp), c.Addr.String())
	if err != nil {
		srvrLog.Debugf("Cannot create outbound peer %s: %v", c.Addr, err)
		s.connManager.Disconnect(c.ID())
		return
	}
	sp.Peer = p
	sp.connReq = c
	sp.isWhitelisted = isWhitelisted(conn.RemoteAddr())
	sp.AssociateConnection(conn)
	go s.peerDoneHandler(sp)
	err = s.addrManager.Attempt(sp.NA())
	if err != nil {
		srvrLog.Debugf("Marking address as attempted failed: %v", err)
	}
}

// peerDoneHandler handles peer disconnects by notifying the server that it's
// done along with other performing other desirable cleanup.
func (s *server) peerDoneHandler(sp *serverPeer) {
	sp.WaitForDisconnect()
	s.donePeers <- sp

	// Notify the net sync manager the peer is gone if it was ever notified that
	// the peer existed.
	if sp.syncNotified {
		s.syncManager.DonePeer(sp.Peer)
	}

	if sp.VersionKnown() {
		tipHash := &s.chain.BestSnapshot().Hash
		isTreasuryEnabled, err := s.chain.IsTreasuryAgendaActive(tipHash)
		if err != nil {
			srvrLog.Errorf("Could not obtain treasury agenda status: %v", err)
		}

		// Evict any remaining orphans that were sent by the peer.
		numEvicted := s.txMemPool.RemoveOrphansByTag(mempool.Tag(sp.ID()),
			isTreasuryEnabled)
		if numEvicted > 0 {
			srvrLog.Debugf("Evicted %d %s from peer %v (id %d)", numEvicted,
				pickNoun(numEvicted, "orphan", "orphans"), sp, sp.ID())
		}
	}
	close(sp.quit)
}

// peerHandler is used to handle peer operations such as adding and removing
// peers to and from the server, banning peers, and broadcasting messages to
// peers.  It must be run in a goroutine.
func (s *server) peerHandler(ctx context.Context) {
	// Start the address manager which is needed by peers.  This is done here
	// since its lifecycle is closely tied to this handler and rather than
	// adding more channels to synchronize things, it's easier and slightly
	// faster to simply start and stop it in this handler.
	s.addrManager.Start()

	srvrLog.Tracef("Starting peer handler")

	state := &peerState{
		inboundPeers:    make(map[int32]*serverPeer),
		persistentPeers: make(map[int32]*serverPeer),
		outboundPeers:   make(map[int32]*serverPeer),
		banned:          make(map[string]time.Time),
		outboundGroups:  make(map[string]int),
		subCache: &naSubmissionCache{
			cache: make(map[string]*naSubmission, maxCachedNaSubmissions),
			limit: maxCachedNaSubmissions,
		},
	}

out:
	for {
		select {
		// New peers connected to the server.
		case p := <-s.newPeers:
			s.handleAddPeerMsg(state, p)

			// Signal the net sync manager this peer is a new sync candidate
			// unless it was disconnected above.
			if p.Connected() {
				s.syncManager.NewPeer(p.Peer)
				p.syncNotified = true
			}

		// Disconnected peers.
		case p := <-s.donePeers:
			s.handleDonePeerMsg(state, p)

		// Peer to ban.
		case p := <-s.banPeers:
			s.handleBanPeerMsg(state, p)

		// New inventory to potentially be relayed to other peers.
		case invMsg := <-s.relayInv:
			s.handleRelayInvMsg(state, invMsg)

		// Message to broadcast to all connected peers except those
		// which are excluded by the message.
		case bmsg := <-s.broadcast:
			s.handleBroadcastMsg(state, &bmsg)

		case qmsg := <-s.query:
			s.handleQuery(state, qmsg)

		case <-ctx.Done():
			// Disconnect all peers on server shutdown.
			state.forAllPeers(func(sp *serverPeer) {
				srvrLog.Tracef("Shutdown peer %s", sp)
				sp.Disconnect()
			})
			break out
		}
	}

	s.addrManager.Stop()

	// Drain channels before exiting so nothing is left waiting around
	// to send.
cleanup:
	for {
		select {
		case <-s.newPeers:
		case <-s.donePeers:
		case <-s.relayInv:
		case <-s.broadcast:
		case <-s.query:
		default:
			break cleanup
		}
	}

	s.wg.Done()
	srvrLog.Tracef("Peer handler done")
}

// AddPeer adds a new peer that has already been connected to the server.
func (s *server) AddPeer(sp *serverPeer) {
	s.newPeers <- sp
}

// BanPeer bans a peer that has already been connected to the server by ip
// unless banning is disabled or the peer has been whitelisted.
func (s *server) BanPeer(sp *serverPeer) {
	if cfg.DisableBanning || sp.isWhitelisted {
		return
	}
	sp.Disconnect()
	s.banPeers <- sp
}

// RelayInventory relays the passed inventory vector to all connected peers
// that are not already known to have it.
func (s *server) RelayInventory(invVect *wire.InvVect, data interface{}, immediate bool) {
	s.relayInv <- relayMsg{invVect: invVect, data: data, immediate: immediate}
}

// BroadcastMessage sends msg to all peers currently connected to the server
// except those in the passed peers to exclude.
func (s *server) BroadcastMessage(msg wire.Message, exclPeers ...*serverPeer) {
	bmsg := broadcastMsg{message: msg, excludePeers: exclPeers}
	s.broadcast <- bmsg
}

// ConnectedCount returns the number of currently connected peers.
func (s *server) ConnectedCount() int32 {
	replyChan := make(chan int32)
	s.query <- getConnCountMsg{reply: replyChan}
	return <-replyChan
}

// OutboundGroupCount returns the number of peers connected to the given
// outbound group key.
func (s *server) OutboundGroupCount(key string) int {
	replyChan := make(chan int)
	s.query <- getOutboundGroup{key: key, reply: replyChan}
	return <-replyChan
}

// AddedNodeInfo returns an array of dcrjson.GetAddedNodeInfoResult structures
// describing the persistent (added) nodes.
func (s *server) AddedNodeInfo() []*serverPeer {
	replyChan := make(chan []*serverPeer)
	s.query <- getAddedNodesMsg{reply: replyChan}
	return <-replyChan
}

// AddBytesSent adds the passed number of bytes to the total bytes sent counter
// for the server.  It is safe for concurrent access.
func (s *server) AddBytesSent(bytesSent uint64) {
	atomic.AddUint64(&s.bytesSent, bytesSent)
}

// AddBytesReceived adds the passed number of bytes to the total bytes received
// counter for the server.  It is safe for concurrent access.
func (s *server) AddBytesReceived(bytesReceived uint64) {
	atomic.AddUint64(&s.bytesReceived, bytesReceived)
}

// NetTotals returns the sum of all bytes received and sent across the network
// for all peers.  It is safe for concurrent access.
func (s *server) NetTotals() (uint64, uint64) {
	return atomic.LoadUint64(&s.bytesReceived),
		atomic.LoadUint64(&s.bytesSent)
}

// notifiedWinningTickets returns whether or not the winning tickets
// notification for the specified block hash has already been sent.
func (s *server) notifiedWinningTickets(hash *chainhash.Hash) bool {
	s.lotteryDataBroadcastMtx.Lock()
	_, beenNotified := s.lotteryDataBroadcast[*hash]
	s.lotteryDataBroadcastMtx.Unlock()
	return beenNotified
}

// headerApprovesParent returns whether or not the vote bits in the passed
// header indicate the regular transaction tree of the parent block should be
// considered valid.
func headerApprovesParent(header *wire.BlockHeader) bool {
	return dcrutil.IsFlagSet16(header.VoteBits, dcrutil.BlockValid)
}

// isDoubleSpendOrDuplicateError returns whether or not the passed error, which
// is expected to have come from mempool, indicates a transaction was rejected
// either due to containing a double spend or already existing in the pool.
func isDoubleSpendOrDuplicateError(err error) bool {
	switch {
	case errors.Is(err, mempool.ErrDuplicate):
		return true
	case errors.Is(err, mempool.ErrAlreadyExists):
		return true
	case errors.Is(err, blockchain.ErrMissingTxOut):
		return true
	}

	return false
}

// proactivelyEvictSigCacheEntries fetches the block that is
// txscript.ProactiveEvictionDepth levels deep from bestHeight and passes it to
// SigCache to evict the entries associated with the transactions in that block.
func (s *server) proactivelyEvictSigCacheEntries(bestHeight int64) {
	// Nothing to do before the eviction depth is reached.
	if bestHeight <= txscript.ProactiveEvictionDepth {
		return
	}

	evictHeight := bestHeight - txscript.ProactiveEvictionDepth
	block, err := s.chain.BlockByHeight(evictHeight)
	if err != nil {
		srvrLog.Warnf("Failed to retrieve the block at height %d: %v",
			evictHeight, err)
		return
	}

	s.sigCache.EvictEntries(block.MsgBlock())
}

// handleBlockchainNotification handles notifications from blockchain.  It does
// things such as request orphan block parents and relay accepted blocks to
// connected peers.
func (s *server) handleBlockchainNotification(notification *blockchain.Notification) {
	switch notification.Type {
	// A block that intends to extend the main chain has passed all sanity and
	// contextual checks and the chain is believed to be current.  Relay it to
	// other peers.
	case blockchain.NTNewTipBlockChecked:
		// WARNING: The chain lock is not released before sending this
		// notification, so care must be taken to avoid calling chain functions
		// which could result in a deadlock.
		block, ok := notification.Data.(*dcrutil.Block)
		if !ok {
			syncLog.Warnf("New tip block checked notification is not a block.")
			break
		}

		// Generate the inventory vector and relay it immediately.
		iv := wire.NewInvVect(wire.InvTypeBlock, block.Hash())
		s.RelayInventory(iv, block.MsgBlock().Header, true)
		s.announcedBlockMtx.Lock()
		s.announcedBlock = block.Hash()
		s.announcedBlockMtx.Unlock()

	// A block has been accepted into the block chain.  Relay it to other peers
	// (will be ignored if already relayed via NTNewTipBlockChecked) and
	// possibly notify RPC clients with the winning tickets.
	case blockchain.NTBlockAccepted:
		// Don't relay or notify RPC clients with winning tickets if we are not
		// current. Other peers that are current should already know about it
		// and clients, such as wallets, shouldn't be voting on old blocks.
		if !s.syncManager.IsCurrent() {
			return
		}

		band, ok := notification.Data.(*blockchain.BlockAcceptedNtfnsData)
		if !ok {
			syncLog.Warnf("Chain accepted notification is not " +
				"BlockAcceptedNtfnsData.")
			break
		}
		block := band.Block

		// Send a winning tickets notification as needed.  The notification will
		// only be sent when the following conditions hold:
		//
		// - The RPC server is running
		// - The block that would build on this one is at or after the height
		//   voting begins
		// - The block that would build on this one would not cause a reorg
		//   larger than the max reorg notify depth
		// - This block is after the final checkpoint height
		// - A notification for this block has not already been sent
		//
		// To help visualize the math here, consider the following two competing
		// branches:
		//
		// 100 -> 101  -> 102  -> 103 -> 104 -> 105 -> 106
		//    \-> 101' -> 102'
		//
		// Further, assume that this is a notification for block 103', or in
		// other words, it is extending the shorter side chain.  The reorg depth
		// would be 106 - (103 - 3) = 6.  This should intuitively make sense,
		// because if the side chain were to be extended enough to become the
		// best chain, it would result in a reorg that would remove 6 blocks,
		// namely blocks 101, 102, 103, 104, 105, and 106.
		//
		// Additionally, a notification will NOT be sent for mainnet once block
		// height 534304 has been reached and the block version is prior to 8.
		// The intent is for future code to perform this type of check more
		// dynamically so it happens for all upgrades after a certain time frame
		// is provided for upgrades to occur, but it is hard coded for now in
		// the interest of time to allow PoS to force PoW to upgrade.
		blockHash := block.Hash()
		bestHeight := band.BestHeight
		blockHeader := &block.MsgBlock().Header
		blockHeight := int64(blockHeader.Height)
		reorgDepth := bestHeight - (blockHeight - band.ForkLen)
		isOldMainnetBlock := s.chainParams.Net == wire.MainNet &&
			blockHeight >= 534304 && blockHeader.Version < 8
		if s.rpcServer != nil &&
			blockHeight >= s.chainParams.StakeValidationHeight-1 &&
			reorgDepth < maxReorgDepthNotify &&
			blockHeight > s.chainParams.LatestCheckpointHeight() &&
			!isOldMainnetBlock &&
			!s.notifiedWinningTickets(blockHash) {

			// Obtain the winning tickets for this block.  handleNotifyMsg
			// should be safe for concurrent access of things contained within
			// blockchain.
			wt, _, _, err := s.chain.LotteryDataForBlock(blockHash)
			if err != nil {
				syncLog.Errorf("Couldn't calculate winning tickets for "+
					"accepted block %v: %v", blockHash, err.Error())
			} else {
				// Notify registered websocket clients of newly eligible tickets
				// to vote on.
				s.rpcServer.NotifyWinningTickets(&rpcserver.WinningTicketsNtfnData{
					BlockHash:   *blockHash,
					BlockHeight: blockHeight,
					Tickets:     wt,
				})

				s.lotteryDataBroadcastMtx.Lock()
				s.lotteryDataBroadcast[*blockHash] = struct{}{}
				s.lotteryDataBroadcastMtx.Unlock()
			}
		}

		// Generate the inventory vector and relay it immediately if not already
		// known to have been sent in NTNewTipBlockChecked.
		s.announcedBlockMtx.Lock()
		sent := s.announcedBlock != nil && *s.announcedBlock == *blockHash
		s.announcedBlock = nil
		s.announcedBlockMtx.Unlock()
		if !sent {
			iv := wire.NewInvVect(wire.InvTypeBlock, blockHash)
			s.RelayInventory(iv, block.MsgBlock().Header, true)
		}

		// Inform the background block template generator about the accepted
		// block.
		if s.bg != nil {
			s.bg.BlockAccepted(block)
		}

		if !s.feeEstimator.IsEnabled() {
			// fee estimation can only start after we have performed an initial
			// sync, otherwise we'll start adding mempool transactions at the
			// wrong height.
			s.feeEstimator.Enable(block.Height())
		}

	// A block has been connected to the main block chain.
	case blockchain.NTBlockConnected:
		ntfn, ok := notification.Data.(*blockchain.BlockConnectedNtfnsData)
		if !ok {
			syncLog.Warnf("Block connected notification is not " +
				"BlockConnectedNtfnsData")
			break
		}
		block := ntfn.Block
		parentBlock := ntfn.ParentBlock
		isTreasuryEnabled := ntfn.IsTreasuryActive

		// Account for transactions mined in the newly connected block for fee
		// estimation. This must be done before attempting to remove
		// transactions from the mempool because the mempool will alert the
		// estimator of the txs that are leaving
		s.feeEstimator.ProcessBlock(block)

		// TODO: In the case the new tip disapproves the previous block, any
		// transactions the previous block contains in its regular tree which
		// double spend the same inputs as transactions in either tree of the
		// current tip should ideally be tracked in the pool as eligible for
		// inclusion in an alternative tip (side chain block) in case the
		// current tip block does not get enough votes.  However, the
		// transaction pool currently does not provide any way to distinguish
		// this condition and thus only provides tracking based on the current
		// tip.  In order to handle this condition, the pool would have to
		// provide a way to track and independently query which txns are
		// eligible based on the current tip both approving and disapproving the
		// previous block as well as the previous block itself.

		// Remove all of the regular and stake transactions in the connected
		// block from the transaction pool.  Also, remove any transactions which
		// are now double spends as a result of these new transactions.
		// Finally, remove any transaction that is no longer an orphan.
		// Transactions which depend on a confirmed transaction are NOT removed
		// recursively because they are still valid.  Also, the coinbase of the
		// regular tx tree is skipped because the transaction pool doesn't (and
		// can't) have regular tree coinbase transactions in it.
		//
		// Also, in the case the RPC server is enabled, stop rebroadcasting any
		// transactions in the block that were setup to be rebroadcast.
		txMemPool := s.txMemPool
		handleConnectedBlockTxns := func(txns []*dcrutil.Tx) {
			for _, tx := range txns {
				txMemPool.RemoveTransaction(tx, false, isTreasuryEnabled)
				txMemPool.MaybeAcceptDependents(tx, isTreasuryEnabled)
				txMemPool.RemoveDoubleSpends(tx, isTreasuryEnabled)
				txMemPool.RemoveOrphan(tx, isTreasuryEnabled)
				acceptedTxs := txMemPool.ProcessOrphans(tx, isTreasuryEnabled)
				s.AnnounceNewTransactions(acceptedTxs)

				// Now that this block is in the blockchain, mark the
				// transaction (except the coinbase) as no longer needing
				// rebroadcasting and keep track of it for use when avoiding
				// requests for recently confirmed transactions.
				s.TransactionConfirmed(tx)
			}
		}

		// Add regular transactions back to the mempool, excluding the coinbase
		// since it does not belong in the mempool.
		handleConnectedBlockTxns(block.Transactions()[1:])
		if isTreasuryEnabled {
			// Skip treasurybase
			handleConnectedBlockTxns(block.STransactions()[1:])
		} else {
			handleConnectedBlockTxns(block.STransactions())
		}

		// In the case the regular tree of the previous block was disapproved,
		// add all of the its transactions, with the exception of the coinbase,
		// back to the transaction pool to be mined in a future block.
		//
		// Notice that some of those transactions might have been included in
		// the current block and others might also be spending some of the same
		// outputs that transactions in the previous originally block spent.
		// This is the expected behavior because disapproval of the regular tree
		// of the previous block essentially makes it as if those transactions
		// never happened.
		//
		// Finally, if transactions fail to add to the pool for some reason
		// other than the pool already having it (a duplicate) or now being a
		// double spend, remove all transactions that depend on it as well.
		// The dependents are not removed for double spends because the only
		// way a transaction which was not a double spend in the previous block
		// to now be one is due to some transaction in the current block
		// (probably the same one) also spending those outputs, and, in that
		// case, anything that happens to be in the pool which depends on the
		// transaction is still valid.
		if !headerApprovesParent(&block.MsgBlock().Header) {
			for _, tx := range parentBlock.Transactions()[1:] {
				_, err := txMemPool.MaybeAcceptTransaction(tx, false, true)
				if err != nil && !isDoubleSpendOrDuplicateError(err) {
					txMemPool.RemoveTransaction(tx, true, isTreasuryEnabled)
				}
			}
		}

		if r := s.rpcServer; r != nil {
			// Filter and update the rebroadcast inventory.
			s.PruneRebroadcastInventory()

			// Notify registered websocket clients of incoming block.
			r.NotifyBlockConnected(block)
		}

		if s.bg != nil {
			s.bg.BlockConnected(block)
		}

		// Proactively evict signature cache entries that are virtually
		// guaranteed to no longer be useful.
		s.proactivelyEvictSigCacheEntries(block.Height())

	// Stake tickets are spent or missed from the most recently connected block.
	case blockchain.NTSpentAndMissedTickets:
		// WARNING: The chain lock is not released before sending this
		// notification, so care must be taken to avoid calling chain functions
		// which could result in a deadlock.
		tnd, ok := notification.Data.(*blockchain.TicketNotificationsData)
		if !ok {
			syncLog.Warnf("Tickets connected notification is not " +
				"TicketNotificationsData")
			break
		}

		if r := s.rpcServer; r != nil {
			r.NotifySpentAndMissedTickets(tnd)
		}

	// Stake tickets are matured from the most recently connected block.
	case blockchain.NTNewTickets:
		// WARNING: The chain lock is not released before sending this
		// notification, so care must be taken to avoid calling chain functions
		// which could result in a deadlock.
		tnd, ok := notification.Data.(*blockchain.TicketNotificationsData)
		if !ok {
			syncLog.Warnf("Tickets connected notification is not " +
				"TicketNotificationsData")
			break
		}

		if r := s.rpcServer; r != nil {
			r.NotifyNewTickets(tnd)
		}

	// A block has been disconnected from the main block chain.
	case blockchain.NTBlockDisconnected:
		ntfn, ok := notification.Data.(*blockchain.BlockDisconnectedNtfnsData)
		if !ok {
			syncLog.Warnf("Block disconnected notification is not " +
				"BlockDisconnectedNtfnsData.")
			break
		}
		block := ntfn.Block
		parentBlock := ntfn.ParentBlock
		isTreasuryEnabled := ntfn.IsTreasuryActive

		// In the case the regular tree of the previous block was disapproved,
		// disconnecting the current block makes all of those transactions valid
		// again.  Thus, with the exception of the coinbase, remove all of those
		// transactions and any that are now double spends from the transaction
		// pool.  Transactions which depend on a confirmed transaction are NOT
		// removed recursively because they are still valid.
		txMemPool := s.txMemPool
		if !headerApprovesParent(&block.MsgBlock().Header) {
			for _, tx := range parentBlock.Transactions()[1:] {
				txMemPool.RemoveTransaction(tx, false, isTreasuryEnabled)
				txMemPool.MaybeAcceptDependents(tx, isTreasuryEnabled)
				txMemPool.RemoveDoubleSpends(tx, isTreasuryEnabled)
				txMemPool.RemoveOrphan(tx, isTreasuryEnabled)
				txMemPool.ProcessOrphans(tx, isTreasuryEnabled)
			}
		}

		// Add all of the regular and stake transactions in the disconnected
		// block, with the exception of the regular tree coinbase, back to the
		// transaction pool to be mined in a future block.
		//
		// Notice that, in the case the previous block was disapproved, some of
		// the transactions in the block being disconnected might have been
		// included in the previous block and others might also have been
		// spending some of the same outputs.  This is the expected behavior
		// because disapproval of the regular tree of the previous block
		// essentially makes it as if those transactions never happened, so
		// disconnecting the block that disapproved those transactions
		// effectively revives them.
		//
		// Finally, if transactions fail to add to the pool for some reason
		// other than the pool already having it (a duplicate) or now being a
		// double spend, remove all transactions that depend on it as well.
		// The dependents are not removed for double spends because the only
		// way a transaction which was not a double spend in the block being
		// disconnected to now be one is due to some transaction in the previous
		// block (probably the same one), which was disapproved, also spending
		// those outputs, and, in that case, anything that happens to be in the
		// pool which depends on the transaction is still valid.
		handleDisconnectedBlockTxns := func(txns []*dcrutil.Tx) {
			for _, tx := range txns {
				_, err := txMemPool.MaybeAcceptTransaction(tx, false, true)
				if err != nil && !isDoubleSpendOrDuplicateError(err) {
					txMemPool.RemoveTransaction(tx, true, isTreasuryEnabled)
				}
			}
		}
		handleDisconnectedBlockTxns(block.Transactions()[1:])

		if isTreasuryEnabled {
			// Skip treasurybase
			handleDisconnectedBlockTxns(block.STransactions()[1:])
		} else {
			handleDisconnectedBlockTxns(block.STransactions())
		}

		if s.bg != nil {
			s.bg.BlockDisconnected(block)
		}

		// Notify registered websocket clients.
		if r := s.rpcServer; r != nil {
			// Filter and update the rebroadcast inventory.
			s.PruneRebroadcastInventory()

			// Notify registered websocket clients.
			r.NotifyBlockDisconnected(block)
		}

	// Chain reorganization has commenced.
	case blockchain.NTChainReorgStarted:
		// WARNING: The chain lock is not released before sending this
		// notification, so care must be taken to avoid calling chain functions
		// which could result in a deadlock.
		if s.bg != nil {
			s.bg.ChainReorgStarted()
		}

	// Chain reorganization has concluded.
	case blockchain.NTChainReorgDone:
		// WARNING: The chain lock is not released before sending this
		// notification, so care must be taken to avoid calling chain functions
		// which could result in a deadlock.
		if s.bg != nil {
			s.bg.ChainReorgDone()
		}

	// The blockchain is reorganizing.
	case blockchain.NTReorganization:
		// WARNING: The chain lock is not released before sending this
		// notification, so care must be taken to avoid calling chain functions
		// which could result in a deadlock.
		rd, ok := notification.Data.(*blockchain.ReorganizationNtfnsData)
		if !ok {
			syncLog.Warnf("Chain reorganization notification is malformed")
			break
		}

		// Notify registered websocket clients.
		if r := s.rpcServer; r != nil {
			r.NotifyReorganization(rd)
		}
	}
}

// rebroadcastHandler keeps track of user submitted inventories that we have
// sent out but have not yet made it into a block. We periodically rebroadcast
// them in case our peers restarted or otherwise lost track of them.
func (s *server) rebroadcastHandler(ctx context.Context) {
	// Wait 5 min before first tx rebroadcast.
	timer := time.NewTimer(5 * time.Minute)
	pendingInvs := make(map[wire.InvVect]interface{})
out:
	for {
		select {
		case riv := <-s.modifyRebroadcastInv:
			switch msg := riv.(type) {

			// Incoming InvVects are added to our map of RPC txs.
			case broadcastInventoryAdd:
				pendingInvs[*msg.invVect] = msg.data

			// When an InvVect has been added to a block, we can
			// now remove it, if it was present.
			case broadcastInventoryDel:
				delete(pendingInvs, *msg)

			case broadcastPruneInventory:
				best := s.chain.BestSnapshot()
				isTreasuryEnabled, err := s.chain.IsTreasuryAgendaActive(&best.Hash)
				if err != nil {
					srvrLog.Errorf("Could not obtain treasury agenda status: %v",
						err)
					break
				}

				for iv, data := range pendingInvs {
					tx, ok := data.(*dcrutil.Tx)
					if !ok {
						continue
					}

					txType := stake.DetermineTxType(tx.MsgTx(),
						isTreasuryEnabled)

					// Remove the ticket rebroadcast if the amount not equal to
					// the current stake difficulty.
					if txType == stake.TxTypeSStx &&
						tx.MsgTx().TxOut[0].Value != best.NextStakeDiff {
						delete(pendingInvs, iv)
						srvrLog.Debugf("Pending ticket purchase broadcast "+
							"inventory for tx %v removed. Ticket value not "+
							"equal to stake difficulty.", tx.Hash())
						continue
					}

					// Remove the ticket rebroadcast if it has already expired.
					if txType == stake.TxTypeSStx &&
						blockchain.IsExpired(tx, best.Height) {
						delete(pendingInvs, iv)
						srvrLog.Debugf("Pending ticket purchase broadcast "+
							"inventory for tx %v removed. Transaction "+
							"expired.", tx.Hash())
						continue
					}

					// Remove the revocation rebroadcast if the associated
					// ticket has been revived.
					if txType == stake.TxTypeSSRtx {
						refSStxHash := tx.MsgTx().TxIn[0].PreviousOutPoint.Hash
						if !s.chain.CheckLiveTicket(refSStxHash) {
							delete(pendingInvs, iv)
							srvrLog.Debugf("Pending revocation broadcast "+
								"inventory for tx %v removed. "+
								"Associated ticket was revived.", tx.Hash())
							continue
						}
					}
				}
			}

		case <-timer.C:
			// Any inventory we have has not made it into a block
			// yet. We periodically resubmit them until they have.
			for iv, data := range pendingInvs {
				ivCopy := iv
				s.RelayInventory(&ivCopy, data, false)
			}

			// Process at a random time up to 30mins (in seconds)
			// in the future.
			timer.Reset(time.Second *
				time.Duration(randomUint16Number(1800)))

		case <-ctx.Done():
			break out
		}
	}

	timer.Stop()

	// Drain channels before exiting so nothing is left waiting around
	// to send.
cleanup:
	for {
		select {
		case <-s.modifyRebroadcastInv:
		default:
			break cleanup
		}
	}

	s.wg.Done()
}

// querySeeders queries the configured seeders to discover peers that supported
// the required services and adds the discovered peers to the address manager.
// Each seeder is contacted in a separate goroutine.
func (s *server) querySeeders(ctx context.Context) {
	// Add peers discovered through DNS to the address manager.
	seeders := s.chainParams.Seeders()
	for _, seeder := range seeders {
		go func(seeder string) {
			ctx, cancel := context.WithTimeout(ctx, time.Minute)
			defer cancel()

			addrs, err := connmgr.SeedAddrs(ctx, seeder, dcrdDial,
				connmgr.SeedFilterServices(defaultRequiredServices))
			if err != nil {
				srvrLog.Infof("seeder '%s' error: %v", seeder, err)
				return
			}

			// Nothing to do if the seeder didn't return any addresses.
			if len(addrs) == 0 {
				return
			}

			// Lookup the IP of the https seeder to use as the source of the
			// seeded addresses.  In the incredibly rare event that the lookup
			// fails after it just succeeded, fall back to using the first
			// returned address as the source.
			srcAddr := addrs[0]
			srcIPs, err := dcrdLookup(seeder)
			if err == nil && len(srcIPs) > 0 {
				const httpsPort = 443
				srcAddr = wire.NewNetAddressIPPort(srcIPs[0], httpsPort, 0)
			}
			s.addrManager.AddAddresses(addrs, srcAddr)
		}(seeder)
	}
}

// Run starts the server and blocks until the provided context is cancelled.
// This entails accepting connections from peers.
func (s *server) Run(ctx context.Context) {
	srvrLog.Trace("Starting server")

	// Start the peer handler which in turn starts the address manager.
	s.wg.Add(1)
	go s.peerHandler(ctx)

	// Start the sync manager.
	s.wg.Add(1)
	go func(ctx context.Context, s *server) {
		s.syncManager.Run(ctx)
		s.wg.Done()
	}(ctx, s)

	// Query the seeders and start the connection manager.
	s.wg.Add(1)
	go func(ctx context.Context, s *server) {
		if !cfg.DisableSeeders {
			s.querySeeders(ctx)
		}
		s.connManager.Run(ctx)
		s.wg.Done()
	}(ctx, s)

	if s.nat != nil {
		s.wg.Add(1)
		go s.upnpUpdateThread(ctx)
	}

	if !cfg.DisableRPC {
		// Start the rebroadcastHandler, which ensures user tx received by
		// the RPC server are rebroadcast until being included in a block.
		s.wg.Add(1)
		go s.rebroadcastHandler(ctx)

		s.wg.Add(1)
		go func(ctx context.Context, s *server) {
			s.rpcServer.Run(ctx)
			s.wg.Done()
		}(ctx, s)
	}

	// Start the background block template generator and CPU miner if the config
	// provides a mining address.
	if len(cfg.miningAddrs) > 0 {
		s.wg.Add(2)
		go func(ctx context.Context, s *server) {
			s.bg.Run(ctx)
			s.wg.Done()
		}(ctx, s)
		go func(ctx context.Context, s *server) {
			s.cpuMiner.Run(ctx)
			s.wg.Done()
		}(ctx, s)

		// The CPU miner is started without any workers which means it is idle.
		// Start mining by setting the default number of workers when requested.
		if cfg.Generate {
			s.cpuMiner.SetNumWorkers(-1)
		}
	}

	// Wait until the server is signalled to shutdown.
	<-ctx.Done()
	atomic.AddInt32(&s.shutdown, 1)

	srvrLog.Warnf("Server shutting down")

	s.feeEstimator.Close()

	s.chain.ShutdownUtxoCache()

	s.wg.Wait()
	srvrLog.Trace("Server stopped")
}

// parseListeners determines whether each listen address is IPv4 and IPv6 and
// returns a slice of appropriate net.Addrs to listen on with TCP. It also
// properly detects addresses which apply to "all interfaces" and adds the
// address as both IPv4 and IPv6.
func parseListeners(addrs []string) ([]net.Addr, error) {
	netAddrs := make([]net.Addr, 0, len(addrs)*2)
	for _, addr := range addrs {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			// Shouldn't happen due to already being normalized.
			return nil, err
		}

		// Empty host or host of * on plan9 is both IPv4 and IPv6.
		if host == "" || (host == "*" && runtime.GOOS == "plan9") {
			netAddrs = append(netAddrs, simpleAddr{net: "tcp4", addr: addr})
			netAddrs = append(netAddrs, simpleAddr{net: "tcp6", addr: addr})
			continue
		}

		// Strip IPv6 zone id if present since net.ParseIP does not
		// handle it.
		zoneIndex := strings.LastIndex(host, "%")
		if zoneIndex > 0 {
			host = host[:zoneIndex]
		}

		// Parse the IP.
		ip := net.ParseIP(host)
		if ip == nil {
			return nil, fmt.Errorf("'%s' is not a valid IP address", host)
		}

		// To4 returns nil when the IP is not an IPv4 address, so use
		// this determine the address type.
		if ip.To4() == nil {
			netAddrs = append(netAddrs, simpleAddr{net: "tcp6", addr: addr})
		} else {
			netAddrs = append(netAddrs, simpleAddr{net: "tcp4", addr: addr})
		}
	}
	return netAddrs, nil
}

func (s *server) upnpUpdateThread(ctx context.Context) {
	// Go off immediately to prevent code duplication, thereafter we renew
	// lease every 15 minutes.
	timer := time.NewTimer(0 * time.Second)
	lport, _ := strconv.ParseInt(s.chainParams.DefaultPort, 10, 16)

	first := true
out:
	for {
		select {
		case <-timer.C:
			// TODO: pick external port more cleverly
			// TODO: know which ports we are listening to on an external net.
			// TODO: if specific listen port doesn't work then ask for wildcard
			// listen port?
			// XXX this assumes timeout is in seconds.
			listenPort, err := s.nat.AddPortMapping("tcp", int(lport), int(lport),
				"dcrd listen port", 20*60)
			if err != nil {
				srvrLog.Warnf("can't add UPnP port mapping: %v", err)
			}
			if first && err == nil {
				// TODO: look this up periodically to see if upnp domain changed
				// and so did ip.
				externalip, err := s.nat.GetExternalAddress()
				if err != nil {
					srvrLog.Warnf("UPnP can't get external address: %v", err)
					continue out
				}
				na := wire.NewNetAddressIPPort(externalip, uint16(listenPort),
					s.services)
				err = s.addrManager.AddLocalAddress(na, addrmgr.UpnpPrio)
				if err != nil {
					srvrLog.Warnf("Failed to add UPnP local address %s: %v",
						na.IP.String(), err)
				} else {
					srvrLog.Warnf("Successfully bound via UPnP to %s",
						addrmgr.NetAddressKey(na))
					first = false
				}
			}
			timer.Reset(time.Minute * 15)

		case <-ctx.Done():
			break out
		}
	}

	timer.Stop()

	err := s.nat.DeletePortMapping("tcp", int(lport), int(lport))
	if err != nil {
		srvrLog.Warnf("unable to remove UPnP port mapping: %v", err)
	} else {
		srvrLog.Debugf("successfully disestablished UPnP port mapping")
	}

	s.wg.Done()
}

// standardScriptVerifyFlags returns the script flags that should be used when
// executing transaction scripts to enforce additional checks which are required
// for the script to be considered standard.  Note these flags are different
// than what is required for the consensus rules in that they are more strict.
func standardScriptVerifyFlags(chain *blockchain.BlockChain) (txscript.ScriptFlags, error) {
	scriptFlags := mempool.BaseStandardVerifyFlags

	// Enable validation of OP_SHA256 when the associated agenda is active.
	tipHash := &chain.BestSnapshot().Hash
	isActive, err := chain.IsLNFeaturesAgendaActive(tipHash)
	if err != nil {
		return 0, err
	}
	if isActive {
		scriptFlags |= txscript.ScriptVerifySHA256
	}

	// Enable validation of treasury-related opcodes when the associated agenda
	// is active.
	isActive, err = chain.IsTreasuryAgendaActive(tipHash)
	if err != nil {
		return 0, err
	}
	if isActive {
		scriptFlags |= txscript.ScriptVerifyTreasury
	}

	return scriptFlags, nil
}

// genCertPair generates a key/cert pair to the paths provided.
func genCertPair(certFile, keyFile string, altDNSNames []string, tlsCurve elliptic.Curve) error {
	rpcsLog.Infof("Generating TLS certificates...")

	org := "dcrd autogenerated cert"
	validUntil := time.Now().Add(10 * 365 * 24 * time.Hour)
	cert, key, err := certgen.NewTLSCertPair(tlsCurve, org,
		validUntil, altDNSNames)
	if err != nil {
		return err
	}

	// Write cert and key files.
	if err = ioutil.WriteFile(certFile, cert, 0644); err != nil {
		return err
	}
	if err = ioutil.WriteFile(keyFile, key, 0600); err != nil {
		os.Remove(certFile)
		return err
	}

	rpcsLog.Infof("Done generating TLS certificates")
	return nil
}

// setupRPCListeners returns a slice of listeners that are configured for use
// with the RPC server depending on the configuration settings for listen
// addresses and TLS.
func setupRPCListeners() ([]net.Listener, error) {
	// Setup TLS if not disabled.
	listenFunc := net.Listen
	if !cfg.DisableRPC && !cfg.DisableTLS {
		// Generate the TLS cert and key file if both don't already exist.
		keyFileExists := fileExists(cfg.RPCKey)
		certFileExists := fileExists(cfg.RPCCert)
		if len(cfg.AltDNSNames) != 0 && (keyFileExists || certFileExists) {
			rpcsLog.Warn("Additional DNS names specified when TLS " +
				"certificates already exist will NOT be included:")
			rpcsLog.Warnf("- In order to create TLS certs that include the "+
				"additional DNS names, delete %q and %q and restart the server",
				cfg.RPCKey, cfg.RPCCert)
		}
		if !keyFileExists && !certFileExists {
			curve, err := tlsCurve(cfg.TLSCurve)
			if err != nil {
				return nil, err
			}
			err = genCertPair(cfg.RPCCert, cfg.RPCKey, cfg.AltDNSNames, curve)
			if err != nil {
				return nil, err
			}
		}
		keypair, err := tls.LoadX509KeyPair(cfg.RPCCert, cfg.RPCKey)
		if err != nil {
			return nil, err
		}

		tlsConfig := tls.Config{
			Certificates: []tls.Certificate{keypair},
			MinVersion:   tls.VersionTLS12,
		}

		if cfg.RPCAuthType == authTypeClientCert {
			pemCerts, err := ioutil.ReadFile(cfg.RPCClientCAs)
			if err != nil {
				return nil, err
			}
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			tlsConfig.ClientCAs = x509.NewCertPool()
			if !tlsConfig.ClientCAs.AppendCertsFromPEM(pemCerts) {
				return nil, fmt.Errorf("no certificates found in %q",
					cfg.RPCClientCAs)
			}
		}

		// Change the standard net.Listen function to the tls one.
		listenFunc = func(net string, laddr string) (net.Listener, error) {
			return tls.Listen(net, laddr, &tlsConfig)
		}
	}

	netAddrs, err := parseListeners(cfg.RPCListeners)
	if err != nil {
		return nil, err
	}

	listeners := make([]net.Listener, 0, len(netAddrs))
	for _, addr := range netAddrs {
		listener, err := listenFunc(addr.Network(), addr.String())
		if err != nil {
			rpcsLog.Warnf("Can't listen on %s: %v", addr, err)
			continue
		}
		listeners = append(listeners, listener)
	}

	return listeners, nil
}

// newServer returns a new dcrd server configured to listen on addr for the
// decred network type specified by chainParams.  Use start to begin accepting
// connections from peers.
func newServer(ctx context.Context, listenAddrs []string, db database.DB, chainParams *chaincfg.Params, dataDir string) (*server, error) {
	amgr := addrmgr.New(cfg.DataDir, dcrdLookup)
	services := defaultServices

	var listeners []net.Listener
	var nat *upnpNAT
	if !cfg.DisableListen {
		var err error
		listeners, nat, err = initListeners(ctx, chainParams, amgr, listenAddrs,
			services)
		if err != nil {
			return nil, err
		}
		if len(listeners) == 0 {
			return nil, errors.New("no valid listen address")
		}
	}

	// Create a SigCache instance.
	sigCache, err := txscript.NewSigCache(cfg.SigCacheMaxSize)
	if err != nil {
		return nil, err
	}

	s := server{
		chainParams:          chainParams,
		addrManager:          amgr,
		newPeers:             make(chan *serverPeer, cfg.MaxPeers),
		donePeers:            make(chan *serverPeer, cfg.MaxPeers),
		banPeers:             make(chan *serverPeer, cfg.MaxPeers),
		query:                make(chan interface{}),
		relayInv:             make(chan relayMsg, cfg.MaxPeers),
		broadcast:            make(chan broadcastMsg, cfg.MaxPeers),
		modifyRebroadcastInv: make(chan interface{}),
		nat:                  nat,
		db:                   db,
		timeSource:           blockchain.NewMedianTime(),
		services:             services,
		sigCache:             sigCache,
		subsidyCache:         standalone.NewSubsidyCache(chainParams),
		lotteryDataBroadcast: make(map[chainhash.Hash]struct{}),
		recentlyConfirmedTxns: apbf.NewFilter(maxRecentlyConfirmedTxns,
			recentlyConfirmedTxnsFPRate),
	}

	// Create the transaction and address indexes if needed.
	//
	// CAUTION: the txindex needs to be first in the indexes array because
	// the addrindex uses data from the txindex during catchup.  If the
	// addrindex is run first, it may not have the transactions from the
	// current block indexed.
	var indexes []indexers.Indexer
	if cfg.TxIndex || cfg.AddrIndex {
		// Enable transaction index if address index is enabled since it
		// requires it.
		if !cfg.TxIndex {
			indxLog.Infof("Transaction index enabled because it " +
				"is required by the address index")
			cfg.TxIndex = true
		} else {
			indxLog.Info("Transaction index is enabled")
		}

		s.txIndex = indexers.NewTxIndex(db)
		indexes = append(indexes, s.txIndex)
	}
	if cfg.AddrIndex {
		indxLog.Info("Address index is enabled")
		s.addrIndex = indexers.NewAddrIndex(db, chainParams)
		indexes = append(indexes, s.addrIndex)
	}
	if !cfg.NoExistsAddrIndex {
		indxLog.Info("Exists address index is enabled")
		s.existsAddrIndex = indexers.NewExistsAddrIndex(db, chainParams)
		indexes = append(indexes, s.existsAddrIndex)
	}

	feC := fees.EstimatorConfig{
		MinBucketFee: cfg.minRelayTxFee,
		MaxBucketFee: dcrutil.Amount(fees.DefaultMaxBucketFeeMultiplier) * cfg.minRelayTxFee,
		MaxConfirms:  fees.DefaultMaxConfirmations,
		FeeRateStep:  fees.DefaultFeeRateStep,
		DatabaseFile: path.Join(dataDir, "feesdb"),

		// 1e5 is the previous (up to 1.1.0) mempool.DefaultMinRelayTxFee that
		// un-upgraded wallets will be using, so track this particular rate
		// explicitly. Note that bumping this value will cause the existing fees
		// database to become invalid and will force nodes to explicitly delete
		// it.
		ExtraBucketFee: 1e5,
	}
	fe, err := fees.NewEstimator(&feC)
	if err != nil {
		return nil, err
	}
	s.feeEstimator = fe

	// Create an index manager if any of the optional indexes are enabled.
	var indexManager indexers.IndexManager
	if len(indexes) > 0 {
		indexManager = indexers.NewManager(db, indexes, chainParams)
	}

	// Only configure checkpoints when enabled.
	var checkpoints []chaincfg.Checkpoint
	if !cfg.DisableCheckpoints {
		checkpoints = s.chainParams.Checkpoints
	}

	// Create a new block chain instance with the appropriate configuration.
	utxoCache := blockchain.NewUtxoCache(&blockchain.UtxoCacheConfig{
		DB:      s.db,
		MaxSize: uint64(cfg.UtxoCacheMaxSize) * 1024 * 1024,
	})
	s.chain, err = blockchain.New(ctx,
		&blockchain.Config{
			DB:            s.db,
			ChainParams:   s.chainParams,
			Checkpoints:   checkpoints,
			TimeSource:    s.timeSource,
			Notifications: s.handleBlockchainNotification,
			SigCache:      s.sigCache,
			SubsidyCache:  s.subsidyCache,
			IndexManager:  indexManager,
			UtxoCache:     utxoCache,
		})
	if err != nil {
		return nil, err
	}

	txC := mempool.Config{
		Policy: mempool.Policy{
			EnableAncestorTracking: len(cfg.miningAddrs) > 0,
			MaxTxVersion:           wire.TxVersionTreasury,
			DisableRelayPriority:   cfg.NoRelayPriority,
			AcceptNonStd:           cfg.AcceptNonStd,
			FreeTxRelayLimit:       cfg.FreeTxRelayLimit,
			MaxOrphanTxs:           cfg.MaxOrphanTxs,
			MaxOrphanTxSize:        mempool.MaxStandardTxSize,
			MaxSigOpsPerTx:         blockchain.MaxSigOpsPerBlock / 5,
			MinRelayTxFee:          cfg.minRelayTxFee,
			AllowOldVotes:          cfg.AllowOldVotes,
			MaxVoteAge: func() uint16 {
				switch chainParams.Net {
				case wire.MainNet, wire.SimNet, wire.RegNet:
					return chainParams.CoinbaseMaturity

				case wire.TestNet3:
					return defaultMaximumVoteAge

				default:
					return chainParams.CoinbaseMaturity
				}
			}(),
			StandardVerifyFlags: func() (txscript.ScriptFlags, error) {
				return standardScriptVerifyFlags(s.chain)
			},
		},
		ChainParams: chainParams,
		NextStakeDifficulty: func() (int64, error) {
			return s.chain.BestSnapshot().NextStakeDiff, nil
		},
		FetchUtxoView:    s.chain.FetchUtxoView,
		BlockByHash:      s.chain.BlockByHash,
		BestHash:         func() *chainhash.Hash { return &s.chain.BestSnapshot().Hash },
		BestHeight:       func() int64 { return s.chain.BestSnapshot().Height },
		CalcSequenceLock: s.chain.CalcSequenceLock,
		SubsidyCache:     s.subsidyCache,
		SigCache:         s.sigCache,
		PastMedianTime: func() time.Time {
			return s.chain.BestSnapshot().MedianTime
		},
		AddrIndex:                 s.addrIndex,
		ExistsAddrIndex:           s.existsAddrIndex,
		AddTxToFeeEstimation:      s.feeEstimator.AddMemPoolTransaction,
		RemoveTxFromFeeEstimation: s.feeEstimator.RemoveMemPoolTransaction,
		OnVoteReceived: func(voteTx *dcrutil.Tx) {
			if s.bg != nil {
				s.bg.VoteReceived(voteTx)
			}
		},
		OnTSpendReceived: func(tx *dcrutil.Tx) {
			if s.rpcServer != nil {
				s.rpcServer.NotifyTSpend(tx)
			}
		},
		IsTreasuryAgendaActive: func() (bool, error) {
			tipHash := &s.chain.BestSnapshot().Hash
			return s.chain.IsTreasuryAgendaActive(tipHash)
		},
		TSpendMinedOnAncestor: func(tspend chainhash.Hash) error {
			tipHash := s.chain.BestSnapshot().Hash
			return s.chain.CheckTSpendExists(tipHash, tspend)
		},
	}
	s.txMemPool = mempool.New(&txC)

	// Create a new sync manager instance with the appropriate configuration.
	if cfg.DisableCheckpoints {
		srvrLog.Info("Checkpoints are disabled")
	}
	s.syncManager = netsync.New(&netsync.Config{
		PeerNotifier: &s,
		Chain:        s.chain,
		ChainParams:  s.chainParams,
		TimeSource:   s.timeSource,
		TxMemPool:    s.txMemPool,
		RpcServer: func() *rpcserver.Server {
			return s.rpcServer
		},
		NoMiningStateSync:     cfg.NoMiningStateSync,
		MaxPeers:              cfg.MaxPeers,
		MaxOrphanTxs:          cfg.MaxOrphanTxs,
		RecentlyConfirmedTxns: s.recentlyConfirmedTxns,
	})

	// Dump the blockchain and quit if requested.
	if cfg.DumpBlockchain != "" {
		err := dumpBlockChain(s.chainParams, s.chain)
		if err != nil {
			return nil, err
		}

		return nil, fmt.Errorf("closing after dumping blockchain")
	}

	// Create the background block template generator and CPU miner if the
	// config has a mining address.
	if len(cfg.miningAddrs) > 0 {
		// Create the mining policy and block template generator based on the
		// configuration options.
		//
		// NOTE: The CPU miner relies on the mempool, so the mempool has to be
		// created before calling the function to create the CPU miner.
		policy := mining.Policy{
			BlockMinSize:      cfg.BlockMinSize,
			BlockMaxSize:      cfg.BlockMaxSize,
			BlockPrioritySize: cfg.BlockPrioritySize,
			TxMinFreeFee:      cfg.minRelayTxFee,
			AggressiveMining:  !cfg.NonAggressive,
			StandardVerifyFlags: func() (txscript.ScriptFlags, error) {
				return standardScriptVerifyFlags(s.chain)
			},
		}
		tg := mining.NewBlkTmplGenerator(&mining.Config{
			Policy:                     &policy,
			TxSource:                   s.txMemPool,
			TimeSource:                 s.timeSource,
			SubsidyCache:               s.subsidyCache,
			ChainParams:                s.chainParams,
			MiningTimeOffset:           cfg.MiningTimeOffset,
			BestSnapshot:               s.chain.BestSnapshot,
			BlockByHash:                s.chain.BlockByHash,
			CalcNextRequiredDifficulty: s.chain.CalcNextRequiredDifficulty,
			CalcStakeVersionByHash:     s.chain.CalcStakeVersionByHash,
			CheckConnectBlockTemplate:  s.chain.CheckConnectBlockTemplate,
			CheckTicketExhaustion:      s.chain.CheckTicketExhaustion,
			CheckTransactionInputs: func(tx *dcrutil.Tx, txHeight int64,
				view *blockchain.UtxoViewpoint, checkFraudProof bool,
				isTreasuryEnabled bool) (int64, error) {

				return blockchain.CheckTransactionInputs(s.subsidyCache, tx, txHeight,
					view, checkFraudProof, s.chainParams, isTreasuryEnabled)
			},
			CheckTSpendHasVotes:             s.chain.CheckTSpendHasVotes,
			CountSigOps:                     blockchain.CountSigOps,
			FetchUtxoView:                   s.chain.FetchUtxoView,
			FetchUtxoViewParentTemplate:     s.chain.FetchUtxoViewParentTemplate,
			ForceHeadReorganization:         s.chain.ForceHeadReorganization,
			IsFinalizedTransaction:          blockchain.IsFinalizedTransaction,
			IsHeaderCommitmentsAgendaActive: s.chain.IsHeaderCommitmentsAgendaActive,
			IsTreasuryAgendaActive:          s.chain.IsTreasuryAgendaActive,
			MaxTreasuryExpenditure:          s.chain.MaxTreasuryExpenditure,
			NewUtxoViewpoint: func() *blockchain.UtxoViewpoint {
				return blockchain.NewUtxoViewpoint(utxoCache)
			},
			TipGeneration: s.chain.TipGeneration,
			ValidateTransactionScripts: func(tx *dcrutil.Tx,
				utxoView *blockchain.UtxoViewpoint, flags txscript.ScriptFlags) error {

				return blockchain.ValidateTransactionScripts(tx, utxoView, flags,
					s.sigCache)
			},
		})

		s.bg = mining.NewBgBlkTmplGenerator(&mining.BgBlkTmplConfig{
			TemplateGenerator:   tg,
			MiningAddrs:         cfg.miningAddrs,
			AllowUnsyncedMining: cfg.AllowUnsyncedMining,
			IsCurrent:           s.syncManager.IsCurrent,
		})

		s.cpuMiner = cpuminer.New(&cpuminer.Config{
			ChainParams:                s.chainParams,
			PermitConnectionlessMining: cfg.SimNet || cfg.RegNet,
			BgBlkTmplGenerator:         s.bg,
			MiningAddrs:                cfg.miningAddrs,
			ProcessBlock:               s.syncManager.ProcessBlock,
			ConnectedCount:             s.ConnectedCount,
			IsCurrent:                  s.syncManager.IsCurrent,
		})
	}

	// Only setup a function to return new addresses to connect to when
	// not running in connect-only mode.  The simulation and regression networks
	// are always in connect-only mode since they are only intended to connect
	// to specified peers and actively avoid advertising and connecting to
	// discovered peers in order to prevent it from becoming a public test
	// network.
	var newAddressFunc func() (net.Addr, error)
	if !cfg.SimNet && !cfg.RegNet && len(cfg.ConnectPeers) == 0 {
		newAddressFunc = func() (net.Addr, error) {
			for tries := 0; tries < 100; tries++ {
				addr := s.addrManager.GetAddress()
				if addr == nil {
					break
				}

				// Address will not be invalid, local or unroutable
				// because addrmanager rejects those on addition.
				// Just check that we don't already have an address
				// in the same group so that we are not connecting
				// to the same network segment at the expense of
				// others.
				key := addrmgr.GroupKey(addr.NetAddress())
				if s.OutboundGroupCount(key) != 0 {
					continue
				}

				// only allow recent nodes (10mins) after we failed 30
				// times
				if tries < 30 && time.Since(addr.LastAttempt()) < 10*time.Minute {
					continue
				}

				// allow nondefault ports after 50 failed tries.
				if fmt.Sprintf("%d", addr.NetAddress().Port) !=
					s.chainParams.DefaultPort && tries < 50 {
					continue
				}

				addrString := addrmgr.NetAddressKey(addr.NetAddress())
				return addrStringToNetAddr(addrString)
			}

			return nil, errors.New("no valid connect address")
		}
	}

	// Create a connection manager.
	targetOutbound := defaultTargetOutbound
	if cfg.MaxPeers < targetOutbound {
		targetOutbound = cfg.MaxPeers
	}
	cmgr, err := connmgr.New(&connmgr.Config{
		Listeners:      listeners,
		OnAccept:       s.inboundPeerConnected,
		RetryDuration:  connectionRetryInterval,
		TargetOutbound: uint32(targetOutbound),
		Dial:           dcrdDial,
		Timeout:        cfg.DialTimeout,
		OnConnection:   s.outboundPeerConnected,
		GetNewAddress:  newAddressFunc,
	})
	if err != nil {
		return nil, err
	}
	s.connManager = cmgr

	// Start up persistent peers.
	permanentPeers := cfg.ConnectPeers
	if len(permanentPeers) == 0 {
		permanentPeers = cfg.AddPeers
	}
	for _, addr := range permanentPeers {
		tcpAddr, err := addrStringToNetAddr(addr)
		if err != nil {
			return nil, err
		}

		go s.connManager.Connect(context.Background(),
			&connmgr.ConnReq{
				Addr:      tcpAddr,
				Permanent: true,
			})
	}

	if !cfg.DisableRPC {
		// Setup listeners for the configured RPC listen addresses and
		// TLS settings.
		rpcListeners, err := setupRPCListeners()
		if err != nil {
			return nil, err
		}

		if len(rpcListeners) == 0 {
			return nil, errors.New("no usable rpc listen addresses")
		}

		rpcsConfig := rpcserver.Config{
			Listeners:    rpcListeners,
			ConnMgr:      &rpcConnManager{&s},
			SyncMgr:      &rpcSyncMgr{server: &s, syncMgr: s.syncManager},
			FeeEstimator: s.feeEstimator,
			TimeSource:   s.timeSource,
			Services:     s.services,
			AddrManager:  s.addrManager,
			Clock:        &rpcClock{},
			SubsidyCache: s.subsidyCache,
			Chain:        &rpcChain{s.chain},
			ChainParams:  chainParams,
			SanityChecker: &rpcSanityChecker{
				chain:       s.chain,
				timeSource:  s.timeSource,
				chainParams: chainParams,
			},
			DB:                   db,
			TxMempooler:          s.txMemPool,
			CPUMiner:             &rpcCPUMiner{s.cpuMiner},
			NetInfo:              cfg.generateNetworkInfo(),
			MinRelayTxFee:        cfg.minRelayTxFee,
			Proxy:                cfg.Proxy,
			RPCUser:              cfg.RPCUser,
			RPCPass:              cfg.RPCPass,
			RPCLimitUser:         cfg.RPCLimitUser,
			RPCLimitPass:         cfg.RPCLimitPass,
			RPCMaxClients:        cfg.RPCMaxClients,
			RPCMaxConcurrentReqs: cfg.RPCMaxConcurrentReqs,
			RPCMaxWebsockets:     cfg.RPCMaxWebsockets,
			TestNet:              cfg.TestNet,
			MiningAddrs:          cfg.miningAddrs,
			AllowUnsyncedMining:  cfg.AllowUnsyncedMining,
			MaxProtocolVersion:   maxProtocolVersion,
			UserAgentVersion:     userAgentVersion,
			LogManager:           &rpcLogManager{},
			FiltererV2:           s.chain,
		}
		if s.existsAddrIndex != nil {
			rpcsConfig.ExistsAddresser = s.existsAddrIndex
		}
		if s.bg != nil {
			rpcsConfig.BlockTemplater = &rpcBlockTemplater{s.bg}
		}
		if s.txIndex != nil {
			rpcsConfig.TxIndexer = s.txIndex
		}
		if s.addrIndex != nil {
			rpcsConfig.AddrIndexer = s.addrIndex
		}

		s.rpcServer, err = rpcserver.New(&rpcsConfig)
		if err != nil {
			return nil, err
		}

		// Signal process shutdown when the RPC server requests it.
		go func() {
			<-s.rpcServer.RequestedProcessShutdown()
			shutdownRequestChannel <- struct{}{}
		}()
	}

	return &s, nil
}

// initListeners initializes the configured net listeners and adds any bound
// addresses to the address manager. Returns the listeners and a NAT interface,
// which is non-nil if UPnP is in use.
func initListeners(ctx context.Context, params *chaincfg.Params, amgr *addrmgr.AddrManager, listenAddrs []string, services wire.ServiceFlag) ([]net.Listener, *upnpNAT, error) {
	// Listen for TCP connections at the configured addresses
	netAddrs, err := parseListeners(listenAddrs)
	if err != nil {
		return nil, nil, err
	}

	listeners := make([]net.Listener, 0, len(netAddrs))
	for _, addr := range netAddrs {
		var listenConfig net.ListenConfig
		listener, err := listenConfig.Listen(ctx, addr.Network(), addr.String())
		if err != nil {
			srvrLog.Warnf("Can't listen on %s: %v", addr, err)
			continue
		}
		listeners = append(listeners, listener)
	}

	var nat *upnpNAT
	if len(cfg.ExternalIPs) != 0 {
		defaultPort, err := strconv.ParseUint(params.DefaultPort, 10, 16)
		if err != nil {
			srvrLog.Errorf("Can not parse default port %s for active chain: %v",
				params.DefaultPort, err)
			return nil, nil, err
		}

		for _, sip := range cfg.ExternalIPs {
			eport := uint16(defaultPort)
			host, portstr, err := net.SplitHostPort(sip)
			if err != nil {
				// no port, use default.
				host = sip
			} else {
				port, err := strconv.ParseUint(portstr, 10, 16)
				if err != nil {
					srvrLog.Warnf("Can not parse port from %s for "+
						"externalip: %v", sip, err)
					continue
				}
				eport = uint16(port)
			}
			na, err := amgr.HostToNetAddress(host, eport, services)
			if err != nil {
				srvrLog.Warnf("Not adding %s as externalip: %v", sip, err)
				continue
			}

			err = amgr.AddLocalAddress(na, addrmgr.ManualPrio)
			if err != nil {
				amgrLog.Warnf("Skipping specified external IP: %v", err)
			}
		}
	} else {
		if cfg.Upnp {
			var err error
			nat, err = discover(ctx)
			if err != nil {
				srvrLog.Warnf("Can't discover upnp: %v", err)
			}
			// nil nat here is fine, just means no upnp on network.
		}

		// Add bound addresses to address manager to be advertised to peers.
		for _, listener := range listeners {
			addr := listener.Addr().String()
			err := addLocalAddress(amgr, addr, services)
			if err != nil {
				amgrLog.Warnf("Skipping bound address %s: %v", addr, err)
			}
		}
	}

	return listeners, nat, nil
}

// addrStringToNetAddr takes an address in the form of 'host:port' and returns
// a net.Addr which maps to the original address with any host names resolved
// to IP addresses.
func addrStringToNetAddr(addr string) (net.Addr, error) {
	host, strPort, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	// Attempt to look up an IP address associated with the parsed host.
	// The dcrdLookup function will transparently handle performing the
	// lookup over Tor if necessary.
	ips, err := dcrdLookup(host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses found for %s", host)
	}

	port, err := strconv.Atoi(strPort)
	if err != nil {
		return nil, err
	}

	return &net.TCPAddr{
		IP:   ips[0],
		Port: port,
	}, nil
}

// addLocalAddress adds an address that this node is listening on to the
// address manager so that it may be relayed to peers.
func addLocalAddress(addrMgr *addrmgr.AddrManager, addr string, services wire.ServiceFlag) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return err
	}

	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		// If bound to unspecified address, advertise all local interfaces
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			return err
		}

		for _, addr := range addrs {
			ifaceIP, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}

			// If bound to 0.0.0.0, do not add IPv6 interfaces and if bound to
			// ::, do not add IPv4 interfaces.
			if (ip.To4() == nil) != (ifaceIP.To4() == nil) {
				continue
			}

			netAddr := wire.NewNetAddressIPPort(ifaceIP, uint16(port), services)
			addrMgr.AddLocalAddress(netAddr, addrmgr.BoundPrio)
		}
	} else {
		netAddr, err := addrMgr.HostToNetAddress(host, uint16(port), services)
		if err != nil {
			return err
		}

		addrMgr.AddLocalAddress(netAddr, addrmgr.BoundPrio)
	}

	return nil
}

// isWhitelisted returns whether the IP address is included in the whitelisted
// networks and IPs.
func isWhitelisted(addr net.Addr) bool {
	if len(cfg.whitelists) == 0 {
		return false
	}

	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		srvrLog.Warnf("Unable to SplitHostPort on '%s': %v", addr, err)
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		srvrLog.Warnf("Unable to parse IP '%s'", addr)
		return false
	}

	for _, ipnet := range cfg.whitelists {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}
