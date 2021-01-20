// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package connmgr

import (
	"net"
	"sync"

	"github.com/decred/dcrd/peer/v2"
)

type BanManagerConfig struct {
	// DisableBanning represents the status of disabling banning of
	// misbehaving peers.
	DisableBanning bool

	// BndThreshold represents the maximum allowed ban score before
	// disconnecting and banning misbehaving peers.
	BanThreshold uint32

	// BanPeer represents a banning callback for the cleanup and status
	// updates purposes on a peer ban.
	BanPeer func(p *peer.Peer)

	// MaxPeers indicates the maximum number of inbound and outbound
	// peers allowed.
	MaxPeers int

	// Whitelist represents the whitelisted IPs of the server.
	WhiteList []*net.IPNet
}

// BanManager provides a manager to handle banning peers.
type BanManager struct {
	cfg       *BanManagerConfig
	peers     map[string]*peer.Peer
	banScores map[string]*DynamicBanScore
	mtx       sync.RWMutex
}

// NewBanManager initializes a new peer banning manager.
func NewBanManager(bcfg *BanManagerConfig) *BanManager {
	return &BanManager{
		cfg:       bcfg,
		peers:     make(map[string]*peer.Peer, bcfg.MaxPeers),
		banScores: make(map[string]*DynamicBanScore),
	}
}

// IsPeerWhitelisted returns the whitelisted status of the provided peer.
func (bm *BanManager) IsPeerWhitelisted(p *peer.Peer) bool {
	// Ensure peers are associated with their connections before checking
	// their whitelisted status.
	if !p.Connected() {
		return false
	}

	// Set the peer's whitelisted state.
	host, _, err := net.SplitHostPort(p.Addr())
	if err != nil {
		log.Errorf("Unable to split peer '%s' IP: %v", p.Addr(), err)
		return false
	}
	ip := net.ParseIP(host)

	if ip == nil {
		log.Errorf("Unable to parse IP '%s'", p.Addr())
		return false
	}
	for _, ipnet := range bm.cfg.WhiteList {
		if ipnet.Contains(ip) {
			return true
		}
	}

	return false
}

// AddPeer adds the provided peer to the manager.
func (bm *BanManager) AddPeer(p *peer.Peer) {
	bm.mtx.Lock()
	banScore := &DynamicBanScore{}
	bm.peers[p.Addr()] = p
	bm.banScores[p.Addr()] = banScore
	bm.mtx.Unlock()
}

// LookupPeer returns the associated peer of the provided address and its
// ban score.
func (bm *BanManager) LookupPeer(addr string) (*peer.Peer, uint32) {
	bm.mtx.Lock()
	defer bm.mtx.Unlock()
	p, ok := bm.peers[addr]
	if !ok {
		return nil, 0
	}

	score := bm.banScores[addr]
	return p, score.Int()
}

// RemovePeer discards the provided peer from the manager.
func (bm *BanManager) RemovePeer(p *peer.Peer) {
	bm.mtx.Lock()
	delete(bm.peers, p.Addr())
	delete(bm.banScores, p.Addr())
	bm.mtx.Unlock()
}

// BanPeer bans the provided peer.
func (bm *BanManager) BanPeer(p *peer.Peer) {
	bm.mtx.Lock()
	p, ok := bm.peers[p.Addr()]
	if !ok {
		bm.mtx.Unlock()
		log.Errorf("no peer found with IP: '%s'", p.Addr())
		return
	}
	bm.mtx.Unlock()

	if bm.cfg.DisableBanning || p.IsWhitelisted() {
		return
	}

	// Ban and remove the peer.
	bm.cfg.BanPeer(p)
	bm.RemovePeer(p)
}

// AddBanScore increases the persistent and decaying ban scores of the
// provided peer by the values passed as parameters. If the resulting score
// exceeds half of the ban threshold, a warning is logged including the reason
// provided. Further, if the score is above the ban threshold, the peer will
// be banned.
func (bm *BanManager) AddBanScore(p *peer.Peer, persistent, transient uint32, reason string) bool {
	// look for the server peer and update its score

	// No warning is logged and no score is calculated if banning is disabled.
	if bm.cfg.DisableBanning {
		return false
	}
	if p.IsWhitelisted() {
		log.Debugf("Misbehaving whitelisted peer %s: %s", p, reason)
		return false
	}

	banScore, ok := bm.banScores[p.Addr()]
	if !ok {
		log.Debugf("No ban score found for peer %s: %s", p)
		return false
	}

	warnThreshold := bm.cfg.BanThreshold >> 1
	if transient == 0 && persistent == 0 {
		// The score is not being increased, but a warning message is still
		// logged if the score is above the warn threshold.
		score := banScore.Int()
		if score > warnThreshold {
			log.Warnf("Misbehaving peer %s: %s -- ban score is %d, "+
				"it was not increased this time", p, reason, score)
		}
		return false
	}
	score := banScore.Increase(persistent, transient)
	bm.banScores[p.Addr()] = banScore
	if score > warnThreshold {
		log.Warnf("Misbehaving peer %s: %s -- ban score increased to %d",
			p, reason, score)
		if score > bm.cfg.BanThreshold {
			log.Warnf("Misbehaving peer %s -- banning and disconnecting", p)
			bm.BanPeer(p)
			return true
		}
	}
	return false
}
