// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer

// BanManager defines a manager that handles updating peer ban scores on
// infringement as well as peers banning misbehaving peers.
type BanManager interface {
	// AddPeer adds the provided peer to the manager.
	AddPeer(p *Peer)

	// RemovePeer discards the provided peer from the manager.
	RemovePeer(p *Peer)

	// AddBanScore increases the persistent and decaying ban scores of the
	// provided peer
	AddBanScore(p *Peer, persistent, transient uint32, reason string) bool

	// LookupPeer returns the associated peer of the provided address and
	// its ban score.
	LookupPeer(addr string) (*Peer, uint32)

	// BanPeer bans the provided peer.
	BanPeer(p *Peer)

	// IsPeerWhitelisted returns the whitelisted status of the provided peer.
	IsPeerWhitelisted(p *Peer) bool
}
