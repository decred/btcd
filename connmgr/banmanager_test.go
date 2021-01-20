// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package connmgr

import (
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/decred/dcrd/peer/v2"
	"github.com/decred/dcrd/wire"
	"github.com/decred/go-socks/socks"
)

// TestBanPeer tests ban manager peer banning functionality.
func TestBanPeer(t *testing.T) {
	banPeer := func(p *peer.Peer) {
		// Do nothing.
	}

	bcfg := &BanManagerConfig{
		DisableBanning: false,
		BanThreshold:   100,
		BanPeer:        banPeer,
		MaxPeers:       10,
		WhiteList:      []*net.IPNet{},
	}

	bmgr := NewBanManager(bcfg)

	peerCfg := &peer.Config{
		UserAgentName:    "peer",
		UserAgentVersion: "1.0",
		Net:              wire.MainNet,
		Services:         0,
	}

	// Add peer A and B.
	pA, err := peer.NewOutboundPeer(peerCfg, "10.0.0.1:8333")
	if err != nil {
		t.Errorf("NewOutboundPeer: unexpected err - %v\n", err)
		return
	}

	bmgr.AddPeer(pA)

	pB, err := peer.NewOutboundPeer(peerCfg, "10.0.0.2:8333")
	if err != nil {
		t.Errorf("NewOutboundPeer: unexpected err - %v\n", err)
		return
	}

	bmgr.AddPeer(pB)

	pC, err := peer.NewOutboundPeer(peerCfg, "10.0.0.3:8333")
	if err != nil {
		t.Errorf("NewOutboundPeer: unexpected err - %v\n", err)
		return
	}

	bmgr.AddPeer(pC)

	if len(bmgr.peers) != 3 {
		t.Fatalf("expected 3 tracked peers, got %d", len(bmgr.peers))
	}

	// Remove disconnected peer C.
	bmgr.RemovePeer(pC)

	if len(bmgr.peers) != 2 {
		t.Fatalf("expected 2 tracked peers, got %d", len(bmgr.peers))
	}

	// Ensure the ban manager updates the correct peer's ban score.
	expectedBBanScore := uint32(0)
	_, peerBBanScore := bmgr.LookupPeer(pB.Addr())
	if peerBBanScore != expectedBBanScore {
		t.Fatalf("expected an unchanged ban score for peer B, got %d",
			peerBBanScore)
	}

	expectedABanScore := uint32(50)
	bmgr.AddBanScore(pA, expectedABanScore, 0, "testing")
	_, peerABanScore := bmgr.LookupPeer(pA.Addr())
	if peerABanScore != expectedABanScore {
		t.Fatalf("expected a ban score of %d for peer A, got %d",
			expectedABanScore, peerABanScore)
	}

	// Ban peerA by exceeding the ban threshold.
	bmgr.AddBanScore(pA, 120, 0, "testing")

	peerA, _ := bmgr.LookupPeer(pA.Addr())
	if peerA != nil {
		t.Fatal("peer A still exists in the manager")
	}

	// Outrightly ban peer B.
	bmgr.BanPeer(pB)

	peerB, _ := bmgr.LookupPeer(pB.Addr())
	if peerB != nil {
		t.Fatal("peer B still exists in the manager")
	}

	if len(bmgr.peers) != 0 {
		t.Fatalf("expected no tracked peers, got %d", len(bmgr.peers))
	}

	if len(bmgr.banScores) != 0 {
		t.Fatalf("expected no tracked peer ban scores, got %d",
			len(bmgr.banScores))
	}
}

// conn mocks a network connection by implementing the net.Conn interface.  It
// is used to test peer connection without actually opening a network
// connection.
type conn struct {
	io.Reader
	io.Writer
	io.Closer

	// local network, address for the connection.
	lnet, laddr string

	// remote network, address for the connection.
	rnet, raddr string

	// mocks socks proxy if true
	proxy bool
}

// LocalAddr returns the local address for the connection.
func (c conn) LocalAddr() net.Addr {
	return &addr{c.lnet, c.laddr}
}

// Remote returns the remote address for the connection.
func (c conn) RemoteAddr() net.Addr {
	if !c.proxy {
		return &addr{c.rnet, c.raddr}
	}
	host, strPort, _ := net.SplitHostPort(c.raddr)
	port, _ := strconv.Atoi(strPort)
	return &socks.ProxiedAddr{
		Net:  c.rnet,
		Host: host,
		Port: port,
	}
}

// Close handles closing the connection.
func (c conn) Close() error {
	return nil
}

func (c conn) SetDeadline(t time.Time) error      { return nil }
func (c conn) SetReadDeadline(t time.Time) error  { return nil }
func (c conn) SetWriteDeadline(t time.Time) error { return nil }

// addr mocks a network address.
type addr struct {
	net, address string
}

func (m addr) Network() string { return m.net }
func (m addr) String() string  { return m.address }

func TestPeerWhitelist(t *testing.T) {
	banPeer := func(p *peer.Peer) {
		// Do nothing.
	}

	ip := net.ParseIP("10.0.0.1")
	ipnet := &net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(32, 32),
	}
	whitelist := []*net.IPNet{ipnet}

	bcfg := &BanManagerConfig{
		DisableBanning: false,
		BanThreshold:   100,
		BanPeer:        banPeer,
		MaxPeers:       10,
		WhiteList:      whitelist,
	}

	bmgr := NewBanManager(bcfg)

	peerCfg := &peer.Config{
		UserAgentName:    "peer",
		UserAgentVersion: "1.0",
		Net:              wire.MainNet,
		Services:         0,
	}

	newPeer := func(cfg *peer.Config, addr string) (*peer.Peer, *conn, error) {
		r, w := io.Pipe()
		c := &conn{raddr: addr, Writer: w, Reader: r}
		p, err := peer.NewOutboundPeer(cfg, addr)
		if err != nil {
			return nil, nil, err
		}
		p.AssociateConnection(c)
		return p, c, nil
	}

	// Add two connected peers and one unconnected peer.
	pA, cA, err := newPeer(peerCfg, "10.0.0.1:8333")
	if err != nil {
		t.Errorf("unexpected peer error: %v", err)
	}
	defer cA.Close()
	bmgr.AddPeer(pA)

	pB, cB, err := newPeer(peerCfg, "10.0.0.2:8333")
	if err != nil {
		t.Errorf("unexpected peer error: %v", err)
	}
	defer cB.Close()
	bmgr.AddPeer(pB)

	pC, err := peer.NewOutboundPeer(peerCfg, "10.0.0.3:8333")
	if err != nil {
		t.Errorf("unexpected peer error: %v", err)
	}
	bmgr.AddPeer(pC)

	// Ensure a peer not associated with their connections cannot be whitelisted.
	if bmgr.IsPeerWhitelisted(pC) {
		t.Errorf("Expected an unconnected peer to not be whitelisted")
	}

	// Ensure a peer not whitelisted is not marked as so.
	if bmgr.IsPeerWhitelisted(pB) {
		t.Errorf("Expected peer B not to be whitelisted")
	}

	// Ensure a peer whitelisted to be markd as so.
	if !bmgr.IsPeerWhitelisted(pA) {
		t.Errorf("Expected peer A to be whitelisted")
	}
}
