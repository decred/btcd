// Copyright (c) 2018 The btcsuite developers
// Copyright (c) 2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package harness

import (
	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrd/rpcclient"
)

// TestNode wraps optional test node implementations for different test setups
type TestNode interface {
	// Network returns current network of the node
	Network() *chaincfg.Params

	// Start node process
	Start(args *TestNodeStartArgs)

	// Stop node process
	Stop()

	// Dispose releases all resources allocated by the node
	// This action is final (irreversible)
	Dispose() error

	// CertFile returns file path of the .cert-file of the node
	CertFile() string

	// RPCConnectionConfig produces a new connection config instance for RPC client
	RPCConnectionConfig() *rpcclient.ConnConfig

	// RPCClient returns node RPCConnection
	RPCClient() *RPCConnection

	// P2PAddress returns node p2p address
	P2PAddress() string
}

// TestNodeFactory produces a new TestNode instance
type TestNodeFactory interface {
	// NewNode is used by harness builder to setup a node component
	NewNode(cfg *TestNodeConfig) TestNode
}

// TestNodeConfig bundles settings required to create a new node instance
type TestNodeConfig struct {
	ActiveNet *chaincfg.Params

	WorkingDir string

	P2PHost string
	P2PPort int

	NodeRPCHost string
	NodeRPCPort int
}

// TestNodeStartArgs bundles Start() arguments to minimize diff
// in case a new argument for the function is added
type TestNodeStartArgs struct {
	ExtraArguments map[string]interface{}
	DebugOutput    bool
	MiningAddress  dcrutil.Address
}
