// Copyright (c) 2018 The btcsuite developers
// Copyright (c) 2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package testnode

import (
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrd/integration"
	"github.com/decred/dcrd/integration/commandline"
	"github.com/decred/dcrd/integration/harness"
	"github.com/decred/dcrd/rpcclient"
)

// DefaultTestNode launches a new dcrd instance using command-line call.
// Implements harness.TestNode.
type DefaultTestNode struct {
	// NodeExecutablePathProvider returns path to the dcrd executable
	NodeExecutablePathProvider commandline.ExecutablePathProvider

	rpcUser    string
	rpcPass    string
	p2pAddress string
	rpcListen  string
	rpcConnect string
	profile    string
	debugLevel string
	appDir     string
	endpoint   string

	externalProcess *commandline.ExternalProcess

	rPCClient *harness.RPCConnection

	miningAddress dcrutil.Address

	network *chaincfg.Params
}

// RPCConnectionConfig produces a new connection config instance for RPC client
func (node *DefaultTestNode) RPCConnectionConfig() *rpcclient.ConnConfig {
	file := node.CertFile()
	fmt.Println("reading: " + file)
	cert, err := ioutil.ReadFile(file)
	integration.CheckTestSetupMalfunction(err)

	return &rpcclient.ConnConfig{
		Host:                 node.rpcListen,
		Endpoint:             node.endpoint,
		User:                 node.rpcUser,
		Pass:                 node.rpcPass,
		Certificates:         cert,
		DisableAutoReconnect: true,
		HTTPPostMode:         false,
	}
}

// FullConsoleCommand returns the full console command used to
// launch external process of the node
func (node *DefaultTestNode) FullConsoleCommand() string {
	return node.externalProcess.FullConsoleCommand()
}

// P2PAddress returns node p2p address
func (node *DefaultTestNode) P2PAddress() string {
	return node.p2pAddress
}

// RPCClient returns node RPCConnection
func (node *DefaultTestNode) RPCClient() *harness.RPCConnection {
	return node.rPCClient
}

// CertFile returns file path of the .cert-file of the node
func (node *DefaultTestNode) CertFile() string {
	return filepath.Join(node.appDir, "rpc.cert")
}

// KeyFile returns file path of the .key-file of the node
func (node *DefaultTestNode) KeyFile() string {
	return filepath.Join(node.appDir, "rpc.key")
}

// Network returns current network of the node
func (node *DefaultTestNode) Network() *chaincfg.Params {
	return node.network
}

// IsRunning returns true if DefaultTestNode is running external dcrd process
func (node *DefaultTestNode) IsRunning() bool {
	return node.externalProcess.IsRunning()
}

// Start node process. Deploys working dir, launches dcrd using command-line,
// connects RPC client to the node.
func (node *DefaultTestNode) Start(args *harness.TestNodeStartArgs) {
	if node.IsRunning() {
		integration.ReportTestSetupMalfunction(fmt.Errorf("DefaultTestNode is already running"))
	}
	fmt.Println("Start node process...")
	integration.MakeDirs(node.appDir)

	node.miningAddress = args.MiningAddress

	exec := node.NodeExecutablePathProvider.Executable()
	node.externalProcess.CommandName = exec
	node.externalProcess.Arguments = commandline.ArgumentsToStringArray(
		node.cookArguments(args.ExtraArguments),
	)
	node.externalProcess.Launch(args.DebugOutput)
	// Node RPC instance will create a cert file when it is ready for incoming calls
	integration.WaitForFile(node.CertFile(), 7)

	fmt.Println("Connect to node RPC...")
	cfg := node.RPCConnectionConfig()
	node.rPCClient.Connect(cfg, nil)
	fmt.Println("node RPC client connected.")
}

// Stop interrupts the running node process.
// Disconnects RPC client from the node, removes cert-files produced by the dcrd,
// stops dcrd process.
func (node *DefaultTestNode) Stop() {
	if !node.IsRunning() {
		integration.ReportTestSetupMalfunction(fmt.Errorf("node is not running"))
	}

	if node.rPCClient.IsConnected() {
		fmt.Println("Disconnect from node RPC...")
		node.rPCClient.Disconnect()
	}

	fmt.Println("Stop node process...")
	err := node.externalProcess.Stop()
	integration.CheckTestSetupMalfunction(err)

	// Delete files, RPC servers will recreate them on the next launch sequence
	integration.DeleteFile(node.CertFile())
	integration.DeleteFile(node.KeyFile())
}

// Dispose simply stops the node process if running
func (node *DefaultTestNode) Dispose() error {
	if node.IsRunning() {
		node.Stop()
	}
	return nil
}

// cookArguments prepares arguments for the command-line call
func (node *DefaultTestNode) cookArguments(extraArguments map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	result["txindex"] = commandline.NoArgumentValue
	result["addrindex"] = commandline.NoArgumentValue
	result["rpcuser"] = node.rpcUser
	result["rpcpass"] = node.rpcPass
	result["rpcconnect"] = node.rpcConnect
	result["rpclisten"] = node.rpcListen
	result["listen"] = node.p2pAddress
	result["datadir"] = node.appDir
	result["debuglevel"] = node.debugLevel
	result["profile"] = node.profile
	result["rpccert"] = node.CertFile()
	result["rpckey"] = node.KeyFile()
	if node.miningAddress != nil {
		result["miningaddr"] = node.miningAddress.String()
	}
	result[networkFor(node.network)] = commandline.NoArgumentValue

	commandline.ArgumentsCopyTo(extraArguments, result)
	return result
}

// networkFor resolves network argument for node and wallet console commands
func networkFor(net *chaincfg.Params) string {
	if net == &chaincfg.SimNetParams {
		return "simnet"
	}
	if net == &chaincfg.TestNet3Params {
		return "testnet"
	}
	if net == &chaincfg.RegNetParams {
		return "regnet"
	}
	if net == &chaincfg.MainNetParams {
		// no argument needed for the MainNet
		return commandline.NoArgument
	}

	// should never reach this line, report violation
	integration.ReportTestSetupMalfunction(fmt.Errorf("unknown network: %v ", net))
	return ""
}
