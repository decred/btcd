// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2015-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/decred/dcrd/blockchain/stake/v3"
	"github.com/decred/dcrd/blockchain/standalone/v2"
	"github.com/decred/dcrd/blockchain/v3"
	"github.com/decred/dcrd/blockchain/v3/indexers"
	"github.com/decred/dcrd/certgen"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/database/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v3/ecdsa"
	"github.com/decred/dcrd/dcrjson/v3"
	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/dcrd/internal/rpcserver"
	"github.com/decred/dcrd/internal/version"
	"github.com/decred/dcrd/mempool/v4"
	"github.com/decred/dcrd/rpc/jsonrpc/types/v2"
	"github.com/decred/dcrd/txscript/v3"
	"github.com/decred/dcrd/wire"
	"github.com/jrick/bitset"
)

// API version constants
const (
	jsonrpcSemverString = "6.1.1"
	jsonrpcSemverMajor  = 6
	jsonrpcSemverMinor  = 1
	jsonrpcSemverPatch  = 2
)

const (
	// rpcAuthTimeoutSeconds is the number of seconds a connection to the
	// RPC server is allowed to stay open without authenticating before it
	// is closed.
	rpcAuthTimeoutSeconds = 10

	// uint256Size is the number of bytes needed to represent an unsigned
	// 256-bit integer.
	uint256Size = 32

	// getworkDataLen is the length of the data field of the getwork RPC.
	// It consists of the serialized block header plus the internal blake256
	// padding.  The internal blake256 padding consists of a single 1 bit
	// followed by zeros and a final 1 bit in order to pad the message out
	// to 56 bytes followed by length of the message in bits encoded as a
	// big-endian uint64 (8 bytes).  Thus, the resulting length is a
	// multiple of the blake256 block size (64 bytes).  Given the padding
	// requires at least a 1 bit and 64 bits for the padding, the following
	// converts the block header length and hash block size to bits in order
	// to ensure the correct number of hash blocks are calculated and then
	// multiplies the result by the block hash block size in bytes.
	getworkDataLen = (1 + ((wire.MaxBlockHeaderPayload*8 + 65) /
		(chainhash.HashBlockSize * 8))) * chainhash.HashBlockSize

	// getworkExpirationDiff is the number of blocks below the current
	// best block in height to begin pruning out old block work from
	// the template pool.
	getworkExpirationDiff = 3

	// sstxCommitmentString is the string to insert when a verbose
	// transaction output's pkscript type is a ticket commitment.
	sstxCommitmentString = "sstxcommitment"

	// syncWait is the maximum time in seconds to wait for an index
	// to sync with the main chain.
	syncWait = time.Second * 3
)

var (
	// blake256Pad is the extra blake256 internal padding needed for the
	// data of the getwork RPC.  It is set in the init routine since it is
	// based on the size of the block header and requires a bit of
	// calculation.
	blake256Pad []byte

	// JSON 2.0 batched request prefix
	batchedRequestPrefix = []byte("[")
)

// Errors
var (
	// ErrRPCUnimplemented is an error returned to RPC clients when the
	// provided command is recognized, but not implemented.
	ErrRPCUnimplemented = &dcrjson.RPCError{
		Code:    dcrjson.ErrRPCUnimplemented,
		Message: "Command unimplemented",
	}

	// ErrRPCNoWallet is an error returned to RPC clients when the provided
	// command is recognized as a wallet command.
	ErrRPCNoWallet = &dcrjson.RPCError{
		Code:    dcrjson.ErrRPCNoWallet,
		Message: "This implementation does not implement wallet commands",
	}
)

type commandHandler func(context.Context, *rpcServer, interface{}) (interface{}, error)

// rpcHandlers maps RPC command strings to appropriate handler functions.
// This is set by init because help references rpcHandlers and thus causes
// a dependency loop.
var rpcHandlers map[types.Method]commandHandler
var rpcHandlersBeforeInit = map[types.Method]commandHandler{
	"addnode":               handleAddNode,
	"createrawsstx":         handleCreateRawSStx,
	"createrawssrtx":        handleCreateRawSSRtx,
	"createrawtransaction":  handleCreateRawTransaction,
	"debuglevel":            handleDebugLevel,
	"decoderawtransaction":  handleDecodeRawTransaction,
	"decodescript":          handleDecodeScript,
	"estimatefee":           handleEstimateFee,
	"estimatesmartfee":      handleEstimateSmartFee,
	"estimatestakediff":     handleEstimateStakeDiff,
	"existsaddress":         handleExistsAddress,
	"existsaddresses":       handleExistsAddresses,
	"existsexpiredtickets":  handleExistsExpiredTickets,
	"existsliveticket":      handleExistsLiveTicket,
	"existslivetickets":     handleExistsLiveTickets,
	"existsmempooltxs":      handleExistsMempoolTxs,
	"existsmissedtickets":   handleExistsMissedTickets,
	"generate":              handleGenerate,
	"getaddednodeinfo":      handleGetAddedNodeInfo,
	"getbestblock":          handleGetBestBlock,
	"getbestblockhash":      handleGetBestBlockHash,
	"getblock":              handleGetBlock,
	"getblockchaininfo":     handleGetBlockchainInfo,
	"getblockcount":         handleGetBlockCount,
	"getblockhash":          handleGetBlockHash,
	"getblockheader":        handleGetBlockHeader,
	"getblocksubsidy":       handleGetBlockSubsidy,
	"getcfilter":            handleGetCFilter,
	"getcfilterheader":      handleGetCFilterHeader,
	"getcfilterv2":          handleGetCFilterV2,
	"getchaintips":          handleGetChainTips,
	"getcoinsupply":         handleGetCoinSupply,
	"getconnectioncount":    handleGetConnectionCount,
	"getcurrentnet":         handleGetCurrentNet,
	"getdifficulty":         handleGetDifficulty,
	"getgenerate":           handleGetGenerate,
	"gethashespersec":       handleGetHashesPerSec,
	"getheaders":            handleGetHeaders,
	"getinfo":               handleGetInfo,
	"getmempoolinfo":        handleGetMempoolInfo,
	"getmininginfo":         handleGetMiningInfo,
	"getnettotals":          handleGetNetTotals,
	"getnetworkhashps":      handleGetNetworkHashPS,
	"getnetworkinfo":        handleGetNetworkInfo,
	"getpeerinfo":           handleGetPeerInfo,
	"getrawmempool":         handleGetRawMempool,
	"getrawtransaction":     handleGetRawTransaction,
	"getstakedifficulty":    handleGetStakeDifficulty,
	"getstakeversioninfo":   handleGetStakeVersionInfo,
	"getstakeversions":      handleGetStakeVersions,
	"getticketpoolvalue":    handleGetTicketPoolValue,
	"getvoteinfo":           handleGetVoteInfo,
	"gettxout":              handleGetTxOut,
	"gettxoutsetinfo":       handleGetTxOutSetInfo,
	"getwork":               handleGetWork,
	"help":                  handleHelp,
	"livetickets":           handleLiveTickets,
	"missedtickets":         handleMissedTickets,
	"node":                  handleNode,
	"ping":                  handlePing,
	"regentemplate":         handleRegenTemplate,
	"searchrawtransactions": handleSearchRawTransactions,
	"sendrawtransaction":    handleSendRawTransaction,
	"setgenerate":           handleSetGenerate,
	"stop":                  handleStop,
	"submitblock":           handleSubmitBlock,
	"ticketfeeinfo":         handleTicketFeeInfo,
	"ticketsforaddress":     handleTicketsForAddress,
	"ticketvwap":            handleTicketVWAP,
	"txfeeinfo":             handleTxFeeInfo,
	"validateaddress":       handleValidateAddress,
	"verifychain":           handleVerifyChain,
	"verifymessage":         handleVerifyMessage,
	"version":               handleVersion,
}

// list of commands that we recognize, but for which dcrd has no support because
// it lacks support for wallet functionality. For these commands the user
// should ask a connected instance of dcrwallet.
var rpcAskWallet = map[string]struct{}{
	"abandontransaction":      {},
	"accountaddressindex":     {},
	"accountsyncaddressindex": {},
	"addmultisigaddress":      {},
	"addticket":               {},
	"consolidate":             {},
	"createmultisig":          {},
	"createnewaccount":        {},
	"dumpprivkey":             {},
	"generatevote":            {},
	"getaccount":              {},
	"getaccountaddress":       {},
	"getaddressesbyaccount":   {},
	"getbalance":              {},
	"getmasterpubkey":         {},
	"getmultisigoutinfo":      {},
	"getnewaddress":           {},
	"getrawchangeaddress":     {},
	"getreceivedbyaccount":    {},
	"getreceivedbyaddress":    {},
	"getstakeinfo":            {},
	"getticketfee":            {},
	"gettickets":              {},
	"gettransaction":          {},
	"getvotechoices":          {},
	"getwalletfee":            {},
	"getunconfirmedbalance":   {},
	"importprivkey":           {},
	"importscript":            {},
	"listaccounts":            {},
	"listaddresstransactions": {},
	"listalltransactions":     {},
	"listreceivedbyaccount":   {},
	"listreceivedbyaddress":   {},
	"listscripts":             {},
	"listsinceblock":          {},
	"listtransactions":        {},
	"listunspent":             {},
	"lockunspent":             {},
	"redeemmultisigout":       {},
	"redeemmultisigouts":      {},
	"renameaccount":           {},
	"rescanwallet":            {},
	"revoketickets":           {},
	"sendfrom":                {},
	"sendmany":                {},
	"sendtoaddress":           {},
	"sendtomultisig":          {},
	"setticketfee":            {},
	"settxfee":                {},
	"setvotechoice":           {},
	"signmessage":             {},
	"signrawtransaction":      {},
	"signrawtransactions":     {},
	"stakepooluserinfo":       {},
	"sweepaccount":            {},
	"ticketsforaddress":       {},
	"validateaddress":         {},
	"verifymessage":           {},
	"verifyseed":              {},
	"walletinfo":              {},
	"walletislocked":          {},
	"walletlock":              {},
	"walletpassphrase":        {},
	"walletpassphrasechange":  {},
}

// Commands that are currently unimplemented, but should ultimately be.
var rpcUnimplemented = map[string]struct{}{
	"estimatepriority": {},
}

// Commands that are available to a limited user
var rpcLimited = map[string]struct{}{
	// Websockets commands
	"notifyblocks":          {},
	"notifynewtransactions": {},
	"notifyreceived":        {},
	"notifyspent":           {},
	"rescan":                {},
	"session":               {},
	"rebroadcastmissed":     {},
	"rebroadcastwinners":    {},

	// Websockets AND HTTP/S commands
	"help": {},

	// HTTP/S-only commands
	"createrawsstx":         {},
	"createrawssrtx":        {},
	"createrawtransaction":  {},
	"decoderawtransaction":  {},
	"decodescript":          {},
	"estimatefee":           {},
	"estimatesmartfee":      {},
	"estimatestakediff":     {},
	"existsaddress":         {},
	"existsaddresses":       {},
	"existsexpiredtickets":  {},
	"existsliveticket":      {},
	"existslivetickets":     {},
	"existsmempooltxs":      {},
	"existsmissedtickets":   {},
	"getbestblock":          {},
	"getbestblockhash":      {},
	"getblock":              {},
	"getblockchaininfo":     {},
	"getblockcount":         {},
	"getblockhash":          {},
	"getblockheader":        {},
	"getblocksubsidy":       {},
	"getcfilter":            {},
	"getcfilterv2":          {},
	"getchaintips":          {},
	"getcoinsupply":         {},
	"getcurrentnet":         {},
	"getdifficulty":         {},
	"getheaders":            {},
	"getinfo":               {},
	"getnettotals":          {},
	"getnetworkhashps":      {},
	"getnetworkinfo":        {},
	"getrawmempool":         {},
	"getstakedifficulty":    {},
	"getstakeversioninfo":   {},
	"getstakeversions":      {},
	"getrawtransaction":     {},
	"gettxout":              {},
	"getvoteinfo":           {},
	"livetickets":           {},
	"missedtickets":         {},
	"regentemplate":         {},
	"searchrawtransactions": {},
	"sendrawtransaction":    {},
	"submitblock":           {},
	"ticketfeeinfo":         {},
	"ticketsforaddress":     {},
	"ticketvwap":            {},
	"txfeeinfo":             {},
	"validateaddress":       {},
	"verifymessage":         {},
	"version":               {},
}

// rpcInternalError is a convenience function to convert an internal error to
// an RPC error with the appropriate code set.  It also logs the error to the
// RPC server subsystem since internal errors really should not occur.  The
// context parameter is only used in the log message and may be empty if it's
// not needed.
func rpcInternalError(errStr, context string) *dcrjson.RPCError {
	logStr := errStr
	if context != "" {
		logStr = context + ": " + errStr
	}
	rpcsLog.Error(logStr)
	return dcrjson.NewRPCError(dcrjson.ErrRPCInternal.Code, errStr)
}

// rpcInvalidError is a convenience function to convert an invalid parameter
// error to an RPC error with the appropriate code set.
func rpcInvalidError(fmtStr string, args ...interface{}) *dcrjson.RPCError {
	return dcrjson.NewRPCError(dcrjson.ErrRPCInvalidParameter,
		fmt.Sprintf(fmtStr, args...))
}

// rpcDeserializetionError is a convenience function to convert a
// deserialization error to an RPC error with the appropriate code set.
func rpcDeserializationError(fmtStr string, args ...interface{}) *dcrjson.RPCError {
	return dcrjson.NewRPCError(dcrjson.ErrRPCDeserialization,
		fmt.Sprintf(fmtStr, args...))
}

// rpcRuleError is a convenience function to convert a
// rule error to an RPC error with the appropriate code set.
func rpcRuleError(fmtStr string, args ...interface{}) *dcrjson.RPCError {
	return dcrjson.NewRPCError(dcrjson.ErrRPCMisc,
		fmt.Sprintf(fmtStr, args...))
}

// rpcDuplicateTxError is a convenience function to convert a
// rejected duplicate tx error to an RPC error with the appropriate code set.
func rpcDuplicateTxError(fmtStr string, args ...interface{}) *dcrjson.RPCError {
	return dcrjson.NewRPCError(dcrjson.ErrRPCDuplicateTx,
		fmt.Sprintf(fmtStr, args...))
}

// rpcAddressKeyError is a convenience function to convert an address/key error to
// an RPC error with the appropriate code set.  It also logs the error to the
// RPC server subsystem since internal errors really should not occur.  The
// context parameter is only used in the log message and may be empty if it's
// not needed.
func rpcAddressKeyError(fmtStr string, args ...interface{}) *dcrjson.RPCError {
	return dcrjson.NewRPCError(dcrjson.ErrRPCInvalidAddressOrKey,
		fmt.Sprintf(fmtStr, args...))
}

// rpcDecodeHexError is a convenience function for returning a nicely formatted
// RPC error which indicates the provided hex string failed to decode.
func rpcDecodeHexError(gotHex string) *dcrjson.RPCError {
	return dcrjson.NewRPCError(dcrjson.ErrRPCDecodeHexString,
		fmt.Sprintf("Argument must be hexadecimal string (not %q)",
			gotHex))
}

// rpcNoTxInfoError is a convenience function for returning a nicely formatted
// RPC error which indicates there is no information available for the provided
// transaction hash.
func rpcNoTxInfoError(txHash *chainhash.Hash) *dcrjson.RPCError {
	return dcrjson.NewRPCError(dcrjson.ErrRPCNoTxInfo,
		fmt.Sprintf("No information available about transaction %v",
			txHash))
}

// rpcMiscError is a convenience function for returning a nicely formatted RPC
// error which indicates there is an unquantifiable error.  Use this sparingly;
// misc return codes are a cop out.
func rpcMiscError(message string) *dcrjson.RPCError {
	return dcrjson.NewRPCError(dcrjson.ErrRPCMisc, message)
}

// workState houses state that is used in between multiple RPC invocations to
// getwork.
type workState struct {
	sync.Mutex
	prevHash     *chainhash.Hash
	templatePool map[[merkleRootPairSize]byte]*wire.MsgBlock
}

// newWorkState returns a new instance of a workState with all internal fields
// initialized and ready to use.
func newWorkState() *workState {
	return &workState{
		templatePool: make(map[[merkleRootPairSize]byte]*wire.MsgBlock),
	}
}

// handleUnimplemented is the handler for commands that should ultimately be
// supported but are not yet implemented.
func handleUnimplemented(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	return nil, ErrRPCUnimplemented
}

// handleAskWallet is the handler for commands that are recognized as valid, but
// are unable to answer correctly since it involves wallet state.
// These commands will be implemented in dcrwallet.
func handleAskWallet(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	return nil, ErrRPCNoWallet
}

// handleAddNode handles addnode commands.
func handleAddNode(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.AddNodeCmd)

	addr := normalizeAddress(c.Addr, s.cfg.ChainParams.DefaultPort)
	connMgr := s.cfg.ConnMgr
	var err error
	switch c.SubCmd {
	case "add":
		err = connMgr.Connect(addr, true)
	case "remove":
		err = connMgr.RemoveByAddr(addr)
	case "onetry":
		err = connMgr.Connect(addr, false)
	default:
		return nil, rpcInvalidError("Invalid subcommand for addnode")
	}

	if err != nil {
		return nil, rpcInvalidError("%v: %v", c.SubCmd, err)
	}

	// no data returned unless an error.
	return nil, nil
}

// handleNode handles node commands.
func handleNode(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.NodeCmd)

	connMgr := s.cfg.ConnMgr

	var addr string
	var nodeID uint64
	var errN, err error
	params := s.cfg.ChainParams
	switch c.SubCmd {
	case "disconnect":
		// If we have a valid uint disconnect by node id. Otherwise,
		// attempt to disconnect by address, returning an error if a
		// valid IP address is not supplied.
		if nodeID, errN = strconv.ParseUint(c.Target, 10, 32); errN == nil {
			err = connMgr.DisconnectByID(int32(nodeID))
		} else {
			if _, _, errP := net.SplitHostPort(c.Target); errP == nil ||
				net.ParseIP(c.Target) != nil {
				addr = normalizeAddress(c.Target, params.DefaultPort)
				err = connMgr.DisconnectByAddr(addr)
			} else {
				return nil, rpcInvalidError("%v: Invalid "+
					"address or node ID", c.SubCmd)
			}
		}
		if err != nil && peerExists(connMgr, addr, int32(nodeID)) {
			return nil, rpcMiscError("can't disconnect a permanent peer, " +
				"use remove")
		}

	case "remove":
		// If we have a valid uint disconnect by node id. Otherwise,
		// attempt to disconnect by address, returning an error if a
		// valid IP address is not supplied.
		if nodeID, errN = strconv.ParseUint(c.Target, 10, 32); errN == nil {
			err = connMgr.RemoveByID(int32(nodeID))
		} else {
			if _, _, errP := net.SplitHostPort(c.Target); errP == nil ||
				net.ParseIP(c.Target) != nil {
				addr = normalizeAddress(c.Target, params.DefaultPort)
				err = connMgr.RemoveByAddr(addr)
			} else {
				return nil, rpcInvalidError("%v: invalid "+
					"address or node ID", c.SubCmd)
			}
		}
		if err != nil && peerExists(connMgr, addr, int32(nodeID)) {
			return nil, rpcMiscError("can't remove a temporary peer, " +
				"use disconnect")
		}

	case "connect":
		addr = normalizeAddress(c.Target, params.DefaultPort)

		// Default to temporary connections.
		subCmd := "temp"
		if c.ConnectSubCmd != nil {
			subCmd = *c.ConnectSubCmd
		}

		switch subCmd {
		case "perm", "temp":
			err = connMgr.Connect(addr, subCmd == "perm")
		default:
			return nil, rpcInvalidError("%v: invalid subcommand "+
				"for node connect", subCmd)
		}
	default:
		return nil, rpcInvalidError("%v: invalid subcommand for node", c.SubCmd)
	}

	if err != nil {
		return nil, rpcInvalidError("%v: %v", c.SubCmd, err)
	}

	// no data returned unless an error.
	return nil, nil
}

// peerExists determines if a certain peer is currently connected given
// information about all currently connected peers. Peer existence is
// determined using either a target address or node id.
func peerExists(connMgr rpcserver.ConnManager, addr string, nodeID int32) bool {
	for _, p := range connMgr.ConnectedPeers() {
		if p.ID() == nodeID || p.Addr() == addr {
			return true
		}
	}
	return false
}

// messageToHex serializes a message to the wire protocol encoding using the
// latest protocol version and returns a hex-encoded string of the result.
func messageToHex(msg wire.Message) (string, error) {
	var buf bytes.Buffer
	if err := msg.BtcEncode(&buf, maxProtocolVersion); err != nil {
		context := fmt.Sprintf("Failed to encode msg of type %T", msg)
		return "", rpcInternalError(err.Error(), context)
	}

	return hex.EncodeToString(buf.Bytes()), nil
}

// handleCreateRawTransaction handles createrawtransaction commands.
func handleCreateRawTransaction(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.CreateRawTransactionCmd)

	// Validate expiry, if given.
	if c.Expiry != nil && *c.Expiry < 0 {
		return nil, rpcInvalidError("Expiry out of range")
	}

	// Validate the locktime, if given.
	if c.LockTime != nil &&
		(*c.LockTime < 0 ||
			*c.LockTime > int64(wire.MaxTxInSequenceNum)) {
		return nil, rpcInvalidError("Locktime out of range")
	}

	// Add all transaction inputs to a new transaction after performing
	// some validity checks.
	mtx := wire.NewMsgTx()
	for _, input := range c.Inputs {
		txHash, err := chainhash.NewHashFromStr(input.Txid)
		if err != nil {
			return nil, rpcDecodeHexError(input.Txid)
		}

		if !(input.Tree == wire.TxTreeRegular ||
			input.Tree == wire.TxTreeStake) {
			return nil, rpcInvalidError("Tx tree must be regular " +
				"or stake")
		}

		prevOutV := wire.NullValueIn
		if input.Amount > 0 {
			amt, err := dcrutil.NewAmount(input.Amount)
			if err != nil {
				return nil, rpcInvalidError(err.Error())
			}
			prevOutV = int64(amt)
		}

		prevOut := wire.NewOutPoint(txHash, input.Vout, input.Tree)
		txIn := wire.NewTxIn(prevOut, prevOutV, []byte{})
		if c.LockTime != nil && *c.LockTime != 0 {
			txIn.Sequence = wire.MaxTxInSequenceNum - 1
		}
		mtx.AddTxIn(txIn)
	}

	// Add all transaction outputs to the transaction after performing
	// some validity checks.
	for encodedAddr, amount := range c.Amounts {
		atoms, err := dcrutil.NewAmount(amount)
		if err != nil {
			return nil, rpcInternalError(err.Error(),
				"New amount")
		}

		// Ensure amount is in the valid range for monetary amounts.
		if atoms <= 0 || atoms > dcrutil.MaxAmount {
			return nil, rpcInvalidError("Invalid amount: 0 >= %v "+
				"> %v", amount, dcrutil.MaxAmount)
		}

		// Decode the provided address.  This also ensures the network encoded
		// with the address matches the network the server is currently on.
		addr, err := dcrutil.DecodeAddress(encodedAddr, s.cfg.ChainParams)
		if err != nil {
			return nil, rpcAddressKeyError("Could not decode address: %v", err)
		}

		// Ensure the address is one of the supported types.
		switch addr.(type) {
		case *dcrutil.AddressPubKeyHash:
		case *dcrutil.AddressScriptHash:
		default:
			return nil, rpcAddressKeyError("Invalid type: %T", addr)
		}

		// Create a new script which pays to the provided address.
		pkScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return nil, rpcInternalError(err.Error(),
				"Pay to address script")
		}

		txOut := wire.NewTxOut(int64(atoms), pkScript)
		mtx.AddTxOut(txOut)
	}

	// Set the Locktime, if given.
	if c.LockTime != nil {
		mtx.LockTime = uint32(*c.LockTime)
	}

	// Set the Expiry, if given.
	if c.Expiry != nil {
		mtx.Expiry = uint32(*c.Expiry)
	}

	// Return the serialized and hex-encoded transaction.  Note that this
	// is intentionally not directly returning because the first return
	// value is a string and it would result in returning an empty string to
	// the client instead of nothing (nil) in the case of an error.
	mtxHex, err := messageToHex(mtx)
	if err != nil {
		return nil, err
	}
	return mtxHex, nil
}

// handleCreateRawSStx handles createrawsstx commands.
func handleCreateRawSStx(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.CreateRawSStxCmd)

	// Basic sanity checks for the information coming from the cmd.
	if len(c.Inputs) != len(c.COuts) {
		return nil, rpcInvalidError("Number of inputs should be equal "+
			"to the number of future commitment/change outs for "+
			"any sstx; %v inputs given, but %v COuts",
			len(c.Inputs), len(c.COuts))
	}
	if len(c.Amount) != 1 {
		return nil, rpcInvalidError("Only one SSGen tagged output is "+
			"allowed per sstx; len ssgenout %v", len(c.Amount))
	}

	// Add all transaction inputs to a new transaction after performing
	// some validity checks.
	mtx := wire.NewMsgTx()
	for _, input := range c.Inputs {
		txHash, err := chainhash.NewHashFromStr(input.Txid)
		if err != nil {
			return nil, rpcDecodeHexError(input.Txid)
		}

		if !(input.Tree == wire.TxTreeRegular ||
			input.Tree == wire.TxTreeStake) {
			return nil, rpcInvalidError("Tx tree must be regular or stake")
		}

		prevOut := wire.NewOutPoint(txHash, input.Vout, input.Tree)
		txIn := wire.NewTxIn(prevOut, input.Amt, nil)
		mtx.AddTxIn(txIn)
	}

	// Add all transaction outputs to the transaction after performing
	// some validity checks.
	amtTicket := int64(0)

	for encodedAddr, amount := range c.Amount {
		// Ensure amount is in the valid range for monetary amounts.
		if amount <= 0 || amount > dcrutil.MaxAmount {
			return nil, rpcInvalidError("Invalid SSTx commitment "+
				"amount: 0 >= %v > %v", amount,
				dcrutil.MaxAmount)
		}

		// Decode the provided address.  This also ensures the network encoded
		// with the address matches the network the server is currently on.
		addr, err := dcrutil.DecodeAddress(encodedAddr, s.cfg.ChainParams)
		if err != nil {
			return nil, rpcAddressKeyError("Could not decode address: %v", err)
		}

		// Ensure the address is one of the supported types.
		switch addr.(type) {
		case *dcrutil.AddressPubKeyHash:
		case *dcrutil.AddressScriptHash:
		default:
			return nil, rpcAddressKeyError("Invalid address type: "+
				"%T", addr)
		}

		// Create a new script which pays to the provided address with an
		// SStx tagged output.
		pkScript, err := txscript.PayToSStx(addr)
		if err != nil {
			return nil, rpcInternalError(err.Error(),
				"Could not create TX script")
		}

		txOut := wire.NewTxOut(amount, pkScript)
		mtx.AddTxOut(txOut)

		amtTicket += amount
	}

	// Calculated the commitment amounts, then create the
	// addresses and payout proportions as null data
	// outputs.
	inputAmts := make([]int64, len(c.Inputs))
	for i, input := range c.Inputs {
		inputAmts[i] = input.Amt
	}
	changeAmts := make([]int64, len(c.COuts))
	for i, cout := range c.COuts {
		changeAmts[i] = cout.ChangeAmt
	}

	// Check and make sure none of the change overflows
	// the input amounts.
	for i, amt := range inputAmts {
		if changeAmts[i] >= amt {
			return nil, rpcInvalidError("input %v >= amount %v",
				changeAmts[i], amt)
		}
	}

	// Obtain the commitment amounts.
	_, amountsCommitted, err := stake.SStxNullOutputAmounts(inputAmts,
		changeAmts, amtTicket)
	if err != nil {
		return nil, rpcInternalError(err.Error(),
			"Invalid SSTx output amounts")
	}

	for i, cout := range c.COuts {
		// Append future commitment output.  This also ensures the network
		// encoded with the address matches the network the server is currently
		// on.
		addr, err := dcrutil.DecodeAddress(cout.Addr, s.cfg.ChainParams)
		if err != nil {
			return nil, rpcAddressKeyError("Could not decode address: %v", err)
		}

		// Ensure the address is one of the supported types.
		switch addr.(type) {
		case *dcrutil.AddressPubKeyHash:
			break
		case *dcrutil.AddressScriptHash:
			break
		default:
			return nil, rpcAddressKeyError("Invalid type: %T", addr)
		}

		// Create an OP_RETURN push containing the pubkeyhash to send
		// rewards to.  TODO Replace 0x0000 fee limits with an argument
		// passed to the RPC call.
		pkScript, err := txscript.GenerateSStxAddrPush(addr,
			dcrutil.Amount(amountsCommitted[i]), 0x0000)
		if err != nil {
			return nil, rpcInternalError(err.Error(),
				"Could not create SStx script")
		}
		txout := wire.NewTxOut(int64(0), pkScript)
		mtx.AddTxOut(txout)

		// 2. Append change output.

		// Ensure amount is in the valid range for monetary amounts.
		if cout.ChangeAmt < 0 || cout.ChangeAmt > dcrutil.MaxAmount {
			return nil, rpcInvalidError("Invalid change amount: 0 "+
				"> %v > %v", cout.ChangeAmt, dcrutil.MaxAmount)
		}

		// Decode the provided address.  This also ensures the network encoded
		// with the address matches the network the server is currently on.
		addr, err = dcrutil.DecodeAddress(cout.ChangeAddr, s.cfg.ChainParams)
		if err != nil {
			return nil, rpcAddressKeyError("Wrong network: %v",
				addr)
		}

		// Ensure the address is one of the supported types and that
		// the network encoded with the address matches the network the
		// server is currently on.
		switch addr.(type) {
		case *dcrutil.AddressPubKeyHash:
			break
		case *dcrutil.AddressScriptHash:
			break
		default:
			return nil, rpcAddressKeyError("Invalid type: %T", addr)
		}

		// Create a new script which pays to the provided address with
		// an SStx change tagged output.
		pkScript, err = txscript.PayToSStxChange(addr)
		if err != nil {
			return nil, rpcInternalError(err.Error(),
				"Could not create SStx change script")
		}

		txOut := wire.NewTxOut(cout.ChangeAmt, pkScript)
		mtx.AddTxOut(txOut)
	}

	// Make sure we generated a valid SStx.
	if err := stake.CheckSStx(mtx); err != nil {
		return nil, rpcInternalError(err.Error(),
			"Invalid SStx")
	}

	// Return the serialized and hex-encoded transaction.
	mtxHex, err := messageToHex(mtx)
	if err != nil {
		return nil, err
	}
	return mtxHex, nil
}

// handleCreateRawSSRtx handles createrawssrtx commands.
func handleCreateRawSSRtx(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.CreateRawSSRtxCmd)

	// Only a single SStx should be given
	if len(c.Inputs) != 1 {
		return nil, rpcInvalidError("SSRtx invalid number of inputs")
	}

	// Decode the fee as coins.
	var feeAmt dcrutil.Amount
	if c.Fee != nil {
		var err error
		feeAmt, err = dcrutil.NewAmount(*c.Fee)
		if err != nil {
			return nil, rpcInvalidError("Invalid fee amount: %v",
				err)
		}
	}

	// 1. Fetch the SStx, then calculate all the values we'll need later
	// for the generation of the SSGen tx outputs.
	//
	// Convert the provided transaction hash hex to a chainhash.Hash.
	input := c.Inputs[0]
	txHash, err := chainhash.NewHashFromStr(input.Txid)
	if err != nil {
		return nil, rpcDecodeHexError(input.Txid)
	}

	// Try to fetch the ticket from the block database.
	ticketUtx, err := s.cfg.Chain.FetchUtxoEntry(txHash)
	if ticketUtx == nil || err != nil {
		return nil, rpcNoTxInfoError(txHash)
	}
	if t := ticketUtx.TransactionType(); t != stake.TxTypeSStx {
		return nil, rpcDeserializationError("Invalid Tx type: %v", t)
	}

	// Store the sstx pubkeyhashes and amounts as found in the transaction
	// outputs.
	minimalOutputs := s.cfg.Chain.ConvertUtxosToMinimalOutputs(ticketUtx)
	ssrtxPayTypes, ssrtxPkhs, sstxAmts, _, _, _ :=
		stake.SStxStakeOutputInfo(minimalOutputs)

	// 2. Add all transaction inputs to a new transaction after performing
	// some validity checks; the only input for an SSRtx is an OP_SSTX tagged
	// output.
	mtx := wire.NewMsgTx()

	if !(input.Tree == wire.TxTreeStake) {
		return nil, rpcInvalidError("Input tree is not TxTreeStake type")
	}

	prevOutV := wire.NullValueIn
	if input.Amount > 0 {
		amt, err := dcrutil.NewAmount(input.Amount)
		if err != nil {
			return nil, rpcInvalidError(err.Error())
		}
		prevOutV = int64(amt)
	}

	prevOut := wire.NewOutPoint(txHash, input.Vout, input.Tree)
	txIn := wire.NewTxIn(prevOut, prevOutV, []byte{})
	mtx.AddTxIn(txIn)

	// 3. Add all the OP_SSRTX tagged outputs.

	// Calculate the output values from this data.
	ssrtxCalcAmts := stake.CalculateRewards(sstxAmts,
		minimalOutputs[0].Value, 0) // No subsidy for a revocation

	// Add all the SSRtx-tagged transaction outputs to the transaction after
	// performing some validity checks.
	feeApplied := false
	for i, ssrtxPkh := range ssrtxPkhs {
		// Ensure amount is in the valid range for monetary amounts.
		if sstxAmts[i] <= 0 || sstxAmts[i] > dcrutil.MaxAmount {
			return nil, rpcInvalidError("Invalid SSTx amount: 0 >="+
				" %v > %v", sstxAmts[i] <= 0, dcrutil.MaxAmount)
		}

		// Create a new script which pays to the provided address specified in
		// the original ticket tx.
		var ssrtxOutScript []byte
		switch ssrtxPayTypes[i] {
		case false: // P2PKH
			ssrtxOutScript, err = txscript.PayToSSRtxPKHDirect(ssrtxPkh)
			if err != nil {
				return nil, rpcInvalidError("Could not "+
					"generate P2PKH script: %v", err)
			}
		case true: // P2SH
			ssrtxOutScript, err = txscript.PayToSSRtxSHDirect(ssrtxPkh)
			if err != nil {
				return nil, rpcInvalidError("Could not "+
					"generate P2SH script: %v", err)
			}
		}

		// Add the txout to our SSGen tx.
		amt := ssrtxCalcAmts[i]
		if !feeApplied && int64(feeAmt) < amt {
			amt -= int64(feeAmt)
			feeApplied = true
		}
		txOut := wire.NewTxOut(amt, ssrtxOutScript)
		mtx.AddTxOut(txOut)
	}

	// Check to make sure our SSRtx was created correctly.
	err = stake.CheckSSRtx(mtx)
	if err != nil {
		return nil, rpcInternalError(err.Error(), "Invalid SSRtx")
	}

	// Return the serialized and hex-encoded transaction.
	mtxHex, err := messageToHex(mtx)
	if err != nil {
		return nil, err
	}
	return mtxHex, nil
}

// handleDebugLevel handles debuglevel commands.
func handleDebugLevel(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.DebugLevelCmd)

	// Special show command to list supported subsystems.
	if c.LevelSpec == "show" {
		return fmt.Sprintf("Supported subsystems %v",
			supportedSubsystems()), nil
	}

	err := parseAndSetDebugLevels(c.LevelSpec)
	if err != nil {
		return nil, rpcInvalidError("Invalid debug level %v: %v",
			c.LevelSpec, err)
	}

	return "Done.", nil
}

// createVinList returns a slice of JSON objects for the inputs of the passed
// transaction.
func createVinList(mtx *wire.MsgTx) []types.Vin {
	// Coinbase transactions only have a single txin by definition.
	vinList := make([]types.Vin, len(mtx.TxIn))
	if standalone.IsCoinBaseTx(mtx) {
		txIn := mtx.TxIn[0]
		vinEntry := &vinList[0]
		vinEntry.Coinbase = hex.EncodeToString(txIn.SignatureScript)
		vinEntry.Sequence = txIn.Sequence
		vinEntry.AmountIn = dcrutil.Amount(txIn.ValueIn).ToCoin()
		vinEntry.BlockHeight = txIn.BlockHeight
		vinEntry.BlockIndex = txIn.BlockIndex
		return vinList
	}

	// Stakebase transactions (votes) have two inputs: a null stake base
	// followed by an input consuming a ticket's stakesubmission.
	isSSGen := stake.IsSSGen(mtx)

	for i, txIn := range mtx.TxIn {
		// Handle only the null input of a stakebase differently.
		if isSSGen && i == 0 {
			vinEntry := &vinList[0]
			vinEntry.Stakebase = hex.EncodeToString(txIn.SignatureScript)
			vinEntry.Sequence = txIn.Sequence
			vinEntry.AmountIn = dcrutil.Amount(txIn.ValueIn).ToCoin()
			vinEntry.BlockHeight = txIn.BlockHeight
			vinEntry.BlockIndex = txIn.BlockIndex
			continue
		}

		// The disassembled string will contain [error] inline
		// if the script doesn't fully parse, so ignore the
		// error here.
		disbuf, _ := txscript.DisasmString(txIn.SignatureScript)

		vinEntry := &vinList[i]
		vinEntry.Txid = txIn.PreviousOutPoint.Hash.String()
		vinEntry.Vout = txIn.PreviousOutPoint.Index
		vinEntry.Tree = txIn.PreviousOutPoint.Tree
		vinEntry.Sequence = txIn.Sequence
		vinEntry.AmountIn = dcrutil.Amount(txIn.ValueIn).ToCoin()
		vinEntry.BlockHeight = txIn.BlockHeight
		vinEntry.BlockIndex = txIn.BlockIndex
		vinEntry.ScriptSig = &types.ScriptSig{
			Asm: disbuf,
			Hex: hex.EncodeToString(txIn.SignatureScript),
		}
	}

	return vinList
}

// createVoutList returns a slice of JSON objects for the outputs of the passed
// transaction.
func createVoutList(mtx *wire.MsgTx, chainParams *chaincfg.Params, filterAddrMap map[string]struct{}) []types.Vout {

	txType := stake.DetermineTxType(mtx)
	voutList := make([]types.Vout, 0, len(mtx.TxOut))
	for i, v := range mtx.TxOut {
		// The disassembled string will contain [error] inline if the
		// script doesn't fully parse, so ignore the error here.
		disbuf, _ := txscript.DisasmString(v.PkScript)

		// Attempt to extract addresses from the public key script.  In
		// the case of stake submission transactions, the odd outputs
		// contain a commitment address, so detect that case
		// accordingly.
		var addrs []dcrutil.Address
		var scriptClass string
		var reqSigs int
		var commitAmt *dcrutil.Amount
		if txType == stake.TxTypeSStx && (i%2 != 0) {
			scriptClass = sstxCommitmentString
			addr, err := stake.AddrFromSStxPkScrCommitment(v.PkScript,
				chainParams)
			if err != nil {
				rpcsLog.Warnf("failed to decode ticket "+
					"commitment addr output for tx hash "+
					"%v, output idx %v", mtx.TxHash(), i)
			} else {
				addrs = []dcrutil.Address{addr}
			}
			amt, err := stake.AmountFromSStxPkScrCommitment(v.PkScript)
			if err != nil {
				rpcsLog.Warnf("failed to decode ticket "+
					"commitment amt output for tx hash %v"+
					", output idx %v", mtx.TxHash(), i)
			} else {
				commitAmt = &amt
			}
		} else {
			// Ignore the error here since an error means the script
			// couldn't parse and there is no additional information
			// about it anyways.
			var sc txscript.ScriptClass
			sc, addrs, reqSigs, _ = txscript.ExtractPkScriptAddrs(
				v.Version, v.PkScript, chainParams)
			scriptClass = sc.String()
		}

		// Encode the addresses while checking if the address passes the
		// filter when needed.
		passesFilter := len(filterAddrMap) == 0
		encodedAddrs := make([]string, len(addrs))
		for j, addr := range addrs {
			encodedAddr := addr.Address()
			encodedAddrs[j] = encodedAddr

			// No need to check the map again if the filter already
			// passes.
			if passesFilter {
				continue
			}
			if _, exists := filterAddrMap[encodedAddr]; exists {
				passesFilter = true
			}
		}

		if !passesFilter {
			continue
		}

		var vout types.Vout
		voutSPK := &vout.ScriptPubKey
		vout.N = uint32(i)
		vout.Value = dcrutil.Amount(v.Value).ToCoin()
		vout.Version = v.Version
		voutSPK.Addresses = encodedAddrs
		voutSPK.Asm = disbuf
		voutSPK.Hex = hex.EncodeToString(v.PkScript)
		voutSPK.Type = scriptClass
		voutSPK.ReqSigs = int32(reqSigs)
		if commitAmt != nil {
			voutSPK.CommitAmt = dcrjson.Float64(commitAmt.ToCoin())
		}

		voutList = append(voutList, vout)
	}

	return voutList
}

// createTxRawResult converts the passed transaction and associated parameters
// to a raw transaction JSON object.
func createTxRawResult(chainParams *chaincfg.Params, mtx *wire.MsgTx, txHash string, blkIdx uint32, blkHeader *wire.BlockHeader, blkHash string, blkHeight int64, confirmations int64) (*types.TxRawResult, error) {
	mtxHex, err := messageToHex(mtx)
	if err != nil {
		return nil, err
	}

	if txHash != mtx.TxHash().String() {
		return nil, rpcInvalidError("Tx hash does not match: got %v "+
			"expected %v", txHash, mtx.TxHash())
	}

	txReply := &types.TxRawResult{
		Hex:         mtxHex,
		Txid:        txHash,
		Vin:         createVinList(mtx),
		Vout:        createVoutList(mtx, chainParams, nil),
		Version:     int32(mtx.Version),
		LockTime:    mtx.LockTime,
		Expiry:      mtx.Expiry,
		BlockHeight: blkHeight,
		BlockIndex:  blkIdx,
	}

	if blkHeader != nil {
		// This is not a typo, they are identical in bitcoind as well.
		txReply.Time = blkHeader.Timestamp.Unix()
		txReply.Blocktime = blkHeader.Timestamp.Unix()
		txReply.BlockHash = blkHash
		txReply.Confirmations = confirmations
	}

	return txReply, nil
}

// handleDecodeRawTransaction handles decoderawtransaction commands.
func handleDecodeRawTransaction(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.DecodeRawTransactionCmd)

	// Deserialize the transaction.
	hexStr := c.HexTx
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}
	serializedTx, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, rpcDecodeHexError(hexStr)
	}
	var mtx wire.MsgTx
	err = mtx.Deserialize(bytes.NewReader(serializedTx))
	if err != nil {
		return nil, rpcDeserializationError("Could not decode Tx: %v",
			err)
	}

	// Create and return the result.
	txReply := types.TxRawDecodeResult{
		Txid:     mtx.TxHash().String(),
		Version:  int32(mtx.Version),
		Locktime: mtx.LockTime,
		Expiry:   mtx.Expiry,
		Vin:      createVinList(&mtx),
		Vout:     createVoutList(&mtx, s.cfg.ChainParams, nil),
	}
	return txReply, nil
}

// handleDecodeScript handles decodescript commands.
func handleDecodeScript(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.DecodeScriptCmd)

	// Convert the hex script to bytes.
	hexStr := c.HexScript
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}
	script, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, rpcDecodeHexError(hexStr)
	}

	// Fetch the script version if provided.
	scriptVersion := uint16(0)
	if c.Version != nil {
		scriptVersion = *c.Version
	}

	// The disassembled string will contain [error] inline if the script
	// doesn't fully parse, so ignore the error here.
	disbuf, _ := txscript.DisasmString(script)

	// Get information about the script.
	// Ignore the error here since an error means the script couldn't parse
	// and there is no additional information about it anyways.
	scriptClass, addrs, reqSigs, _ := txscript.ExtractPkScriptAddrs(
		scriptVersion, script, s.cfg.ChainParams)
	addresses := make([]string, len(addrs))
	for i, addr := range addrs {
		addresses[i] = addr.Address()
	}

	// Convert the script itself to a pay-to-script-hash address.
	p2sh, err := dcrutil.NewAddressScriptHash(script, s.cfg.ChainParams)
	if err != nil {
		return nil, rpcInternalError(err.Error(),
			"Failed to convert script to pay-to-script-hash")
	}

	// Generate and return the reply.
	reply := types.DecodeScriptResult{
		Asm:       disbuf,
		ReqSigs:   int32(reqSigs),
		Type:      scriptClass.String(),
		Addresses: addresses,
	}
	if scriptClass != txscript.ScriptHashTy {
		reply.P2sh = p2sh.Address()
	}
	return reply, nil
}

// handleEstimateFee implements the estimatefee command.
// TODO this is a very basic implementation.  It should be
// modified to match the bitcoin-core one.
func handleEstimateFee(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	return cfg.minRelayTxFee.ToCoin(), nil
}

// handleEstimateSmartFee implements the estimatesmartfee command.
//
// The default estimation mode when unset is assumed as "conservative". As of
// 2018-12, the only supported mode is "conservative".
func handleEstimateSmartFee(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.EstimateSmartFeeCmd)

	mode := types.EstimateSmartFeeConservative
	if c.Mode != nil {
		mode = *c.Mode
	}

	if mode != types.EstimateSmartFeeConservative {
		return nil, rpcInvalidError("Only the default and conservative modes " +
			"are supported for smart fee estimation at the moment")
	}

	fee, err := s.cfg.FeeEstimator.EstimateFee(int32(c.Confirmations))
	if err != nil {
		return nil, rpcInternalError(err.Error(), "Could not estimate fee")
	}

	return fee.ToCoin(), nil
}

// handleEstimateStakeDiff implements the estimatestakediff command.
func handleEstimateStakeDiff(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.EstimateStakeDiffCmd)

	// Minimum possible stake difficulty.
	chain := s.cfg.Chain
	min, err := chain.EstimateNextStakeDifficulty(0, false)
	if err != nil {
		return nil, rpcInternalError(err.Error(), "Could not "+
			"estimate next minimum stake difficulty")
	}

	// Maximum possible stake difficulty.
	max, err := chain.EstimateNextStakeDifficulty(0, true)
	if err != nil {
		return nil, rpcInternalError(err.Error(), "Could not "+
			"estimate next maximum stake difficulty")
	}

	// The expected stake difficulty. Average the number of fresh stake
	// since the last retarget to get the number of tickets per block,
	// then use that to estimate the next stake difficulty.
	params := s.cfg.ChainParams
	bestHeight := chain.BestSnapshot().Height
	lastAdjustment := (bestHeight / params.StakeDiffWindowSize) *
		params.StakeDiffWindowSize
	nextAdjustment := ((bestHeight / params.StakeDiffWindowSize) + 1) *
		params.StakeDiffWindowSize
	totalTickets := 0
	for i := lastAdjustment; i <= bestHeight; i++ {
		bh, err := chain.HeaderByHeight(i)
		if err != nil {
			return nil, rpcInternalError(err.Error(), "Could not "+
				"estimate next stake difficulty")
		}
		totalTickets += int(bh.FreshStake)
	}
	blocksSince := float64(bestHeight - lastAdjustment + 1)
	remaining := float64(nextAdjustment - bestHeight - 1)
	averagePerBlock := float64(totalTickets) / blocksSince
	expectedTickets := int64(math.Floor(averagePerBlock * remaining))
	expected, err := chain.EstimateNextStakeDifficulty(expectedTickets,
		false)
	if err != nil {
		return nil, rpcInternalError(err.Error(), "Could not "+
			"estimate next stake difficulty")
	}

	// User-specified stake difficulty, if they asked for one.
	var userEstFltPtr *float64
	if c.Tickets != nil {
		userEst, err := chain.EstimateNextStakeDifficulty(int64(*c.Tickets),
			false)
		if err != nil {
			return nil, rpcInternalError(err.Error(), "Could not "+
				"estimate next user specified stake difficulty")
		}
		userEstFlt := dcrutil.Amount(userEst).ToCoin()
		userEstFltPtr = &userEstFlt
	}

	return &types.EstimateStakeDiffResult{
		Min:      dcrutil.Amount(min).ToCoin(),
		Max:      dcrutil.Amount(max).ToCoin(),
		Expected: dcrutil.Amount(expected).ToCoin(),
		User:     userEstFltPtr,
	}, nil
}

// handleExistsAddress implements the existsaddress command.
func handleExistsAddress(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	existsAddrIndex := s.cfg.SyncMgr.ExistsAddrIndex()
	if existsAddrIndex == nil {
		return nil, rpcInternalError("Exists address index disabled",
			"Configuration")
	}

	c := cmd.(*types.ExistsAddressCmd)

	// Decode the provided address.  This also ensures the network encoded with
	// the address matches the network the server is currently on.
	addr, err := dcrutil.DecodeAddress(c.Address, s.cfg.ChainParams)
	if err != nil {
		return nil, rpcAddressKeyError("Could not decode address: %v",
			err)
	}

	// Ensure the exists address index is synced.
	tHeight, tHash, err := existsAddrIndex.Tip()
	if err != nil {
		return nil, rpcInternalError(err.Error(), "")
	}

	chain := s.cfg.Chain
	if chain.BestSnapshot().Height > (tHeight + 5) {
		return nil, fmt.Errorf("%s: index not synced", existsAddrIndex.Name())
	}

	for !chain.BestSnapshot().Hash.IsEqual(tHash) {
		select {
		case <-time.After(syncWait):
			return nil, fmt.Errorf("%s: index not synced", existsAddrIndex.Name())
		case <-existsAddrIndex.WaitForSync():
		}
	}

	exists, err := existsAddrIndex.ExistsAddress(addr)
	if err != nil {
		return nil, rpcInvalidError("Could not query address: %v", err)
	}

	return exists, nil
}

// handleExistsAddresses implements the existsaddresses command.
func handleExistsAddresses(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	existsAddrIndex := s.cfg.SyncMgr.ExistsAddrIndex()
	if existsAddrIndex == nil {
		return nil, rpcInternalError("Exists address index disabled",
			"Configuration")
	}

	c := cmd.(*types.ExistsAddressesCmd)
	addresses := make([]dcrutil.Address, len(c.Addresses))
	for i := range c.Addresses {
		// Decode the provided address.  This also ensures the network encoded
		// with the address matches the network the server is currently on.
		addr, err := dcrutil.DecodeAddress(c.Addresses[i], s.cfg.ChainParams)
		if err != nil {
			return nil, rpcAddressKeyError("Could not decode address: %v", err)
		}
		addresses[i] = addr
	}

	// Ensure the exists address index is synced.
	tHeight, tHash, err := existsAddrIndex.Tip()
	if err != nil {
		return nil, rpcInternalError(err.Error(), "")
	}

	chain := s.cfg.Chain
	if chain.BestSnapshot().Height > (tHeight + 5) {
		return nil, fmt.Errorf("%s: index not synced", existsAddrIndex.Name())
	}

	for !chain.BestSnapshot().Hash.IsEqual(tHash) {
		select {
		case <-time.After(syncWait):
			return nil, fmt.Errorf("%s: index not synced", existsAddrIndex.Name())
		case <-existsAddrIndex.WaitForSync():
		}
	}

	exists, err := existsAddrIndex.ExistsAddresses(addresses)
	if err != nil {
		return nil, rpcInvalidError("Could not query address: %v", err)
	}

	// Convert the slice of bools into a compacted set of bit flags.
	set := bitset.NewBytes(len(c.Addresses))
	for i := range exists {
		if exists[i] {
			set.Set(i)
		}
	}

	return hex.EncodeToString([]byte(set)), nil
}

func decodeHashes(strs []string) ([]chainhash.Hash, error) {
	hashes := make([]chainhash.Hash, len(strs))
	for i, s := range strs {
		if len(s) != 2*chainhash.HashSize {
			return nil, rpcDecodeHexError(s)
		}
		_, err := hex.Decode(hashes[i][:], []byte(s))
		if err != nil {
			return nil, rpcDecodeHexError(s)
		}
		// unreverse hash string bytes
		for j := 0; j < 16; j++ {
			hashes[i][j], hashes[i][31-j] = hashes[i][31-j], hashes[i][j]
		}
	}
	return hashes, nil
}

func decodeHashPointers(strs []string) ([]*chainhash.Hash, error) {
	hashes := make([]*chainhash.Hash, len(strs))
	for i, s := range strs {
		h, err := chainhash.NewHashFromStr(s)
		if err != nil {
			return nil, rpcDecodeHexError(s)
		}
		hashes[i] = h
	}
	return hashes, nil
}

// handleExistsMissedTickets implements the existsmissedtickets command.
func handleExistsMissedTickets(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.ExistsMissedTicketsCmd)

	hashes, err := decodeHashes(c.TxHashes)
	if err != nil {
		return nil, err
	}

	exists := s.cfg.Chain.CheckMissedTickets(hashes)
	if len(exists) != len(hashes) {
		return nil, rpcInvalidError("Invalid missed ticket count "+
			"got %v, want %v", len(exists), len(hashes))
	}

	// Convert the slice of bools into a compacted set of bit flags.
	set := bitset.NewBytes(len(hashes))
	for i := range exists {
		if exists[i] {
			set.Set(i)
		}
	}

	return hex.EncodeToString([]byte(set)), nil
}

// handleExistsExpiredTickets implements the existsexpiredtickets command.
func handleExistsExpiredTickets(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.ExistsExpiredTicketsCmd)

	hashes, err := decodeHashes(c.TxHashes)
	if err != nil {
		return nil, err
	}

	exists := s.cfg.Chain.CheckExpiredTickets(hashes)
	if len(exists) != len(hashes) {
		return nil, rpcInvalidError("Invalid expired ticket count "+
			"got %v, want %v", len(exists), len(hashes))
	}

	// Convert the slice of bools into a compacted set of bit flags.
	set := bitset.NewBytes(len(hashes))
	for i := range exists {
		if exists[i] {
			set.Set(i)
		}
	}

	return hex.EncodeToString([]byte(set)), nil
}

// handleExistsLiveTicket implements the existsliveticket command.
func handleExistsLiveTicket(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.ExistsLiveTicketCmd)

	hash, err := chainhash.NewHashFromStr(c.TxHash)
	if err != nil {
		return nil, rpcDecodeHexError(c.TxHash)
	}

	return s.cfg.Chain.CheckLiveTicket(*hash), nil
}

// handleExistsLiveTickets implements the existslivetickets command.
func handleExistsLiveTickets(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.ExistsLiveTicketsCmd)

	hashes, err := decodeHashes(c.TxHashes)
	if err != nil {
		return nil, err
	}

	exists := s.cfg.Chain.CheckLiveTickets(hashes)
	if len(exists) != len(hashes) {
		return nil, rpcInvalidError("Invalid live ticket count got "+
			"%v, want %v", len(exists), len(hashes))
	}

	// Convert the slice of bools into a compacted set of bit flags.
	set := bitset.NewBytes(len(hashes))
	for i := range exists {
		if exists[i] {
			set.Set(i)
		}
	}

	return hex.EncodeToString([]byte(set)), nil
}

// handleExistsMempoolTxs implements the existsmempooltxs command.
func handleExistsMempoolTxs(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.ExistsMempoolTxsCmd)

	hashes, err := decodeHashPointers(c.TxHashes)
	if err != nil {
		return nil, err
	}

	exists := s.cfg.TxMemPool.HaveTransactions(hashes)
	if len(exists) != len(hashes) {
		return nil, rpcInternalError(fmt.Sprintf("got %v, want %v",
			len(exists), len(hashes)),
			"Invalid mempool Tx ticket count")
	}

	// Convert the slice of bools into a compacted set of bit flags.
	set := bitset.NewBytes(len(hashes))
	for i := range exists {
		if exists[i] {
			set.Set(i)
		}
	}

	return hex.EncodeToString([]byte(set)), nil
}

// handleGenerate handles generate commands.
func handleGenerate(ctx context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	// Respond with an error if there are no addresses to pay the
	// created blocks to.
	if len(cfg.miningAddrs) == 0 {
		return nil, rpcInternalError("No payment addresses specified "+
			"via --miningaddr", "Configuration")
	}

	// Respond with an error if there's virtually 0 chance of CPU-mining a block.
	params := s.cfg.ChainParams
	if !params.GenerateSupported {
		return nil, &dcrjson.RPCError{
			Code: dcrjson.ErrRPCDifficulty,
			Message: fmt.Sprintf("No support for `generate` on the current "+
				"network, %s, as it's unlikely to be possible to main a block "+
				"with the CPU.", params.Net),
		}
	}

	c := cmd.(*types.GenerateCmd)

	// Respond with an error if the client is requesting 0 blocks to be generated.
	if c.NumBlocks == 0 {
		return nil, rpcInternalError("Invalid number of blocks",
			"Configuration")
	}

	// Create a reply
	reply := make([]string, c.NumBlocks)

	blockHashes, err := s.cfg.CPUMiner.GenerateNBlocks(ctx, c.NumBlocks)
	if err != nil {
		return nil, rpcInternalError(err.Error(), "Could not generate blocks")
	}

	// Mine the correct number of blocks, assigning the hex representation of the
	// hash of each one to its place in the reply.
	for i, hash := range blockHashes {
		reply[i] = hash.String()
	}

	return reply, nil
}

// handleGetAddedNodeInfo handles getaddednodeinfo commands.
func handleGetAddedNodeInfo(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.GetAddedNodeInfoCmd)

	// Retrieve a list of persistent (added) peers from the Decred server
	// and filter the list of peers per the specified address (if any).
	peers := s.cfg.ConnMgr.AddedNodeInfo()
	if c.Node != nil {
		found := false
		for i, peer := range peers {
			if peer.Addr() == *c.Node {
				peers = peers[i : i+1]
				found = true
			}
		}
		if !found {
			return nil, rpcInternalError("Node not found", "")
		}
	}

	// Without the dns flag, the result is just a slice of the addresses as
	// strings.
	if !c.DNS {
		results := make([]string, 0, len(peers))
		for _, peer := range peers {
			results = append(results, peer.Addr())
		}
		return results, nil
	}

	// With the dns flag, the result is an array of JSON objects which
	// include the result of DNS lookups for each peer.
	results := make([]*types.GetAddedNodeInfoResult, 0, len(peers))
	for _, peer := range peers {
		// Set the "address" of the peer which could be an ip address
		// or a domain name.
		var result types.GetAddedNodeInfoResult
		result.AddedNode = peer.Addr()
		result.Connected = dcrjson.Bool(peer.Connected())

		// Split the address into host and port portions so we can do a
		// DNS lookup against the host.  When no port is specified in
		// the address, just use the address as the host.
		host, _, err := net.SplitHostPort(peer.Addr())
		if err != nil {
			host = peer.Addr()
		}

		// Do a DNS lookup for the address.  If the lookup fails, just
		// use the host.
		var ipList []string
		ips, err := dcrdLookup(host)
		if err == nil {
			ipList = make([]string, 0, len(ips))
			for _, ip := range ips {
				ipList = append(ipList, ip.String())
			}
		} else {
			ipList = make([]string, 1)
			ipList[0] = host
		}

		// Add the addresses and connection info to the result.
		addrs := make([]types.GetAddedNodeInfoResultAddr, 0,
			len(ipList))
		for _, ip := range ipList {
			var addr types.GetAddedNodeInfoResultAddr
			addr.Address = ip
			addr.Connected = "false"
			if ip == host && peer.Connected() {
				addr.Connected = directionString(peer.Inbound())
			}
			addrs = append(addrs, addr)
		}
		result.Addresses = &addrs
		results = append(results, &result)
	}
	return results, nil
}

// handleGetBestBlock implements the getbestblock command.
func handleGetBestBlock(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	// All other "get block" commands give either the height, the hash, or
	// both but require the block SHA.  This gets both for the best block.
	best := s.cfg.Chain.BestSnapshot()
	result := &types.GetBestBlockResult{
		Hash:   best.Hash.String(),
		Height: best.Height,
	}
	return result, nil
}

// handleGetBestBlockHash implements the getbestblockhash command.
func handleGetBestBlockHash(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	best := s.cfg.Chain.BestSnapshot()
	return best.Hash.String(), nil
}

// getDifficultyRatio returns the proof-of-work difficulty as a multiple of the
// minimum difficulty using the passed bits field from the header of a block.
func getDifficultyRatio(bits uint32, params *chaincfg.Params) float64 {
	// The minimum difficulty is the max possible proof-of-work limit bits
	// converted back to a number.  Note this is not the same as the proof
	// of work limit directly because the block difficulty is encoded in a
	// block with the compact form which loses precision.
	max := standalone.CompactToBig(params.PowLimitBits)
	target := standalone.CompactToBig(bits)

	difficulty := new(big.Rat).SetFrac(max, target)
	outString := difficulty.FloatString(8)
	diff, err := strconv.ParseFloat(outString, 64)
	if err != nil {
		rpcsLog.Errorf("Cannot get difficulty: %v", err)
		return 0
	}
	return diff
}

// handleGetBlock implements the getblock command.
func handleGetBlock(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.GetBlockCmd)

	// Load the raw block bytes from the database.
	hash, err := chainhash.NewHashFromStr(c.Hash)
	if err != nil {
		return nil, rpcDecodeHexError(c.Hash)
	}

	chain := s.cfg.Chain
	blk, err := chain.BlockByHash(hash)
	if err != nil {
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCBlockNotFound,
			Message: fmt.Sprintf("Block not found: %v", hash),
		}
	}

	// When the verbose flag isn't set, simply return the
	// network-serialized block as a hex-encoded string.
	if c.Verbose != nil && !*c.Verbose {
		blkBytes, err := blk.Bytes()
		if err != nil {
			return nil, rpcInternalError(err.Error(),
				"Could not serialize block")
		}

		return hex.EncodeToString(blkBytes), nil
	}

	chainWork, err := chain.ChainWork(hash)
	if err != nil {
		return nil, rpcInternalError(err.Error(), "Failed to retrieve work")
	}

	best := chain.BestSnapshot()

	// Get next block hash unless there are none.
	var nextHashString string
	blockHeader := &blk.MsgBlock().Header
	confirmations := int64(-1)
	if chain.MainChainHasBlock(hash) {
		if int64(blockHeader.Height) < best.Height {
			nextHash, err := chain.BlockHashByHeight(int64(blockHeader.Height + 1))
			if err != nil {
				context := "No next block"
				return nil, rpcInternalError(err.Error(), context)
			}
			nextHashString = nextHash.String()
		}
		confirmations = 1 + best.Height - int64(blockHeader.Height)
	}

	sbitsFloat := float64(blockHeader.SBits) / dcrutil.AtomsPerCoin
	blockReply := types.GetBlockVerboseResult{
		Hash:          c.Hash,
		Version:       blockHeader.Version,
		MerkleRoot:    blockHeader.MerkleRoot.String(),
		StakeRoot:     blockHeader.StakeRoot.String(),
		PreviousHash:  blockHeader.PrevBlock.String(),
		Nonce:         blockHeader.Nonce,
		VoteBits:      blockHeader.VoteBits,
		FinalState:    hex.EncodeToString(blockHeader.FinalState[:]),
		Voters:        blockHeader.Voters,
		FreshStake:    blockHeader.FreshStake,
		Revocations:   blockHeader.Revocations,
		PoolSize:      blockHeader.PoolSize,
		Time:          blockHeader.Timestamp.Unix(),
		StakeVersion:  blockHeader.StakeVersion,
		Confirmations: confirmations,
		Height:        int64(blockHeader.Height),
		Size:          int32(blk.MsgBlock().Header.Size),
		Bits:          strconv.FormatInt(int64(blockHeader.Bits), 16),
		SBits:         sbitsFloat,
		Difficulty:    getDifficultyRatio(blockHeader.Bits, s.cfg.ChainParams),
		ChainWork:     fmt.Sprintf("%064x", chainWork),
		ExtraData:     hex.EncodeToString(blockHeader.ExtraData[:]),
		NextHash:      nextHashString,
	}

	if c.VerboseTx == nil || !*c.VerboseTx {
		transactions := blk.Transactions()
		txNames := make([]string, len(transactions))
		for i, tx := range transactions {
			txNames[i] = tx.Hash().String()
		}

		blockReply.Tx = txNames

		stransactions := blk.STransactions()
		stxNames := make([]string, len(stransactions))
		for i, tx := range stransactions {
			stxNames[i] = tx.Hash().String()
		}

		blockReply.STx = stxNames
	} else {
		txns := blk.Transactions()
		chainParams := s.cfg.ChainParams
		rawTxns := make([]types.TxRawResult, len(txns))
		for i, tx := range txns {
			rawTxn, err := createTxRawResult(chainParams,
				tx.MsgTx(), tx.Hash().String(), uint32(i),
				blockHeader, blk.Hash().String(),
				int64(blockHeader.Height), confirmations)
			if err != nil {
				return nil, rpcInternalError(err.Error(),
					"Could not create transaction")
			}
			rawTxns[i] = *rawTxn
		}
		blockReply.RawTx = rawTxns

		stxns := blk.STransactions()
		rawSTxns := make([]types.TxRawResult, len(stxns))
		for i, tx := range stxns {
			rawSTxn, err := createTxRawResult(chainParams,
				tx.MsgTx(), tx.Hash().String(), uint32(i),
				blockHeader, blk.Hash().String(),
				int64(blockHeader.Height), confirmations)
			if err != nil {
				return nil, rpcInternalError(err.Error(),
					"Could not create stake transaction")
			}
			rawSTxns[i] = *rawSTxn
		}
		blockReply.RawSTx = rawSTxns
	}

	return blockReply, nil
}

// handleGetBlockchainInfo implements the getblockchaininfo command.
func handleGetBlockchainInfo(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	chain := s.cfg.Chain
	best := chain.BestSnapshot()

	// Fetch the current chain work using the the best block hash.
	chainWork, err := chain.ChainWork(&best.Hash)
	if err != nil {
		return nil, rpcInternalError(err.Error(), "Could not fetch chain work.")
	}

	// Estimate the verification progress of the node.
	syncHeight := s.cfg.SyncMgr.SyncHeight()
	var verifyProgress float64
	if syncHeight > 0 {
		verifyProgress = math.Min(float64(best.Height)/float64(syncHeight), 1.0)
	}

	// Fetch the maximum allowed block size.
	maxBlockSize, err := chain.MaxBlockSize()
	if err != nil {
		return nil, rpcInternalError(err.Error(),
			"Could not fetch max block size.")
	}

	// Fetch the agendas of the consensus deployments as well as their
	// threshold states and state activation heights.
	dInfo := make(map[string]types.AgendaInfo)
	params := s.cfg.ChainParams
	defaultStatus := blockchain.ThresholdStateTuple{
		State: blockchain.ThresholdDefined,
	}.String()
	for version, deployments := range params.Deployments {
		for _, agenda := range deployments {
			aInfo := types.AgendaInfo{
				StartTime:  agenda.StartTime,
				ExpireTime: agenda.ExpireTime,
				Status:     defaultStatus,
			}

			// If the best block is the genesis block, continue without attempting to
			// query the threshold state or state changed height.
			if best.PrevHash == zeroHash {
				dInfo[agenda.Vote.Id] = aInfo
				continue
			}

			state, err := chain.NextThresholdState(&best.PrevHash, version,
				agenda.Vote.Id)
			if err != nil {
				return nil, rpcInternalError(err.Error(),
					fmt.Sprintf("Could not fetch threshold state "+
						"for agenda with id (%v).", agenda.Vote.Id))
			}

			stateChangedHeight, err := chain.StateLastChangedHeight(
				&best.Hash, version, agenda.Vote.Id)
			if err != nil {
				return nil, rpcInternalError(err.Error(),
					fmt.Sprintf("Could not fetch state last changed "+
						"height for agenda with id (%v).", agenda.Vote.Id))
			}

			aInfo.Since = stateChangedHeight
			aInfo.Status = state.String()
			dInfo[agenda.Vote.Id] = aInfo
		}
	}

	// Generate rpc response.
	response := types.GetBlockChainInfoResult{
		Chain:                params.Name,
		Blocks:               best.Height,
		Headers:              best.Height,
		SyncHeight:           syncHeight,
		ChainWork:            fmt.Sprintf("%064x", chainWork),
		InitialBlockDownload: !chain.IsCurrent(),
		VerificationProgress: verifyProgress,
		BestBlockHash:        best.Hash.String(),
		Difficulty:           best.Bits,
		DifficultyRatio:      getDifficultyRatio(best.Bits, params),
		MaxBlockSize:         maxBlockSize,
		Deployments:          dInfo,
	}

	return response, nil
}

// handleGetBlockCount implements the getblockcount command.
func handleGetBlockCount(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	best := s.cfg.Chain.BestSnapshot()
	return best.Height, nil
}

// handleGetBlockHash implements the getblockhash command.
func handleGetBlockHash(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.GetBlockHashCmd)
	hash, err := s.cfg.Chain.BlockHashByHeight(c.Index)
	if err != nil {
		return nil, &dcrjson.RPCError{
			Code: dcrjson.ErrRPCOutOfRange,
			Message: fmt.Sprintf("Block number out of range: %v",
				c.Index),
		}
	}

	return hash.String(), nil
}

// handleGetBlockHeader implements the getblockheader command.
func handleGetBlockHeader(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.GetBlockHeaderCmd)

	// Fetch the header from chain.
	hash, err := chainhash.NewHashFromStr(c.Hash)
	if err != nil {
		return nil, rpcDecodeHexError(c.Hash)
	}

	chain := s.cfg.Chain
	blockHeader, err := chain.HeaderByHash(hash)
	if err != nil {
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCBlockNotFound,
			Message: fmt.Sprintf("Block not found: %v", c.Hash),
		}
	}

	// When the verbose flag isn't set, simply return the serialized block
	// header as a hex-encoded string.
	if c.Verbose != nil && !*c.Verbose {
		var headerBuf bytes.Buffer
		err := blockHeader.Serialize(&headerBuf)
		if err != nil {
			context := "Failed to serialize block header"
			return nil, rpcInternalError(err.Error(), context)
		}
		return hex.EncodeToString(headerBuf.Bytes()), nil
	}

	// The verbose flag is set, so generate the JSON object and return it.

	chainWork, err := chain.ChainWork(hash)
	if err != nil {
		return nil, rpcInternalError(err.Error(), "Failed to retrieve work")
	}

	best := chain.BestSnapshot()

	// Get next block hash unless there are none.
	var nextHashString string
	confirmations := int64(-1)
	height := int64(blockHeader.Height)
	if chain.MainChainHasBlock(hash) {
		if height < best.Height {
			nextHash, err := chain.BlockHashByHeight(height + 1)
			if err != nil {
				context := "No next block"
				return nil, rpcInternalError(err.Error(), context)
			}
			nextHashString = nextHash.String()
		}
		confirmations = 1 + best.Height - height
	}

	blockHeaderReply := types.GetBlockHeaderVerboseResult{
		Hash:          c.Hash,
		Confirmations: confirmations,
		Version:       blockHeader.Version,
		MerkleRoot:    blockHeader.MerkleRoot.String(),
		StakeRoot:     blockHeader.StakeRoot.String(),
		VoteBits:      blockHeader.VoteBits,
		FinalState:    hex.EncodeToString(blockHeader.FinalState[:]),
		Voters:        blockHeader.Voters,
		FreshStake:    blockHeader.FreshStake,
		Revocations:   blockHeader.Revocations,
		PoolSize:      blockHeader.PoolSize,
		Bits:          strconv.FormatInt(int64(blockHeader.Bits), 16),
		SBits:         dcrutil.Amount(blockHeader.SBits).ToCoin(),
		Height:        uint32(height),
		Size:          blockHeader.Size,
		Time:          blockHeader.Timestamp.Unix(),
		Nonce:         blockHeader.Nonce,
		ExtraData:     hex.EncodeToString(blockHeader.ExtraData[:]),
		StakeVersion:  blockHeader.StakeVersion,
		Difficulty:    getDifficultyRatio(blockHeader.Bits, s.cfg.ChainParams),
		ChainWork:     fmt.Sprintf("%064x", chainWork),
		PreviousHash:  blockHeader.PrevBlock.String(),
		NextHash:      nextHashString,
	}

	return blockHeaderReply, nil
}

// handleGetBlockSubsidy implements the getblocksubsidy command.
func handleGetBlockSubsidy(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.GetBlockSubsidyCmd)

	height := c.Height
	voters := c.Voters

	dev := s.cfg.SubsidyCache.CalcTreasurySubsidy(height, voters)
	pos := s.cfg.SubsidyCache.CalcStakeVoteSubsidy(height-1) * int64(voters)
	pow := s.cfg.SubsidyCache.CalcWorkSubsidy(height, voters)
	total := dev + pos + pow

	rep := types.GetBlockSubsidyResult{
		Developer: dev,
		PoS:       pos,
		PoW:       pow,
		Total:     total,
	}

	return rep, nil
}

// handleGetChainTips implements the getchaintips command.
func handleGetChainTips(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	chainTips := s.cfg.Chain.ChainTips()
	result := make([]types.GetChainTipsResult, 0, len(chainTips))
	for _, tip := range chainTips {
		result = append(result, types.GetChainTipsResult{
			Height:    tip.Height,
			Hash:      tip.Hash.String(),
			BranchLen: tip.BranchLen,
			Status:    tip.Status,
		})
	}
	return result, nil
}

// handleGetCoinSupply implements the getcoinsupply command.
func handleGetCoinSupply(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	return s.cfg.Chain.BestSnapshot().TotalSubsidy, nil
}

// handleGetConnectionCount implements the getconnectioncount command.
func handleGetConnectionCount(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	return s.cfg.ConnMgr.ConnectedCount(), nil
}

// handleGetCurrentNet implements the getcurrentnet command.
func handleGetCurrentNet(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	return s.cfg.ChainParams.Net, nil
}

// handleGetDifficulty implements the getdifficulty command.
func handleGetDifficulty(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	best := s.cfg.Chain.BestSnapshot()
	return getDifficultyRatio(best.Bits, s.cfg.ChainParams), nil
}

// handleGetGenerate implements the getgenerate command.
func handleGetGenerate(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	return s.cfg.CPUMiner.IsMining(), nil
}

// handleGetHashesPerSec implements the gethashespersec command.
func handleGetHashesPerSec(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	return int64(s.cfg.CPUMiner.HashesPerSecond()), nil
}

// handleGetCFilter implements the getcfilter command.
func handleGetCFilter(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	cfIndex := s.cfg.SyncMgr.CFIndex()
	if cfIndex == nil {
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCNoCFIndex,
			Message: "Compact filters must be enabled for this command",
		}
	}

	c := cmd.(*types.GetCFilterCmd)
	hash, err := chainhash.NewHashFromStr(c.Hash)
	if err != nil {
		return nil, rpcDecodeHexError(c.Hash)
	}

	var filterType wire.FilterType
	switch c.FilterType {
	case "regular":
		filterType = wire.GCSFilterRegular
	case "extended":
		filterType = wire.GCSFilterExtended
	default:
		return nil, rpcInvalidError("Unknown filter type %q", c.FilterType)
	}

	// Ensure the committed filter index is synced.
	tHeight, tHash, err := cfIndex.Tip()
	if err != nil {
		return nil, rpcInternalError(err.Error(), "")
	}

	chain := s.cfg.Chain
	if chain.BestSnapshot().Height > (tHeight + 5) {
		return nil, fmt.Errorf("%s: index not synced", cfIndex.Name())
	}

	for !chain.BestSnapshot().Hash.IsEqual(tHash) {
		select {
		case <-time.After(syncWait):
			return nil, fmt.Errorf("%s: index not synced", cfIndex.Name())
		case <-cfIndex.WaitForSync():
		}
	}

	filterBytes, err := cfIndex.FilterByBlockHash(hash, filterType)
	if err != nil {
		context := fmt.Sprintf("Failed to load %v filter for block %v",
			filterType, hash)
		return "", rpcInternalError(err.Error(), context)
	}
	if len(filterBytes) == 0 {
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCBlockNotFound,
			Message: fmt.Sprintf("Block not found: %v", hash),
		}
	}

	rpcsLog.Debugf("Found committed filter for %v", hash)
	return hex.EncodeToString(filterBytes), nil
}

// handleGetCFilterHeader implements the getcfilterheader command.
func handleGetCFilterHeader(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	cfIndex := s.cfg.SyncMgr.CFIndex()
	if cfIndex == nil {
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCNoCFIndex,
			Message: "The CF index must be enabled for this command",
		}
	}

	c := cmd.(*types.GetCFilterHeaderCmd)
	hash, err := chainhash.NewHashFromStr(c.Hash)
	if err != nil {
		return nil, rpcDecodeHexError(c.Hash)
	}

	var filterType wire.FilterType
	switch c.FilterType {
	case "regular":
		filterType = wire.GCSFilterRegular
	case "extended":
		filterType = wire.GCSFilterExtended
	default:
		return nil, rpcInvalidError("Unknown filter type %q",
			c.FilterType)
	}

	// Ensure the committed filter index is synced.
	tHeight, tHash, err := cfIndex.Tip()
	if err != nil {
		return nil, rpcInternalError(err.Error(), "")
	}

	chain := s.cfg.Chain
	if chain.BestSnapshot().Height > (tHeight + 5) {
		return nil, fmt.Errorf("%s: index not synced", cfIndex.Name())
	}

	for !chain.BestSnapshot().Hash.IsEqual(tHash) {
		select {
		case <-time.After(syncWait):
			return nil, fmt.Errorf("%s: index not synced", cfIndex.Name())
		case <-cfIndex.WaitForSync():
		}
	}

	headerBytes, err := cfIndex.FilterHeaderByBlockHash(hash, filterType)
	if err != nil {
		context := fmt.Sprintf("Failed to load %v filter header for block %v",
			filterType, hash)
		return "", rpcInternalError(err.Error(), context)
	}
	if bytes.Equal(headerBytes, zeroHash[:]) && *hash !=
		s.cfg.ChainParams.GenesisHash {

		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCBlockNotFound,
			Message: fmt.Sprintf("Block not found: %v", hash),
		}
	}

	hash.SetBytes(headerBytes)
	return hash.String(), nil
}

// handleGetHeaders implements the getheaders command.
func handleGetHeaders(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.GetHeadersCmd)
	blockLocators, err := decodeHashes(c.BlockLocators)
	if err != nil {
		// Already a *dcrjson.RPCError
		return nil, err
	}
	var hashStop chainhash.Hash
	if c.HashStop != "" {
		err := chainhash.Decode(&hashStop, c.HashStop)
		if err != nil {
			return nil, rpcInvalidError("Failed to decode "+
				"hashstop: %v", err)
		}
	}

	// Until wire.MsgGetHeaders uses []Hash instead of the []*Hash, this
	// conversion is necessary.  The wire protocol getheaders is (probably)
	// called much more often than this RPC, so chain.LocateHeaders is
	// optimized for that and this is given the performance penalty.
	locators := make(blockchain.BlockLocator, len(blockLocators))
	for i := range blockLocators {
		locators[i] = &blockLocators[i]
	}

	chain := s.cfg.Chain
	headers := chain.LocateHeaders(locators, &hashStop)

	// Return the serialized block headers as hex-encoded strings.
	hexBlockHeaders := make([]string, len(headers))
	var buf bytes.Buffer
	buf.Grow(wire.MaxBlockHeaderPayload)
	for i, h := range headers {
		err := h.Serialize(&buf)
		if err != nil {
			return nil, rpcInternalError(err.Error(),
				"Failed to serialize block header")
		}
		hexBlockHeaders[i] = hex.EncodeToString(buf.Bytes())
		buf.Reset()
	}
	return &types.GetHeadersResult{Headers: hexBlockHeaders}, nil
}

// handleGetCFilterV2 implements the getcfilterv2 command.
func handleGetCFilterV2(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.GetCFilterV2Cmd)
	hash, err := chainhash.NewHashFromStr(c.BlockHash)
	if err != nil {
		return nil, rpcDecodeHexError(c.BlockHash)
	}

	filter, err := s.cfg.Chain.FilterByBlockHash(hash)
	if err != nil {
		var nErr blockchain.NoFilterError
		if errors.As(err, &nErr) {
			return nil, &dcrjson.RPCError{
				Code:    dcrjson.ErrRPCBlockNotFound,
				Message: fmt.Sprintf("Block not found: %v", hash),
			}
		}

		context := fmt.Sprintf("Failed to load filter for block %s", hash)
		return nil, rpcInternalError(err.Error(), context)
	}

	// NOTE: When more header commitments are added, this will need to load the
	// inclusion proof for the filter from the database.  However, since there
	// is only currently a single commitment, there is only a single leaf in the
	// commitment merkle tree, and hence the proof hashes will always be empty
	// given there are no siblings.  Adding an additional header commitment will
	// require a consensus vote anyway and this can be updated at that time.
	result := &types.GetCFilterV2Result{
		BlockHash:   c.BlockHash,
		Data:        hex.EncodeToString(filter.Bytes()),
		ProofIndex:  blockchain.HeaderCmtFilterIndex,
		ProofHashes: nil,
	}
	return result, nil
}

// handleGetInfo implements the getinfo command. We only return the fields
// that are not related to wallet functionality.
func handleGetInfo(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	best := s.cfg.Chain.BestSnapshot()
	ret := &types.InfoChainResult{
		Version: int32(1000000*version.Major + 10000*version.Minor +
			100*version.Patch),
		ProtocolVersion: int32(maxProtocolVersion),
		Blocks:          best.Height,
		TimeOffset:      int64(s.cfg.TimeSource.Offset().Seconds()),
		Connections:     s.cfg.ConnMgr.ConnectedCount(),
		Proxy:           cfg.Proxy,
		Difficulty:      getDifficultyRatio(best.Bits, s.cfg.ChainParams),
		TestNet:         cfg.TestNet,
		RelayFee:        cfg.minRelayTxFee.ToCoin(),
		AddrIndex:       cfg.AddrIndex,
		TxIndex:         cfg.TxIndex,
	}

	return ret, nil
}

// handleGetMempoolInfo implements the getmempoolinfo command.
func handleGetMempoolInfo(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	mempoolTxns := s.cfg.TxMemPool.TxDescs()

	var numBytes int64
	for _, txD := range mempoolTxns {
		numBytes += int64(txD.Tx.MsgTx().SerializeSize())
	}

	ret := &types.GetMempoolInfoResult{
		Size:  int64(len(mempoolTxns)),
		Bytes: numBytes,
	}

	return ret, nil
}

// handleGetMiningInfo implements the getmininginfo command. We only return the
// fields that are not related to wallet functionality.
func handleGetMiningInfo(ctx context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	// Create a default getnetworkhashps command to use defaults and make
	// use of the existing getnetworkhashps handler.
	gnhpsCmd := types.NewGetNetworkHashPSCmd(nil, nil)
	networkHashesPerSecIface, err := handleGetNetworkHashPS(ctx, s, gnhpsCmd)
	if err != nil {
		return nil, err
	}
	networkHashesPerSec, ok := networkHashesPerSecIface.(int64)
	if !ok {
		return nil, rpcInternalError("invalid network hashes per sec",
			fmt.Sprintf("Invalid type: %q",
				networkHashesPerSecIface))
	}

	best := s.cfg.Chain.BestSnapshot()
	nextStakeDiff, err := s.cfg.Chain.CalcNextRequiredStakeDifficulty()
	if err != nil {
		return nil, rpcInternalError(err.Error(),
			"Could not calculate next stake difficulty")
	}

	result := types.GetMiningInfoResult{
		Blocks:           best.Height,
		CurrentBlockSize: best.BlockSize,
		CurrentBlockTx:   best.NumTxns,
		Difficulty:       getDifficultyRatio(best.Bits, s.cfg.ChainParams),
		StakeDifficulty:  nextStakeDiff,
		Generate:         s.cfg.CPUMiner.IsMining(),
		GenProcLimit:     s.cfg.CPUMiner.NumWorkers(),
		HashesPerSec:     int64(s.cfg.CPUMiner.HashesPerSecond()),
		NetworkHashPS:    networkHashesPerSec,
		PooledTx:         uint64(s.cfg.TxMemPool.Count()),
		TestNet:          cfg.TestNet,
	}
	return &result, nil
}

// handleGetNetTotals implements the getnettotals command.
func handleGetNetTotals(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	totalBytesRecv, totalBytesSent := s.cfg.ConnMgr.NetTotals()
	reply := &types.GetNetTotalsResult{
		TotalBytesRecv: totalBytesRecv,
		TotalBytesSent: totalBytesSent,
		TimeMillis:     s.cfg.Clock.Now().UTC().UnixNano() / int64(time.Millisecond),
	}
	return reply, nil
}

// handleGetNetworkHashPS implements the getnetworkhashps command.
func handleGetNetworkHashPS(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	// Note: All valid error return paths should return an int64.  Literal
	// zeros are inferred as int, and won't coerce to int64 because the
	// return value is an interface{}.

	c := cmd.(*types.GetNetworkHashPSCmd)

	// When the passed height is too high or zero, just return 0 now since
	// we can't reasonably calculate the number of network hashes per
	// second from invalid values.  When it's negative, use the current
	// best block height.
	chain := s.cfg.Chain
	best := chain.BestSnapshot()
	endHeight := int64(-1)
	if c.Height != nil {
		endHeight = int64(*c.Height)
	}
	if endHeight > best.Height || endHeight == 0 {
		return int64(0), nil
	}
	if endHeight < 0 {
		endHeight = best.Height
	}

	// Calculate the number of blocks per retarget interval based on the
	// chain parameters.
	params := s.cfg.ChainParams
	blocksPerRetarget := int64(params.TargetTimespan / params.TargetTimePerBlock)

	// Calculate the starting block height based on the passed number of
	// blocks.  When the passed value is negative, use the last block the
	// difficulty changed as the starting height.  Also make sure the
	// starting height is not before the beginning of the chain.

	numBlocks := int64(120)
	if c.Blocks != nil {
		numBlocks = int64(*c.Blocks)
	}

	var startHeight int64
	if numBlocks <= 0 {
		startHeight = endHeight - ((endHeight % blocksPerRetarget) + 1)
	} else {
		startHeight = endHeight - numBlocks
	}
	if startHeight < 0 {
		startHeight = 0
	}
	rpcsLog.Debugf("Calculating network hashes per second from %d to %d",
		startHeight, endHeight)

	// Find the min and max block timestamps as well as calculate the total
	// amount of work that happened between the start and end blocks.
	var minTimestamp, maxTimestamp time.Time
	totalWork := big.NewInt(0)
	for curHeight := startHeight; curHeight <= endHeight; curHeight++ {
		hash, err := chain.BlockHashByHeight(curHeight)
		if err != nil {
			context := "Failed to fetch block hash"
			return nil, rpcInternalError(err.Error(), context)
		}

		// Fetch the header from chain.
		header, err := chain.HeaderByHash(hash)
		if err != nil {
			context := "Failed to fetch block header"
			return nil, rpcInternalError(err.Error(), context)
		}

		if curHeight == startHeight {
			minTimestamp = header.Timestamp
			maxTimestamp = minTimestamp
		} else {
			totalWork.Add(totalWork, standalone.CalcWork(header.Bits))

			if minTimestamp.After(header.Timestamp) {
				minTimestamp = header.Timestamp
			}
			if maxTimestamp.Before(header.Timestamp) {
				maxTimestamp = header.Timestamp
			}
		}
	}

	// Calculate the difference in seconds between the min and max block
	// timestamps and avoid division by zero in the case where there is no
	// time difference.
	timeDiff := int64(maxTimestamp.Sub(minTimestamp) / time.Second)
	if timeDiff == 0 {
		return int64(0), nil
	}

	hashesPerSec := new(big.Int).Div(totalWork, big.NewInt(timeDiff))
	return hashesPerSec.Int64(), nil
}

// handleGetNetworkInfo implements the getnetworkinfo command.
func handleGetNetworkInfo(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	networks := cfg.generateNetworkInfo()
	lAddrs := s.cfg.AddrManager.LocalAddresses()
	localAddrs := make([]types.LocalAddressesResult, len(lAddrs))
	for idx, entry := range lAddrs {
		addr := types.LocalAddressesResult{
			Address: entry.Address,
			Port:    entry.Port,
		}
		localAddrs[idx] = addr
	}

	info := types.GetNetworkInfoResult{
		Version: int32(1000000*version.Major + 10000*version.Minor +
			100*version.Patch),
		SubVersion:      userAgentVersion,
		ProtocolVersion: int32(maxProtocolVersion),
		TimeOffset:      int64(s.cfg.TimeSource.Offset().Seconds()),
		Connections:     s.cfg.ConnMgr.ConnectedCount(),
		RelayFee:        cfg.minRelayTxFee.ToCoin(),
		Networks:        networks,
		LocalAddresses:  localAddrs,
		LocalServices:   fmt.Sprintf("%016x", uint64(s.cfg.Services)),
	}

	return info, nil
}

// handleGetPeerInfo implements the getpeerinfo command.
func handleGetPeerInfo(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	peers := s.cfg.ConnMgr.ConnectedPeers()
	syncPeerID := s.cfg.SyncMgr.SyncPeerID()
	infos := make([]*types.GetPeerInfoResult, 0, len(peers))
	for _, p := range peers {
		statsSnap := p.StatsSnapshot()
		info := &types.GetPeerInfoResult{
			ID:             statsSnap.ID,
			Addr:           statsSnap.Addr,
			AddrLocal:      p.LocalAddr().String(),
			Services:       fmt.Sprintf("%08d", uint64(statsSnap.Services)),
			RelayTxes:      !p.IsTxRelayDisabled(),
			LastSend:       statsSnap.LastSend.Unix(),
			LastRecv:       statsSnap.LastRecv.Unix(),
			BytesSent:      statsSnap.BytesSent,
			BytesRecv:      statsSnap.BytesRecv,
			ConnTime:       statsSnap.ConnTime.Unix(),
			PingTime:       float64(statsSnap.LastPingMicros),
			TimeOffset:     statsSnap.TimeOffset,
			Version:        statsSnap.Version,
			SubVer:         statsSnap.UserAgent,
			Inbound:        statsSnap.Inbound,
			StartingHeight: statsSnap.StartingHeight,
			CurrentHeight:  statsSnap.LastBlock,
			BanScore:       int32(p.BanScore()),
			SyncNode:       p.ID() == syncPeerID,
		}
		if p.LastPingNonce() != 0 {
			wait := float64(s.cfg.Clock.Since(statsSnap.LastPingTime).Nanoseconds())
			// We actually want microseconds.
			info.PingWait = wait / 1000
		}
		infos = append(infos, info)
	}
	return infos, nil
}

// handleGetRawMempool implements the getrawmempool command.
func handleGetRawMempool(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.GetRawMempoolCmd)

	// Choose the type to filter the results by based on the provided param.
	// A filter type of nil means no filtering.
	var filterType *stake.TxType
	if c.TxType != nil {
		switch types.GetRawMempoolTxTypeCmd(*c.TxType) {
		case types.GRMRegular:
			filterType = new(stake.TxType)
			*filterType = stake.TxTypeRegular
		case types.GRMTickets:
			filterType = new(stake.TxType)
			*filterType = stake.TxTypeSStx
		case types.GRMVotes:
			filterType = new(stake.TxType)
			*filterType = stake.TxTypeSSGen
		case types.GRMRevocations:
			filterType = new(stake.TxType)
			*filterType = stake.TxTypeSSRtx
		case types.GRMAll:
			// Nothing to do
		default:
			supported := []types.GetRawMempoolTxTypeCmd{types.GRMRegular,
				types.GRMTickets, types.GRMVotes, types.GRMRevocations,
				types.GRMAll}
			return nil, rpcInvalidError("Invalid transaction type: %s -- "+
				"supported types: %v", *c.TxType, supported)
		}
	}

	// Return verbose results if requested.
	mp := s.cfg.TxMemPool
	if c.Verbose != nil && *c.Verbose {
		descs := mp.VerboseTxDescs()
		result := make(map[string]*types.GetRawMempoolVerboseResult, len(descs))
		for i := range descs {
			desc := descs[i]
			if filterType != nil && desc.Type != *filterType {
				continue
			}

			tx := desc.Tx
			mpd := &types.GetRawMempoolVerboseResult{
				Size:             int32(tx.MsgTx().SerializeSize()),
				Fee:              dcrutil.Amount(desc.Fee).ToCoin(),
				Time:             desc.Added.Unix(),
				Height:           desc.Height,
				StartingPriority: desc.StartingPriority,
				CurrentPriority:  desc.CurrentPriority,
				Depends:          make([]string, len(desc.Depends)),
			}
			for j, depDesc := range desc.Depends {
				mpd.Depends[j] = depDesc.Tx.Hash().String()
			}

			result[tx.Hash().String()] = mpd
		}

		return result, nil
	}

	// The response is simply an array of the transaction hashes if the
	// verbose flag is not set.
	descs := mp.TxDescs()
	hashStrings := make([]string, 0, len(descs))
	for i := range descs {
		if filterType != nil && descs[i].Type != *filterType {
			continue
		}
		hashStrings = append(hashStrings, descs[i].Tx.Hash().String())
	}
	return hashStrings, nil
}

// handleGetRawTransaction implements the getrawtransaction command.
func handleGetRawTransaction(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.GetRawTransactionCmd)

	// Convert the provided transaction hash hex to a Hash.
	txHash, err := chainhash.NewHashFromStr(c.Txid)
	if err != nil {
		return nil, rpcDecodeHexError(c.Txid)
	}

	verbose := false
	if c.Verbose != nil {
		verbose = *c.Verbose != 0
	}

	// Try to fetch the transaction from the memory pool and if that fails,
	// try the block database.
	var mtx *wire.MsgTx
	var blkHash *chainhash.Hash
	var blkHeight int64
	var blkIndex uint32
	tx, err := s.cfg.TxMemPool.FetchTransaction(txHash)
	if err != nil {
		txIndex := s.cfg.TxIndex
		if txIndex == nil {
			return nil, rpcInternalError("The transaction index "+
				"must be enabled to query the blockchain "+
				"(specify --txindex)", "Configuration")
		}

		// Ensure the tx index is synced.
		tHeight, tHash, err := txIndex.Tip()
		if err != nil {
			return nil, rpcInternalError(err.Error(), "")
		}

		chain := s.cfg.Chain
		if chain.BestSnapshot().Height > (tHeight + 5) {
			return nil, fmt.Errorf("%s: index not synced", txIndex.Name())
		}

		for !chain.BestSnapshot().Hash.IsEqual(tHash) {
			select {
			case <-time.After(syncWait):
				return nil, fmt.Errorf("%s: index not synced", txIndex.Name())
			case <-txIndex.WaitForSync():
			}
		}

		// Look up the location of the transaction.
		idxEntry, err := txIndex.Entry(txHash)
		if err != nil {
			context := "Failed to retrieve transaction location"
			return nil, rpcInternalError(err.Error(), context)
		}
		if idxEntry == nil {
			return nil, rpcNoTxInfoError(txHash)
		}
		blockRegion := &idxEntry.BlockRegion

		// Load the raw transaction bytes from the database.
		var txBytes []byte
		err = s.cfg.DB.View(func(dbTx database.Tx) error {
			var err error
			txBytes, err = dbTx.FetchBlockRegion(blockRegion)
			return err
		})
		if err != nil {
			return nil, rpcNoTxInfoError(txHash)
		}

		// When the verbose flag isn't set, simply return the serialized
		// transaction as a hex-encoded string.  This is done here to
		// avoid deserializing it only to reserialize it again later.
		if !verbose {
			return hex.EncodeToString(txBytes), nil
		}

		// Grab the block details.
		blkHash = blockRegion.Hash
		blkHeight, err = s.cfg.Chain.BlockHeightByHash(blkHash)
		if err != nil {
			context := "Failed to retrieve block height"
			return nil, rpcInternalError(err.Error(), context)
		}
		blkIndex = idxEntry.BlockIndex

		// Deserialize the transaction
		var msgTx wire.MsgTx
		err = msgTx.Deserialize(bytes.NewReader(txBytes))
		if err != nil {
			context := "Failed to deserialize transaction"
			return nil, rpcInternalError(err.Error(), context)
		}
		mtx = &msgTx
	} else {
		// When the verbose flag isn't set, simply return the
		// network-serialized transaction as a hex-encoded string.
		if !verbose {
			// Note that this is intentionally not directly
			// returning because the first return value is a
			// string and it would result in returning an empty
			// string to the client instead of nothing (nil) in the
			// case of an error.
			mtxHex, err := messageToHex(tx.MsgTx())
			if err != nil {
				return nil, err
			}
			return mtxHex, nil
		}

		mtx = tx.MsgTx()
	}

	// The verbose flag is set, so generate the JSON object and return it.
	var (
		blkHeader     *wire.BlockHeader
		blkHashStr    string
		confirmations int64
	)
	if blkHash != nil {
		// Fetch the header from chain.
		header, err := s.cfg.Chain.HeaderByHash(blkHash)
		if err != nil {
			context := "Failed to fetch block header"
			return nil, rpcInternalError(err.Error(), context)
		}

		blkHeader = &header
		blkHashStr = blkHash.String()
		confirmations = 1 + s.cfg.Chain.BestSnapshot().Height - blkHeight
	}

	rawTxn, err := createTxRawResult(s.cfg.ChainParams, mtx, txHash.String(),
		blkIndex, blkHeader, blkHashStr, blkHeight, confirmations)
	if err != nil {
		return nil, err
	}
	return *rawTxn, nil
}

// handleGetStakeDifficulty implements the getstakedifficulty command.
func handleGetStakeDifficulty(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	chain := s.cfg.Chain
	best := chain.BestSnapshot()
	blockHeader, err := chain.HeaderByHeight(best.Height)
	if err != nil {
		rpcsLog.Errorf("Error getting block: %v", err)
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCDifficulty,
			Message: "Error getting stake difficulty: " + err.Error(),
		}
	}
	currentSdiff := dcrutil.Amount(blockHeader.SBits)

	nextSdiff, err := chain.CalcNextRequiredStakeDifficulty()
	if err != nil {
		context := "Could not calculate next stake difficulty"
		return nil, rpcInternalError(err.Error(), context)
	}
	nextSdiffAmount := dcrutil.Amount(nextSdiff)

	sDiffResult := &types.GetStakeDifficultyResult{
		CurrentStakeDifficulty: currentSdiff.ToCoin(),
		NextStakeDifficulty:    nextSdiffAmount.ToCoin(),
	}

	return sDiffResult, nil
}

// convertVersionMap translates a map[int]int into a sorted array of
// VersionCount that contains the same information.
func convertVersionMap(m map[int]int) []types.VersionCount {
	sorted := make([]types.VersionCount, 0, len(m))
	order := make([]int, 0, len(m))
	for k := range m {
		order = append(order, k)
	}
	sort.Ints(order)

	for _, v := range order {
		sorted = append(sorted, types.VersionCount{Version: uint32(v),
			Count: uint32(m[v])})
	}

	return sorted
}

// handleGetStakeVersionInfo implements the getstakeversioninfo command.
func handleGetStakeVersionInfo(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.GetStakeVersionInfoCmd)

	chain := s.cfg.Chain
	snapshot := chain.BestSnapshot()
	interval := s.cfg.ChainParams.StakeVersionInterval

	count := int32(1)
	if c.Count != nil {
		count = *c.Count
		if count <= 0 {
			return nil, rpcInvalidError("Count must be > 0")
		}

		// Limit the count to the total possible available intervals.
		totalIntervals := (snapshot.Height + interval - 1) / interval
		if int64(count) > totalIntervals {
			count = int32(totalIntervals)
		}
	}

	// Assemble JSON result.
	result := types.GetStakeVersionInfoResult{
		CurrentHeight: snapshot.Height,
		Hash:          snapshot.Hash.String(),
		Intervals:     make([]types.VersionInterval, 0, count),
	}

	startHeight := snapshot.Height
	endHeight := chain.CalcWantHeight(interval, snapshot.Height) + 1
	hash := &snapshot.Hash
	adjust := int32(1) // We are off by one on the initial iteration.
	for i := int32(0); i < count; i++ {
		numBlocks := int32(startHeight - endHeight)
		if numBlocks <= 0 {
			// Just return what we got.
			break
		}
		sv, err := chain.GetStakeVersions(hash, numBlocks+adjust)
		if err != nil {
			context := fmt.Sprintf("Failed to get stake versions starting "+
				"from hash %v", hash)
			return nil, rpcInternalError(err.Error(), context)
		}

		posVersions := make(map[int]int)
		voteVersions := make(map[int]int)
		for _, v := range sv {
			posVersions[int(v.StakeVersion)]++
			for _, vote := range v.Votes {
				voteVersions[int(vote.Version)]++
			}
		}
		versionInterval := types.VersionInterval{
			StartHeight:  endHeight,
			EndHeight:    startHeight,
			PoSVersions:  convertVersionMap(posVersions),
			VoteVersions: convertVersionMap(voteVersions),
		}
		result.Intervals = append(result.Intervals, versionInterval)

		// Adjust interval.
		endHeight -= interval
		startHeight = endHeight + interval
		adjust = 0

		// Get prior block hash.
		hash, err = chain.BlockHashByHeight(startHeight - 1)
		if err != nil {
			context := fmt.Sprintf("Failed to get block hash for height %d",
				startHeight-1)
			return nil, rpcInternalError(err.Error(), context)
		}
	}

	return result, nil
}

// handleGetStakeVersions implements the getstakeversions command.
func handleGetStakeVersions(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.GetStakeVersionsCmd)

	hash, err := chainhash.NewHashFromStr(c.Hash)
	if err != nil {
		return nil, rpcDecodeHexError(c.Hash)
	}
	if c.Count <= 0 {
		return nil, rpcInvalidError("Invalid parameter, count must " +
			"be > 0")
	}

	sv, err := s.cfg.Chain.GetStakeVersions(hash, c.Count)
	if err != nil {
		return nil, rpcInternalError(err.Error(),
			"Could not obtain stake versions")
	}

	result := types.GetStakeVersionsResult{
		StakeVersions: make([]types.StakeVersions, 0, len(sv)),
	}
	for _, v := range sv {
		nsv := types.StakeVersions{
			Hash:         v.Hash.String(),
			Height:       v.Height,
			BlockVersion: v.BlockVersion,
			StakeVersion: v.StakeVersion,
			Votes: make([]types.VersionBits, 0,
				len(v.Votes)),
		}
		for _, vote := range v.Votes {
			nsv.Votes = append(nsv.Votes,
				types.VersionBits{Version: vote.Version, Bits: vote.Bits})
		}

		result.StakeVersions = append(result.StakeVersions, nsv)
	}

	return result, nil
}

// handleGetTicketPoolValue implements the getticketpoolvalue command.
func handleGetTicketPoolValue(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	amt, err := s.cfg.Chain.TicketPoolValue()
	if err != nil {
		return nil, rpcInternalError(err.Error(),
			"Could not obtain ticket pool value")
	}

	return amt.ToCoin(), nil
}

// handleGetVoteInfo implements the getvoteinfo command.
func handleGetVoteInfo(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.GetVoteInfoCmd)

	// Shorter versions of some parameters for convenience.
	interval := int64(s.cfg.ChainParams.RuleChangeActivationInterval)
	quorum := s.cfg.ChainParams.RuleChangeActivationQuorum
	chain := s.cfg.Chain
	snapshot := chain.BestSnapshot()

	vi, err := chain.GetVoteInfo(&snapshot.Hash, c.Version)
	if err != nil {
		var vErr blockchain.VoteVersionError
		if errors.As(err, &vErr) {
			return nil, rpcInvalidError("%d: unrecognized vote version",
				c.Version)
		}
		return nil, rpcInternalError(err.Error(), "could not obtain vote info")
	}

	// Assemble JSON result.
	result := types.GetVoteInfoResult{
		CurrentHeight: snapshot.Height,
		StartHeight:   chain.CalcWantHeight(interval, snapshot.Height) + 1,
		EndHeight:     chain.CalcWantHeight(interval, snapshot.Height) + interval,
		Hash:          snapshot.Hash.String(),
		VoteVersion:   c.Version,
		Quorum:        quorum,
	}

	// We don't fail, we try to return the totals for this version.
	result.TotalVotes, err = chain.CountVoteVersion(c.Version)
	if err != nil {
		return nil, rpcInternalError(err.Error(),
			"could not count voter versions")
	}

	result.Agendas = make([]types.Agenda, 0, len(vi.Agendas))
	for _, agenda := range vi.Agendas {
		// Obtain status of agenda.
		state, err := chain.NextThresholdState(&snapshot.Hash, c.Version,
			agenda.Vote.Id)
		if err != nil {
			return nil, err
		}

		a := types.Agenda{
			ID:          agenda.Vote.Id,
			Description: agenda.Vote.Description,
			Mask:        agenda.Vote.Mask,
			Choices:     make([]types.Choice, 0, len(agenda.Vote.Choices)),
			StartTime:   agenda.StartTime,
			ExpireTime:  agenda.ExpireTime,
			Status:      state.String(),
		}

		// Handle choices.
		for _, choice := range agenda.Vote.Choices {
			a.Choices = append(a.Choices, types.Choice{
				ID:          choice.Id,
				Description: choice.Description,
				Bits:        choice.Bits,
				IsAbstain:   choice.IsAbstain,
				IsNo:        choice.IsNo,
			})
		}

		if state.State != blockchain.ThresholdStarted {
			// Append transformed agenda without progress.
			result.Agendas = append(result.Agendas, a)
			continue
		}

		counts, err := s.cfg.Chain.GetVoteCounts(c.Version, agenda.Vote.Id)
		if err != nil {
			return nil, rpcInternalError(err.Error(),
				"could not obtain vote count")
		}

		// Calculate quorum.
		qmin := quorum
		totalNonAbstain := counts.Total - counts.TotalAbstain
		if totalNonAbstain < quorum {
			qmin = totalNonAbstain
		}
		a.QuorumProgress = float64(qmin) / float64(quorum)

		// Calculate choice progress.
		for k := range a.Choices {
			a.Choices[k].Count = counts.VoteChoices[k]
			a.Choices[k].Progress = float64(counts.VoteChoices[k]) /
				float64(counts.Total)
		}

		// Append transformed agenda.
		result.Agendas = append(result.Agendas, a)
	}

	return result, nil
}

// bigToLEUint256 returns the passed big integer as an unsigned 256-bit integer
// encoded as little-endian bytes.  Numbers which are larger than the max
// unsigned 256-bit integer are truncated.
func bigToLEUint256(n *big.Int) [uint256Size]byte {
	// Pad or truncate the big-endian big int to correct number of bytes.
	nBytes := n.Bytes()
	nlen := len(nBytes)
	pad := 0
	start := 0
	if nlen <= uint256Size {
		pad = uint256Size - nlen
	} else {
		start = nlen - uint256Size
	}
	var buf [uint256Size]byte
	copy(buf[pad:], nBytes[start:])

	// Reverse the bytes to little endian and return them.
	for i := 0; i < uint256Size/2; i++ {
		buf[i], buf[uint256Size-1-i] = buf[uint256Size-1-i], buf[i]
	}
	return buf
}

// handleGetTxOut handles gettxout commands.
func handleGetTxOut(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.GetTxOutCmd)

	// Convert the provided transaction hash hex to a Hash.
	txHash, err := chainhash.NewHashFromStr(c.Txid)
	if err != nil {
		return nil, rpcDecodeHexError(c.Txid)
	}

	// If requested and the tx is available in the mempool try to fetch it
	// from there, otherwise attempt to fetch from the block database.
	var bestBlockHash string
	var confirmations int64
	var txVersion uint16
	var value int64
	var scriptVersion uint16
	var pkScript []byte
	var isCoinbase bool
	includeMempool := true
	if c.IncludeMempool != nil {
		includeMempool = *c.IncludeMempool
	}
	var txFromMempool *dcrutil.Tx
	if includeMempool {
		txFromMempool, _ = s.cfg.TxMemPool.FetchTransaction(txHash)
	}
	if txFromMempool != nil {
		mtx := txFromMempool.MsgTx()
		if c.Vout > uint32(len(mtx.TxOut)-1) {
			return nil, &dcrjson.RPCError{
				Code: dcrjson.ErrRPCInvalidTxVout,
				Message: "Output index number (vout) does not " +
					"exist for transaction.",
			}
		}

		txOut := mtx.TxOut[c.Vout]
		if txOut == nil {
			errStr := fmt.Sprintf("Output index: %d for txid: %s "+
				"does not exist", c.Vout, txHash)
			return nil, rpcInternalError(errStr, "")
		}

		best := s.cfg.Chain.BestSnapshot()
		bestBlockHash = best.Hash.String()
		confirmations = 0
		txVersion = mtx.Version
		value = txOut.Value
		scriptVersion = txOut.Version
		pkScript = txOut.PkScript
		isCoinbase = standalone.IsCoinBaseTx(mtx)
	} else {
		entry, err := s.cfg.Chain.FetchUtxoEntry(txHash)
		if err != nil {
			context := "Failed to retrieve utxo entry"
			return nil, rpcInternalError(err.Error(), context)
		}

		// To match the behavior of the reference client, return nil
		// (JSON null) if the transaction output could not be found
		// (never existed or was pruned) or is spent by another
		// transaction already in the main chain.  Mined transactions
		// that are spent by a mempool transaction are not affected by
		// this.
		if entry == nil || entry.IsOutputSpent(c.Vout) {
			return nil, nil
		}

		best := s.cfg.Chain.BestSnapshot()
		bestBlockHash = best.Hash.String()
		confirmations = 1 + best.Height - entry.BlockHeight()
		txVersion = entry.TxVersion()
		value = entry.AmountByIndex(c.Vout)
		scriptVersion = entry.ScriptVersionByIndex(c.Vout)
		pkScript = entry.PkScriptByIndex(c.Vout)
		isCoinbase = entry.IsCoinBase()
	}

	// Disassemble script into single line printable format.  The
	// disassembled string will contain [error] inline if the script
	// doesn't fully parse, so ignore the error here.
	script := pkScript
	disbuf, _ := txscript.DisasmString(script)

	// Get further info about the script.  Ignore the error here since an
	// error means the script couldn't parse and there is no additional
	// information about it anyways.
	scriptClass, addrs, reqSigs, _ := txscript.ExtractPkScriptAddrs(
		scriptVersion, script, s.cfg.ChainParams)
	addresses := make([]string, len(addrs))
	for i, addr := range addrs {
		addresses[i] = addr.Address()
	}

	txOutReply := &types.GetTxOutResult{
		BestBlock:     bestBlockHash,
		Confirmations: confirmations,
		Value:         dcrutil.Amount(value).ToUnit(dcrutil.AmountCoin),
		Version:       int32(txVersion),
		ScriptPubKey: types.ScriptPubKeyResult{
			Asm:       disbuf,
			Hex:       hex.EncodeToString(pkScript),
			ReqSigs:   int32(reqSigs),
			Type:      scriptClass.String(),
			Addresses: addresses,
		},
		Coinbase: isCoinbase,
	}
	return txOutReply, nil
}

// handleGetTxOutSetInfo returns statistics on the current unspent transaction output set.
func handleGetTxOutSetInfo(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	best := s.cfg.Chain.BestSnapshot()
	stats, err := s.cfg.Chain.FetchUtxoStats()
	if err != nil {
		return nil, err
	}

	return types.GetTxOutSetInfoResult{
		Height:         best.Height,
		BestBlock:      best.Hash.String(),
		Transactions:   stats.Transactions,
		TxOuts:         stats.Utxos,
		DiskSize:       stats.Size,
		TotalAmount:    stats.Total,
		SerializedHash: stats.SerializedHash.String(),
	}, nil
}

// pruneOldBlockTemplates prunes all old block templates from the templatePool
// map.
//
// This function MUST be called with the RPC workstate locked.
func (s *workState) pruneOldBlockTemplates(bestHeight int64) {
	pruneHeight := bestHeight - getworkExpirationDiff
	for key, block := range s.templatePool {
		height := int64(block.Header.Height)
		if height < pruneHeight {
			delete(s.templatePool, key)
		}
	}
}

// getWorkTemplateKey returns the key to use for the template pool that houses
// the information necessary to construct full blocks from getwork submissions.
func getWorkTemplateKey(header *wire.BlockHeader) [merkleRootPairSize]byte {
	// Create the new template key which is the MerkleRoot + StakeRoot fields.
	// Note that with DCP0005 active, the stake root field will be merged with
	// the merkle root field and the stake root field will be a commitment
	// root.  Since the commitment root changes with the contents of the block
	// it will still be a good piece of information to add to the key.
	var merkleRootPair [merkleRootPairSize]byte
	copy(merkleRootPair[:chainhash.HashSize], header.MerkleRoot[:])
	copy(merkleRootPair[chainhash.HashSize:], header.StakeRoot[:])
	return merkleRootPair
}

// handleGetWorkRequest is a helper for handleGetWork which deals with
// generating and returning work to the caller.
//
// This function MUST be called with the RPC workstate locked.
func handleGetWorkRequest(s *rpcServer) (interface{}, error) {
	// Prune old templates and wait for updated templates when the current best
	// chain changes.
	state := s.workState
	best := s.cfg.Chain.BestSnapshot()
	bgTmplGenerator := s.cfg.BgBlkTmplGenerator()
	var template *BlockTemplate
	if state.prevHash == nil || *state.prevHash != best.Hash {
		// Prune old templates from the pool when the best block changes.
		state.pruneOldBlockTemplates(best.Height)
		state.prevHash = &best.Hash

		// Wait until a new template is generated.  Since the subscription
		// immediately sends the current template, the template might not have
		// been updated yet (for example, it might be waiting on votes).  In
		// that case, wait for the updated template with an eventual timeout
		// in case the new tip never gets enough votes and no other events
		// that trigger a new template have happened.
		templateSub := bgTmplGenerator.Subscribe()
		templateNtfn := <-templateSub.C()
		template = templateNtfn.Template
		templateKey := getWorkTemplateKey(&template.Block.Header)
		if _, ok := state.templatePool[templateKey]; ok {
			const maxTemplateTimeoutDuration = time.Millisecond * 5500
			select {
			case templateNtfn = <-templateSub.C():
				template = templateNtfn.Template

			case <-time.After(maxTemplateTimeoutDuration):
				template = nil
			}
		}
		templateSub.Stop()
	}

	// Grab the current template from the background generator immediately when
	// it was not already obtained above.  Return any errors that might have
	// happened when generating the template.
	if template == nil {
		var err error
		template, err = bgTmplGenerator.CurrentTemplate()
		if err != nil || template == nil {
			context := "Unable to retrieve work due to invalid template"
			return nil, rpcInternalError(err.Error(), context)
		}
	}

	// Update the time of the block template to the current time while
	// accounting for the median time of the past several blocks per the chain
	// consensus rules.  Note that the header is copied to avoid mutating the
	// shared block template.
	headerCopy := template.Block.Header
	err := bgTmplGenerator.tg.UpdateBlockTime(&headerCopy)
	if err != nil {
		context := "Failed to update block time"
		return nil, rpcInternalError(err.Error(), context)
	}

	// Serialize the block header into a buffer large enough to hold the
	// the block header and the internal blake256 padding that is added and
	// retuned as part of the data below.
	//
	// For reference (0-index based, end value is exclusive):
	// data[115:119] --> Bits
	// data[135:139] --> Timestamp
	// data[139:143] --> Nonce
	// data[143:151] --> ExtraNonce
	data := make([]byte, 0, getworkDataLen)
	buf := bytes.NewBuffer(data)
	err = headerCopy.Serialize(buf)
	if err != nil {
		context := "Failed to serialize data"
		return nil, rpcInternalError(err.Error(), context)
	}

	// Add the template to the template pool.  Since the key is a combination
	// of the merkle and stake root fields, this will not add duplicate entries
	// for the templates with modified timestamps and/or difficulty bits.
	templateKey := getWorkTemplateKey(&headerCopy)
	state.templatePool[templateKey] = template.Block

	// Expand the data slice to include the full data buffer and apply the
	// internal blake256 padding.  This makes the data ready for callers to
	// make use of only the final chunk along with the midstate for the
	// rest.
	data = data[:getworkDataLen]
	copy(data[wire.MaxBlockHeaderPayload:], blake256Pad)

	// The target is in big endian, but it is treated as a uint256 and byte
	// swapped to little endian in the final result.  Even though there is
	// really no reason for it to be swapped, it is a holdover from legacy code
	// and is now required for compatibility.
	target := bigToLEUint256(standalone.CompactToBig(headerCopy.Bits))
	reply := &types.GetWorkResult{
		Data:   hex.EncodeToString(data),
		Target: hex.EncodeToString(target[:]),
	}
	return reply, nil
}

// handleGetWorkSubmission is a helper for handleGetWork which deals with
// the calling submitting work to be verified and processed.
//
// This function MUST be called with the RPC workstate locked.
func handleGetWorkSubmission(_ context.Context, s *rpcServer, hexData string) (interface{}, error) {
	// Ensure the provided data is sane.
	if len(hexData)%2 != 0 {
		hexData = "0" + hexData
	}
	data, err := hex.DecodeString(hexData)
	if err != nil {
		return false, rpcDecodeHexError(hexData)
	}
	if len(data) != getworkDataLen {
		return nil, rpcInvalidError("Argument must be %d bytes (not "+
			"%d)", getworkDataLen, len(data))
	}

	// Deserialize the block header from the data.
	var submittedHeader wire.BlockHeader
	bhBuf := bytes.NewReader(data[0:wire.MaxBlockHeaderPayload])
	err = submittedHeader.Deserialize(bhBuf)
	if err != nil {
		return false, rpcInvalidError("Invalid block header: %v", err)
	}

	// Ensure the submitted block hash is less than the target difficulty.
	blockHash := submittedHeader.BlockHash()
	err = standalone.CheckProofOfWork(&blockHash, submittedHeader.Bits,
		s.cfg.ChainParams.PowLimit)
	if err != nil {
		// Anything other than a rule violation is an unexpected error, so
		// return that error as an internal error.
		var rErr blockchain.RuleError
		if !errors.As(err, &rErr) {
			context := "Unexpected error while checking proof of work"
			return false, rpcInternalError(err.Error(), context)
		}

		rpcsLog.Errorf("Block submitted via getwork does not meet the "+
			"required proof of work: %v", err)
		return false, nil
	}

	// Look up the full block for the provided data based on the merkle and
	// stake roots.  Return false to indicate the solve failed if it's not
	// available.
	templateKey := getWorkTemplateKey(&submittedHeader)
	templateBlock, ok := s.workState.templatePool[templateKey]
	if !ok || templateBlock == nil {
		rpcsLog.Errorf("Block submitted via getwork has no matching template "+
			"for merkle root %s, stake root %s",
			submittedHeader.MerkleRoot, submittedHeader.StakeRoot)
		return false, nil
	}

	// Reconstruct the block using the submitted header stored block info.  Note
	// that the block template is shallow copied to avoid mutating the header
	// of the shared block template.
	msgBlock := *templateBlock
	msgBlock.Header = submittedHeader
	block := dcrutil.NewBlock(&msgBlock)

	// Process this block using the same rules as blocks coming from other
	// nodes.  This will in turn relay it to the network like normal.
	isOrphan, err := s.cfg.SyncMgr.SubmitBlock(block, blockchain.BFNone)
	if err != nil {
		// Anything other than a rule violation is an unexpected error,
		// so return that error as an internal error.
		var rErr blockchain.RuleError
		if !errors.As(err, &rErr) {
			context := "Unexpected error while processing block"
			return false, rpcInternalError(err.Error(), context)
		}

		rpcsLog.Infof("Block submitted via getwork rejected: %v", err)
		return false, nil
	}

	if isOrphan {
		rpcsLog.Infof("Block submitted via getwork rejected: an orphan "+
			"building on parent %v", block.MsgBlock().Header.PrevBlock)
		return false, nil
	}

	// The block was accepted.
	rpcsLog.Infof("Block submitted via getwork accepted: %s (height %d)",
		block.Hash(), msgBlock.Header.Height)
	return true, nil
}

// handleGetWork implements the getwork command.
func handleGetWork(ctx context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	if s.cfg.CPUMiner.IsMining() {
		return nil, rpcMiscError("getwork polling is disallowed " +
			"while CPU mining is enabled. Please disable CPU " +
			"mining and try again.")
	}

	// Respond with an error if there are no addresses to pay the created
	// blocks to.
	if len(cfg.miningAddrs) == 0 {
		return nil, rpcInternalError("No payment addresses specified "+
			"via --miningaddr", "Configuration")
	}

	// Return an error if there are no peers connected since there is no way to
	// relay a found block or receive transactions to work on unless
	// unsynchronized mining has specifically been allowed.
	if !cfg.AllowUnsyncedMining && s.cfg.ConnMgr.ConnectedCount() == 0 {
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCClientNotConnected,
			Message: "Decred is not connected",
		}
	}

	// No point in generating or accepting work before the chain is synced
	// unless unsynchronized mining has specifically been allowed.
	bestHeight := s.cfg.Chain.BestSnapshot().Height
	if !cfg.AllowUnsyncedMining && bestHeight != 0 && !s.cfg.Chain.IsCurrent() {
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCClientInInitialDownload,
			Message: "Decred is downloading blocks...",
		}
	}

	c := cmd.(*types.GetWorkCmd)

	// Protect concurrent access from multiple RPC invocations for work
	// requests and submission.
	s.workState.Lock()
	defer s.workState.Unlock()

	// When the caller provides data, it is a submission of a supposedly
	// solved block that needs to be checked and submitted to the network
	// if valid.
	if c.Data != nil && *c.Data != "" {
		return handleGetWorkSubmission(ctx, s, *c.Data)
	}

	// No data was provided, so the caller is requesting work.
	return handleGetWorkRequest(s)
}

// handleHelp implements the help command.
func handleHelp(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.HelpCmd)

	// Provide a usage overview of all commands when no specific command
	// was specified.
	var method types.Method
	if c.Command != nil {
		method = types.Method(*c.Command)
	}
	if method == "" {
		usage, err := s.helpCacher.rpcUsage(false)
		if err != nil {
			context := "Failed to generate RPC usage"
			return nil, rpcInternalError(err.Error(), context)
		}
		return usage, nil
	}

	// Check that the command asked for is supported and implemented.  Only
	// search the main list of handlers since help should not be provided
	// for commands that are unimplemented or related to wallet
	// functionality.
	if _, ok := rpcHandlers[method]; !ok {
		return nil, rpcInvalidError("Unknown method: %v", method)
	}

	// Get the help for the command.
	help, err := s.helpCacher.rpcMethodHelp(method)
	if err != nil {
		context := "Failed to generate help"
		return nil, rpcInternalError(err.Error(), context)
	}
	return help, nil
}

// handleLiveTickets implements the livetickets command.
func handleLiveTickets(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	lt, err := s.cfg.Chain.LiveTickets()
	if err != nil {
		return nil, rpcInternalError("Could not get live tickets "+
			err.Error(), "")
	}

	ltString := make([]string, len(lt))
	for i := range lt {
		ltString[i] = lt[i].String()
	}

	return types.LiveTicketsResult{Tickets: ltString}, nil
}

// handleMissedTickets implements the missedtickets command.
func handleMissedTickets(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	mt, err := s.cfg.Chain.MissedTickets()
	if err != nil {
		return nil, rpcInternalError("Could not get missed tickets "+
			err.Error(), "")
	}

	mtString := make([]string, len(mt))
	for i, hash := range mt {
		mtString[i] = hash.String()
	}

	return types.MissedTicketsResult{Tickets: mtString}, nil
}

// handlePing implements the ping command.
func handlePing(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	// Ask server to ping \o_
	nonce, err := wire.RandomUint64()
	if err != nil {
		return nil, rpcInternalError("Not sending ping - failed to "+
			"generate nonce: "+err.Error(), "")
	}
	s.cfg.ConnMgr.BroadcastMessage(wire.NewMsgPing(nonce))

	return nil, nil
}

// handleRegenTemplate implements the regentemplate command.
func handleRegenTemplate(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	bg := s.cfg.BgBlkTmplGenerator()
	if bg == nil {
		return nil, rpcInternalError("Node is not configured for mining", "")
	}
	bg.ForceRegen()
	return nil, nil
}

// retrievedTx represents a transaction that was either loaded from the
// transaction memory pool or from the database.  When a transaction is loaded
// from the database, it is loaded with the raw serialized bytes while the
// mempool has the fully deserialized structure.  This structure therefore will
// have one of the two fields set depending on where is was retrieved from.
// This is mainly done for efficiency to avoid extra serialization steps when
// possible.
type retrievedTx struct {
	txBytes  []byte
	blkHash  *chainhash.Hash // Only set when transaction is in a block.
	blkIndex uint32          // Only set when transaction is in a block.
	tx       *dcrutil.Tx
}

// fetchInputTxos fetches the outpoints from all transactions referenced by the
// inputs to the passed transaction by checking the transaction mempool first
// then the transaction index for those already mined into blocks.
func fetchInputTxos(s *rpcServer, tx *wire.MsgTx) (map[wire.OutPoint]wire.TxOut, error) {
	mp := s.cfg.TxMemPool
	originOutputs := make(map[wire.OutPoint]wire.TxOut)
	voteTx := stake.IsSSGen(tx)
	for txInIndex, txIn := range tx.TxIn {
		// vote tx have null input for vin[0],
		// skip since it resolves to an invalid transaction
		if voteTx && txInIndex == 0 {
			continue
		}
		// Attempt to fetch and use the referenced transaction from the
		// memory pool.
		origin := &txIn.PreviousOutPoint
		originTx, err := mp.FetchTransaction(&origin.Hash)
		if err == nil {
			txOuts := originTx.MsgTx().TxOut
			if origin.Index >= uint32(len(txOuts)) {
				errStr := fmt.Sprintf("unable to find output "+
					"%v referenced from transaction %s:%d",
					origin, tx.TxHash(), txInIndex)
				return nil, rpcInternalError(errStr, "")
			}

			originOutputs[*origin] = *txOuts[origin.Index]
			continue
		}

		txIndex := s.cfg.TxIndex

		// Ensure the tx index is synced.
		tHeight, tHash, err := txIndex.Tip()
		if err != nil {
			return nil, rpcInternalError(err.Error(), "")
		}

		chain := s.cfg.Chain
		if chain.BestSnapshot().Height > (tHeight + 5) {
			return nil, fmt.Errorf("%s: index not synced", txIndex.Name())
		}

		for !chain.BestSnapshot().Hash.IsEqual(tHash) {
			select {
			case <-time.After(syncWait):
				return nil, fmt.Errorf("%s: index not synced", txIndex.Name())
			case <-txIndex.WaitForSync():
			}
		}

		// Look up the location of the transaction.
		idxEntry, err := s.cfg.TxIndex.Entry(&origin.Hash)
		if err != nil {
			context := "Failed to retrieve transaction location"
			return nil, rpcInternalError(err.Error(), context)
		}
		if idxEntry == nil {
			return nil, rpcNoTxInfoError(&origin.Hash)
		}
		blockRegion := &idxEntry.BlockRegion

		// Load the raw transaction bytes from the database.
		var txBytes []byte
		err = s.cfg.DB.View(func(dbTx database.Tx) error {
			var err error
			txBytes, err = dbTx.FetchBlockRegion(blockRegion)
			return err
		})
		if err != nil {
			return nil, rpcNoTxInfoError(&origin.Hash)
		}

		// Deserialize the transaction
		var msgTx wire.MsgTx
		err = msgTx.Deserialize(bytes.NewReader(txBytes))
		if err != nil {
			context := "Failed to deserialize transaction"
			return nil, rpcInternalError(err.Error(), context)
		}

		// Add the referenced output to the map.
		if origin.Index >= uint32(len(msgTx.TxOut)) {
			errStr := fmt.Sprintf("unable to find output %v "+
				"referenced from transaction %s:%d", origin,
				tx.TxHash(), txInIndex)
			return nil, rpcInternalError(errStr, "")
		}
		originOutputs[*origin] = *msgTx.TxOut[origin.Index]
	}

	return originOutputs, nil
}

// createVinListPrevOut returns a slice of JSON objects for the inputs of the
// passed transaction.
func createVinListPrevOut(s *rpcServer, mtx *wire.MsgTx, chainParams *chaincfg.Params, vinExtra bool, filterAddrMap map[string]struct{}) ([]types.VinPrevOut, error) {
	// Coinbase transactions only have a single txin by definition.
	if standalone.IsCoinBaseTx(mtx) {
		// Only include the transaction if the filter map is empty
		// because a coinbase input has no addresses and so would never
		// match a non-empty filter.
		if len(filterAddrMap) != 0 {
			return nil, nil
		}

		txIn := mtx.TxIn[0]
		vinList := make([]types.VinPrevOut, 1)
		vinList[0].Coinbase = hex.EncodeToString(txIn.SignatureScript)
		amountIn := dcrutil.Amount(txIn.ValueIn).ToCoin()
		vinList[0].AmountIn = &amountIn
		vinList[0].Sequence = txIn.Sequence
		return vinList, nil
	}

	// Use a dynamically sized list to accommodate the address filter.
	vinList := make([]types.VinPrevOut, 0, len(mtx.TxIn))

	// Lookup all of the referenced transaction outputs needed to populate
	// the previous output information if requested.
	var originOutputs map[wire.OutPoint]wire.TxOut
	if vinExtra || len(filterAddrMap) > 0 {
		var err error
		originOutputs, err = fetchInputTxos(s, mtx)
		if err != nil {
			return nil, err
		}
	}

	// Stakebase transactions (votes) have two inputs: a null stake base
	// followed by an input consuming a ticket's stakesubmission.
	isSSGen := stake.IsSSGen(mtx)

	for i, txIn := range mtx.TxIn {
		// Handle only the null input of a stakebase differently.
		if isSSGen && i == 0 {
			amountIn := dcrutil.Amount(txIn.ValueIn).ToCoin()
			vinEntry := types.VinPrevOut{
				Stakebase: hex.EncodeToString(txIn.SignatureScript),
				AmountIn:  &amountIn,
				Sequence:  txIn.Sequence,
			}
			vinList = append(vinList, vinEntry)
			// No previous outpoints to check against the address filter.
			continue
		}

		// The disassembled string will contain [error] inline if the
		// script doesn't fully parse, so ignore the error here.
		disbuf, _ := txscript.DisasmString(txIn.SignatureScript)

		// Create the basic input entry without the additional optional
		// previous output details which will be added later if
		// requested and available.
		prevOut := &txIn.PreviousOutPoint
		amountIn := dcrutil.Amount(txIn.ValueIn).ToCoin()
		vinEntry := types.VinPrevOut{
			Txid:        prevOut.Hash.String(),
			Vout:        prevOut.Index,
			Tree:        prevOut.Tree,
			AmountIn:    &amountIn,
			BlockHeight: &txIn.BlockHeight,
			BlockIndex:  &txIn.BlockIndex,
			Sequence:    txIn.Sequence,
			ScriptSig: &types.ScriptSig{
				Asm: disbuf,
				Hex: hex.EncodeToString(txIn.SignatureScript),
			},
		}

		// Add the entry to the list now if it already passed the
		// filter since the previous output might not be available.
		passesFilter := len(filterAddrMap) == 0
		if passesFilter {
			vinList = append(vinList, vinEntry)
		}

		// Only populate previous output information if requested and
		// available.
		if len(originOutputs) == 0 {
			continue
		}
		originTxOut, ok := originOutputs[*prevOut]
		if !ok {
			continue
		}

		// Ignore the error here since an error means the script
		// couldn't parse and there is no additional information about
		// it anyways.
		_, addrs, _, _ := txscript.ExtractPkScriptAddrs(originTxOut.Version,
			originTxOut.PkScript, chainParams)

		// Encode the addresses while checking if the address passes
		// the filter when needed.
		encodedAddrs := make([]string, len(addrs))
		for j, addr := range addrs {
			encodedAddr := addr.Address()
			encodedAddrs[j] = encodedAddr

			// No need to check the map again if the filter already
			// passes.
			if passesFilter {
				continue
			}
			if _, exists := filterAddrMap[encodedAddr]; exists {
				passesFilter = true
			}
		}

		// Ignore the entry if it doesn't pass the filter.
		if !passesFilter {
			continue
		}

		// Add entry to the list if it wasn't already done above.
		if len(filterAddrMap) != 0 {
			vinList = append(vinList, vinEntry)
		}

		// Update the entry with previous output information if
		// requested.
		if vinExtra {
			vinListEntry := &vinList[len(vinList)-1]
			vinListEntry.PrevOut = &types.PrevOut{
				Addresses: encodedAddrs,
				Value:     dcrutil.Amount(originTxOut.Value).ToCoin(),
			}
		}
	}

	return vinList, nil
}

// fetchMempoolTxnsForAddress queries the address index for all unconfirmed
// transactions that involve the provided address.  The results will be limited
// by the number to skip and the number requested.
func fetchMempoolTxnsForAddress(s *rpcServer, addr dcrutil.Address, numToSkip, numRequested uint32) ([]*dcrutil.Tx, uint32) {
	// There are no entries to return when there are less available than
	// the number being skipped.
	mpTxns := s.cfg.AddrIndex.UnconfirmedTxnsForAddress(addr)
	numAvailable := uint32(len(mpTxns))
	if numToSkip > numAvailable {
		return nil, numAvailable
	}

	// Filter the available entries based on the number to skip and number
	// requested.
	rangeEnd := numToSkip + numRequested
	if rangeEnd > numAvailable {
		rangeEnd = numAvailable
	}
	return mpTxns[numToSkip:rangeEnd], numToSkip
}

// handleSearchRawTransactions implements the searchrawtransactions command.
func handleSearchRawTransactions(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	// Respond with an error if the address index is not enabled.
	addrIndex := s.cfg.AddrIndex
	if addrIndex == nil {
		return nil, rpcInternalError("Address index must be "+
			"enabled (--addrindex)", "Configuration")
	}

	// Override the flag for including extra previous output information in
	// each input if needed.
	c := cmd.(*types.SearchRawTransactionsCmd)
	vinExtra := false
	if c.VinExtra != nil {
		vinExtra = *c.VinExtra != 0
	}

	// Including the extra previous output information requires the
	// transaction index.  Currently the address index relies on the
	// transaction index, so this check is redundant, but it's better to be
	// safe in case the address index is ever changed to not rely on it.
	if vinExtra && s.cfg.TxIndex == nil {
		return nil, rpcInternalError("Transaction index must be "+
			"enabled (--txindex)", "Configuration")
	}

	// Attempt to decode the supplied address.  This also ensures the network
	// encoded with the address matches the network the server is currently on.
	addr, err := dcrutil.DecodeAddress(c.Address, s.cfg.ChainParams)
	if err != nil {
		return nil, rpcAddressKeyError("Could not decode address: %v",
			err)
	}

	// Override the default number of requested entries if needed.  Also,
	// just return now if the number of requested entries is zero to avoid
	// extra work.
	numRequested := 100
	if c.Count != nil {
		numRequested = *c.Count
		if numRequested < 0 {
			numRequested = 1
		}
	}
	if numRequested == 0 {
		return nil, nil
	}

	// Override the default number of entries to skip if needed.
	var numToSkip int
	if c.Skip != nil {
		numToSkip = *c.Skip
		if numToSkip < 0 {
			numToSkip = 0
		}
	}

	// Override the reverse flag if needed.
	var reverse bool
	if c.Reverse != nil {
		reverse = *c.Reverse
	}

	// Add transactions from mempool first if client asked for reverse
	// order.  Otherwise, they will be added last (as needed depending on
	// the requested counts).
	//
	// NOTE: This code doesn't sort by dependency.  This might be something
	// to do in the future for the client's convenience, or leave it to the
	// client.
	numSkipped := uint32(0)
	addressTxns := make([]retrievedTx, 0, numRequested)
	if reverse {
		// Transactions in the mempool are not in a block header yet,
		// so the block header and block index fields in the retrieved
		// transaction struct are left unset.
		mpTxns, mpSkipped := fetchMempoolTxnsForAddress(s, addr,
			uint32(numToSkip), uint32(numRequested))
		numSkipped += mpSkipped
		for _, tx := range mpTxns {
			addressTxns = append(addressTxns, retrievedTx{tx: tx})
		}
	}

	// Fetch transactions from the database in the desired order if more
	// are needed.
	if len(addressTxns) < numRequested {
		// Ensure the adddr index is synced.
		tHeight, tHash, err := addrIndex.Tip()
		if err != nil {
			return nil, rpcInternalError(err.Error(), "")
		}

		chain := s.cfg.Chain
		if chain.BestSnapshot().Height > (tHeight + 5) {
			return nil, fmt.Errorf("%s: index not synced", addrIndex.Name())
		}

		for !chain.BestSnapshot().Hash.IsEqual(tHash) {
			select {
			case <-time.After(syncWait):
				return nil, fmt.Errorf("%s: index not synced", addrIndex.Name())
			case <-addrIndex.WaitForSync():
			}
		}

		err = s.cfg.DB.View(func(dbTx database.Tx) error {
			idxEntries, dbSkipped, err := addrIndex.EntriesForAddress(
				dbTx, addr, uint32(numToSkip)-numSkipped,
				uint32(numRequested-len(addressTxns)), reverse)
			if err != nil {
				return err
			}
			regions := make([]database.BlockRegion, 0, len(idxEntries))
			for i := 0; i < len(idxEntries); i++ {
				entry := &idxEntries[i]
				regions = append(regions, entry.BlockRegion)
			}

			// Load the raw transaction bytes from the database.
			serializedTxns, err := dbTx.FetchBlockRegions(regions)
			if err != nil {
				return err
			}

			// Add the transaction and the hash of the block it is
			// contained in to the list.  Note that the transaction
			// is left serialized here since the caller might have
			// requested non-verbose output and hence there would
			// be no point in deserializing it just to reserialize
			// it later.
			//
			// TODO: Update txindex to provide block index.
			for i, serializedTx := range serializedTxns {
				addressTxns = append(addressTxns, retrievedTx{
					txBytes:  serializedTx,
					blkHash:  regions[i].Hash,
					blkIndex: idxEntries[i].BlockIndex,
				})
			}
			numSkipped += dbSkipped

			return nil
		})
		if err != nil {
			context := "Failed to load address index entries"
			return nil, rpcInternalError(err.Error(), context)
		}
	}

	// Add transactions from mempool last if client did not request reverse
	// order and the number of results is still under the number requested.
	if !reverse && len(addressTxns) < numRequested {
		// Transactions in the mempool are not in a block header yet,
		// so the block header field in the retrieved transaction
		// struct is left nil.
		mpTxns, mpSkipped := fetchMempoolTxnsForAddress(s, addr,
			uint32(numToSkip)-numSkipped, uint32(numRequested-
				len(addressTxns)))
		numSkipped += mpSkipped
		for _, tx := range mpTxns {
			addressTxns = append(addressTxns, retrievedTx{tx: tx})
		}
	}

	// Address has never been used if neither source yielded any results.
	if len(addressTxns) == 0 {
		return nil, rpcInternalError("No Txns available", "")
	}

	// Serialize all of the transactions to hex.
	hexTxns := make([]string, len(addressTxns))
	for i := range addressTxns {
		// Simply encode the raw bytes to hex when the retrieved
		// transaction is already in serialized form.
		rtx := &addressTxns[i]
		if rtx.txBytes != nil {
			hexTxns[i] = hex.EncodeToString(rtx.txBytes)
			continue
		}

		// Serialize the transaction first and convert to hex when the
		// retrieved transaction is the deserialized structure.
		hexTxns[i], err = messageToHex(rtx.tx.MsgTx())
		if err != nil {
			return nil, err
		}
	}

	// When not in verbose mode, simply return a list of serialized txns.
	if c.Verbose != nil && *c.Verbose == 0 {
		return hexTxns, nil
	}

	// Normalize the provided filter addresses (if any) to ensure there are
	// no duplicates.
	filterAddrMap := make(map[string]struct{})
	if c.FilterAddrs != nil && len(*c.FilterAddrs) > 0 {
		for _, addr := range *c.FilterAddrs {
			filterAddrMap[addr] = struct{}{}
		}
	}

	// The verbose flag is set, so generate the JSON object and return it.
	best := s.cfg.Chain.BestSnapshot()
	chainParams := s.cfg.ChainParams
	srtList := make([]types.SearchRawTransactionsResult, len(addressTxns))
	for i := range addressTxns {
		// The deserialized transaction is needed, so deserialize the
		// retrieved transaction if it's in serialized form (which will
		// be the case when it was lookup up from the database).
		// Otherwise, use the existing deserialized transaction.
		rtx := &addressTxns[i]
		var mtx *wire.MsgTx
		if rtx.tx == nil {
			// Deserialize the transaction.
			mtx = new(wire.MsgTx)
			err := mtx.Deserialize(bytes.NewReader(rtx.txBytes))
			if err != nil {
				context := "Failed to deserialize transaction"
				return nil, rpcInternalError(err.Error(),
					context)
			}
		} else {
			mtx = rtx.tx.MsgTx()
		}

		result := &srtList[i]
		result.Hex = hexTxns[i]
		result.Txid = mtx.TxHash().String()
		result.Vin, err = createVinListPrevOut(s, mtx, s.cfg.ChainParams,
			vinExtra, filterAddrMap)
		if err != nil {
			return nil, rpcInternalError(err.Error(),
				"Could not create vin list")
		}
		result.Vout = createVoutList(mtx, chainParams, filterAddrMap)
		result.Version = int32(mtx.Version)
		result.LockTime = mtx.LockTime
		result.Expiry = mtx.Expiry

		// Transactions grabbed from the mempool aren't yet in a block,
		// so conditionally fetch block details here.  This will be
		// reflected in the final JSON output (mempool won't have
		// confirmations or block information).
		var blkHeader *wire.BlockHeader
		var blkHashStr string
		var blkHeight int64
		var blkIndex uint32
		if blkHash := rtx.blkHash; blkHash != nil {
			// Fetch the header from chain.
			header, err := s.cfg.Chain.HeaderByHash(blkHash)
			if err != nil {
				return nil, &dcrjson.RPCError{
					Code:    dcrjson.ErrRPCBlockNotFound,
					Message: "Block not found",
				}
			}

			// Get the block height from chain.
			height, err := s.cfg.Chain.BlockHeightByHash(blkHash)
			if err != nil {
				context := "Failed to obtain block height"
				return nil, rpcInternalError(err.Error(), context)
			}

			blkHeader = &header
			blkHashStr = blkHash.String()
			blkHeight = height
			blkIndex = rtx.blkIndex
		}

		// Add the block information to the result if there is any.
		if blkHeader != nil {
			// This is not a typo, they are identical in Bitcoin
			// Core as well.
			result.Time = blkHeader.Timestamp.Unix()
			result.Blocktime = blkHeader.Timestamp.Unix()
			result.BlockHash = blkHashStr
			result.BlockHeight = blkHeight
			result.BlockIndex = blkIndex
			result.Confirmations = uint64(1 + best.Height - blkHeight)
		}
	}

	return srtList, nil
}

// handleSendRawTransaction implements the sendrawtransaction command.
func handleSendRawTransaction(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.SendRawTransactionCmd)
	// Deserialize and send off to tx relay

	allowHighFees := *c.AllowHighFees
	hexStr := c.HexTx
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}
	serializedTx, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, rpcDecodeHexError(hexStr)
	}
	msgtx := wire.NewMsgTx()
	err = msgtx.Deserialize(bytes.NewReader(serializedTx))
	if err != nil {
		return nil, rpcDeserializationError("Could not decode Tx: %v",
			err)
	}

	// Use 0 for the tag to represent local node.
	tx := dcrutil.NewTx(msgtx)
	acceptedTxs, err := s.cfg.SyncMgr.ProcessTransaction(tx, false,
		false, allowHighFees, 0)
	if err != nil {
		// When the error is a rule error, it means the transaction was
		// simply rejected as opposed to something actually going
		// wrong, so log it as such.  Otherwise, something really did
		// go wrong, so log it as an actual error.  In both cases, a
		// JSON-RPC error is returned to the client with the
		// deserialization error code (to match bitcoind behavior).
		var rErr mempool.RuleError
		if errors.As(err, &rErr) {
			err = fmt.Errorf("rejected transaction %v: %v", tx.Hash(),
				err)
			rpcsLog.Debugf("%v", err)
			if mempool.IsErrorCode(rErr, mempool.ErrDuplicate) {
				// This is an actual exact duplicate tx, so
				// return the specific duplicate tx error.
				return nil, rpcDuplicateTxError("%v", err)
			}

			// return a generic rule error
			return nil, rpcRuleError("%v", err)
		}

		err = fmt.Errorf("failed to process transaction %v: %v",
			tx.Hash(), err)
		rpcsLog.Errorf("%v", err)
		return nil, rpcDeserializationError("rejected: %v", err)
	}

	s.cfg.PeerNotifier.AnnounceNewTransactions(acceptedTxs)

	// Keep track of all the regular sendrawtransaction request txns so that
	// they can be rebroadcast if they don't make their way into a block.
	//
	// Note that votes are only valid for a specific block and are time
	// sensitive, so they should not be added to the rebroadcast logic.
	if txType := stake.DetermineTxType(msgtx); txType != stake.TxTypeSSGen {
		iv := wire.NewInvVect(wire.InvTypeTx, tx.Hash())
		s.cfg.ConnMgr.AddRebroadcastInventory(iv, tx)
	}

	return tx.Hash().String(), nil
}

// handleSetGenerate implements the setgenerate command.
func handleSetGenerate(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.SetGenerateCmd)

	// Disable generation regardless of the provided generate flag if the
	// maximum number of threads (goroutines for our purposes) is 0.
	// Otherwise enable or disable it depending on the provided flag.
	generate := c.Generate
	genProcLimit := -1
	if c.GenProcLimit != nil {
		genProcLimit = *c.GenProcLimit
	}
	if genProcLimit == 0 {
		generate = false
	}

	if !generate {
		s.cfg.CPUMiner.Stop()
	} else {
		// Respond with an error if there are no addresses to pay the
		// created blocks to.
		if len(cfg.miningAddrs) == 0 {
			return nil, rpcInternalError("No payment addresses "+
				"specified via --miningaddr", "Configuration")
		}

		// It's safe to call start even if it's already started.
		s.cfg.CPUMiner.SetNumWorkers(int32(genProcLimit))
		s.cfg.CPUMiner.Start()
	}
	return nil, nil
}

// handleStop implements the stop command.
func handleStop(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	select {
	case s.requestProcessShutdown <- struct{}{}:
	default:
	}
	return "dcrd stopping.", nil
}

// handleSubmitBlock implements the submitblock command.
func handleSubmitBlock(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.SubmitBlockCmd)

	// Deserialize the submitted block.
	hexStr := c.HexBlock
	if len(hexStr)%2 != 0 {
		hexStr = "0" + c.HexBlock
	}
	serializedBlock, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, rpcInternalError(err.Error(), "Block decode")
	}

	block, err := dcrutil.NewBlockFromBytes(serializedBlock)
	if err != nil {
		return nil, rpcInternalError(err.Error(), "Block decode")
	}

	_, err = s.cfg.SyncMgr.SubmitBlock(block, blockchain.BFNone)
	if err != nil {
		return fmt.Sprintf("rejected: %v", err), nil
	}

	rpcsLog.Infof("Accepted block %s via submitblock", block.Hash())
	return nil, nil
}

// min gets the minimum amount from a slice of amounts.
func min(s []dcrutil.Amount) dcrutil.Amount {
	if len(s) == 0 {
		return 0
	}

	min := s[0]
	for i := range s {
		if s[i] < min {
			min = s[i]
		}
	}

	return min
}

// max gets the maximum amount from a slice of amounts.
func max(s []dcrutil.Amount) dcrutil.Amount {
	max := dcrutil.Amount(0)
	for i := range s {
		if s[i] > max {
			max = s[i]
		}
	}

	return max
}

// mean gets the mean amount from a slice of amounts.
func mean(s []dcrutil.Amount) dcrutil.Amount {
	sum := dcrutil.Amount(0)
	for i := range s {
		sum += s[i]
	}

	if len(s) == 0 {
		return 0
	}

	return sum / dcrutil.Amount(len(s))
}

// median gets the median amount from a slice of amounts.
func median(s []dcrutil.Amount) dcrutil.Amount {
	if len(s) == 0 {
		return 0
	}

	sort.Sort(dcrutil.AmountSorter(s))

	middle := len(s) / 2

	if len(s) == 0 {
		return 0
	} else if (len(s) % 2) != 0 {
		return s[middle]
	}
	return (s[middle] + s[middle-1]) / 2
}

// stdDev gets the standard deviation amount from a slice of amounts.
func stdDev(s []dcrutil.Amount) dcrutil.Amount {
	var total float64
	mean := mean(s)

	for i := range s {
		total += math.Pow(s[i].ToCoin()-mean.ToCoin(), 2)
	}
	if len(s)-1 == 0 {
		return 0
	}
	v := total / float64(len(s)-1)

	// Not concerned with an error here, it'll return
	// zero if the amount is too small.
	amt, _ := dcrutil.NewAmount(math.Sqrt(v))

	return amt
}

// feeInfoForMempool returns the fee information for the passed tx type in the
// memory pool.
func feeInfoForMempool(s *rpcServer, txType stake.TxType) *types.FeeInfoMempool {
	txDs := s.cfg.TxMemPool.TxDescs()
	ticketFees := make([]dcrutil.Amount, 0, len(txDs))
	for _, txD := range txDs {
		if txD.Type == txType {
			feePerKb := (dcrutil.Amount(txD.Fee)) * 1000 /
				dcrutil.Amount(txD.Tx.MsgTx().SerializeSize())
			ticketFees = append(ticketFees, feePerKb)
		}
	}

	return &types.FeeInfoMempool{
		Number: uint32(len(ticketFees)),
		Min:    min(ticketFees).ToCoin(),
		Max:    max(ticketFees).ToCoin(),
		Mean:   mean(ticketFees).ToCoin(),
		Median: median(ticketFees).ToCoin(),
		StdDev: stdDev(ticketFees).ToCoin(),
	}
}

// calcFee calculates the fee of a transaction that has its fraud proofs
// properly set.
func calcFeePerKb(tx *dcrutil.Tx) dcrutil.Amount {
	var in dcrutil.Amount
	for _, txIn := range tx.MsgTx().TxIn {
		in += dcrutil.Amount(txIn.ValueIn)
	}
	var out dcrutil.Amount
	for _, txOut := range tx.MsgTx().TxOut {
		out += dcrutil.Amount(txOut.Value)
	}

	return ((in - out) * 1000) / dcrutil.Amount(tx.MsgTx().SerializeSize())
}

// feeInfoForBlock fetches the ticket fee information for a given tx type in a
// block.
func ticketFeeInfoForBlock(s *rpcServer, height int64, txType stake.TxType) (*types.FeeInfoBlock, error) {
	bl, err := s.cfg.Chain.BlockByHeight(height)
	if err != nil {
		return nil, err
	}

	txNum := 0
	switch txType {
	case stake.TxTypeRegular:
		txNum = len(bl.MsgBlock().Transactions) - 1
	case stake.TxTypeSStx:
		txNum = int(bl.MsgBlock().Header.FreshStake)
	case stake.TxTypeSSGen:
		txNum = int(bl.MsgBlock().Header.Voters)
	case stake.TxTypeSSRtx:
		txNum = int(bl.MsgBlock().Header.Revocations)
	}

	txFees := make([]dcrutil.Amount, txNum)
	itr := 0
	if txType == stake.TxTypeRegular {
		for i, tx := range bl.Transactions() {
			// Skip the coin base.
			if i == 0 {
				continue
			}

			txFees[itr] = calcFeePerKb(tx)
			itr++
		}
	} else {
		for _, stx := range bl.STransactions() {
			thisTxType := stake.DetermineTxType(stx.MsgTx())
			if thisTxType == txType {
				txFees[itr] = calcFeePerKb(stx)
				itr++
			}
		}
	}

	return &types.FeeInfoBlock{
		Height: uint32(height),
		Number: uint32(txNum),
		Min:    min(txFees).ToCoin(),
		Max:    max(txFees).ToCoin(),
		Mean:   mean(txFees).ToCoin(),
		Median: median(txFees).ToCoin(),
		StdDev: stdDev(txFees).ToCoin(),
	}, nil
}

// ticketFeeInfoForRange fetches the ticket fee information for a given range
// from [start, end).
func ticketFeeInfoForRange(s *rpcServer, start int64, end int64, txType stake.TxType) (*types.FeeInfoWindow, error) {
	hashes, err := s.cfg.Chain.HeightRange(start, end)
	if err != nil {
		return nil, err
	}

	var txFees []dcrutil.Amount
	for i := range hashes {
		bl, err := s.cfg.Chain.BlockByHash(&hashes[i])
		if err != nil {
			return nil, err
		}

		if txType == stake.TxTypeRegular {
			for i, tx := range bl.Transactions() {
				// Skip the coin base.
				if i == 0 {
					continue
				}

				txFees = append(txFees, calcFeePerKb(tx))
			}
		} else {
			for _, stx := range bl.STransactions() {
				thisTxType := stake.DetermineTxType(stx.MsgTx())
				if thisTxType == txType {
					txFees = append(txFees, calcFeePerKb(stx))
				}
			}
		}
	}

	return &types.FeeInfoWindow{
		StartHeight: uint32(start),
		EndHeight:   uint32(end),
		Number:      uint32(len(txFees)),
		Min:         min(txFees).ToCoin(),
		Max:         max(txFees).ToCoin(),
		Mean:        mean(txFees).ToCoin(),
		Median:      median(txFees).ToCoin(),
		StdDev:      stdDev(txFees).ToCoin(),
	}, nil
}

// handleTicketFeeInfo implements the ticketfeeinfo command.
func handleTicketFeeInfo(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.TicketFeeInfoCmd)

	bestHeight := s.cfg.Chain.BestSnapshot().Height

	// Memory pool first.
	feeInfoMempool := feeInfoForMempool(s, stake.TxTypeSStx)

	// Blocks requested, descending from the chain tip.
	var feeInfoBlocks []types.FeeInfoBlock
	blocks := uint32(0)
	if c.Blocks != nil {
		blocks = *c.Blocks
	}
	if blocks > 0 {
		start := bestHeight
		end := bestHeight - int64(blocks)

		for i := start; i > end; i-- {
			feeInfo, err := ticketFeeInfoForBlock(s, i, stake.TxTypeSStx)
			if err != nil {
				return nil, rpcInternalError(err.Error(),
					"Could not obtain ticket fee info")
			}
			feeInfoBlocks = append(feeInfoBlocks, *feeInfo)
		}
	}

	var feeInfoWindows []types.FeeInfoWindow
	windows := uint32(0)
	if c.Windows != nil {
		windows = *c.Windows
	}
	if windows > 0 {
		// The first window is special because it may not be finished.
		// Perform this first and return if it's the only window the
		// user wants. Otherwise, append and continue.
		winLen := s.cfg.ChainParams.StakeDiffWindowSize
		lastChange := (bestHeight / winLen) * winLen

		feeInfo, err := ticketFeeInfoForRange(s, lastChange, bestHeight+1,
			stake.TxTypeSStx)
		if err != nil {
			return nil, rpcInternalError(err.Error(),
				"Could not obtain ticket fee info")
		}
		feeInfoWindows = append(feeInfoWindows, *feeInfo)

		// We need data on windows from before this. Start from
		// the last adjustment and move backwards through window
		// lengths, calculating the fees data and appending it
		// each time.
		if windows > 1 {
			// Go down to the last height requested, except
			// in the case that the user has specified to
			// many windows. In that case, just proceed to the
			// first block.
			end := int64(-1)
			if lastChange-int64(windows)*winLen > end {
				end = lastChange - int64(windows)*winLen
			}
			for i := lastChange; i > end+winLen; i -= winLen {
				feeInfo, err := ticketFeeInfoForRange(s, i-winLen, i,
					stake.TxTypeSStx)
				if err != nil {
					return nil, rpcInternalError(err.Error(),
						"Could not obtain ticket fee info")
				}
				feeInfoWindows = append(feeInfoWindows, *feeInfo)
			}
		}
	}

	return &types.TicketFeeInfoResult{
		FeeInfoMempool: *feeInfoMempool,
		FeeInfoBlocks:  feeInfoBlocks,
		FeeInfoWindows: feeInfoWindows,
	}, nil
}

// handleTicketsForAddress implements the ticketsforaddress command.
func handleTicketsForAddress(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.TicketsForAddressCmd)

	// Decode the provided address.  This also ensures the network encoded
	// with the address matches the network the server is currently on.
	addr, err := dcrutil.DecodeAddress(c.Address, s.cfg.ChainParams)
	if err != nil {
		return nil, rpcInvalidError("Invalid address: %v", err)
	}

	tickets, err := s.cfg.Chain.TicketsWithAddress(addr)
	if err != nil {
		return nil, rpcInternalError(err.Error(), "could not obtain tickets")
	}

	ticketStrings := make([]string, len(tickets))
	itr := 0
	for _, ticket := range tickets {
		ticketStrings[itr] = ticket.String()
		itr++
	}

	reply := &types.TicketsForAddressResult{
		Tickets: ticketStrings,
	}
	return reply, nil
}

// handleTicketVWAP implements the ticketvwap command.
func handleTicketVWAP(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.TicketVWAPCmd)

	// The default VWAP is for the past WorkDiffWindows * WorkDiffWindowSize
	// many blocks.
	bestHeight := s.cfg.Chain.BestSnapshot().Height
	var start uint32
	if c.Start == nil {
		params := s.cfg.ChainParams
		toEval := params.WorkDiffWindows * params.WorkDiffWindowSize
		startI64 := bestHeight - toEval

		// Use 1 as the first block if there aren't enough blocks.
		if startI64 <= 0 {
			start = 1
		} else {
			start = uint32(startI64)
		}
	} else {
		start = *c.Start
	}

	end := uint32(bestHeight)
	if c.End != nil {
		end = *c.End
	}
	if start > end {
		return nil, rpcInvalidError("Start height %v is beyond end "+
			"height %v", start, end)
	}
	if end > uint32(bestHeight) {
		return nil, rpcInvalidError("End height %v is beyond "+
			"blockchain tip height %v", end, bestHeight)
	}

	// Calculate the volume weighted average price of a ticket for the
	// given range.
	ticketNum := int64(0)
	totalValue := int64(0)
	for i := start; i <= end; i++ {
		blockHeader, err := s.cfg.Chain.HeaderByHeight(int64(i))
		if err != nil {
			return nil, rpcInternalError(err.Error(),
				"Could not obtain header")
		}

		ticketNum += int64(blockHeader.FreshStake)
		totalValue += blockHeader.SBits * int64(blockHeader.FreshStake)
	}
	vwap := int64(0)
	if ticketNum > 0 {
		vwap = totalValue / ticketNum
	}

	return dcrutil.Amount(vwap).ToCoin(), nil
}

// handleTxFeeInfo implements the txfeeinfo command.
func handleTxFeeInfo(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.TxFeeInfoCmd)

	bestHeight := s.cfg.Chain.BestSnapshot().Height

	// Memory pool first.
	feeInfoMempool := feeInfoForMempool(s, stake.TxTypeRegular)

	// Blocks requested, descending from the chain tip.
	var feeInfoBlocks []types.FeeInfoBlock
	blocks := uint32(0)
	if c.Blocks != nil {
		blocks = *c.Blocks
	}
	if blocks > 0 {
		start := bestHeight
		end := bestHeight - int64(blocks)

		for i := start; i > end; i-- {
			feeInfo, err := ticketFeeInfoForBlock(s, i,
				stake.TxTypeRegular)
			if err != nil {
				return nil, rpcInternalError(err.Error(),
					"Could not obtain ticket fee info")
			}
			feeInfoBlocks = append(feeInfoBlocks, *feeInfo)
		}
	}

	// Get the fee info for the range requested, unless none is given.  The
	// default range is for the past WorkDiffWindowSize many blocks.
	var feeInfoRange types.FeeInfoRange

	var start uint32
	if c.RangeStart == nil {
		toEval := s.cfg.ChainParams.WorkDiffWindowSize
		startI64 := bestHeight - toEval

		// Use 1 as the first block if there aren't enough blocks.
		if startI64 <= 0 {
			start = 1
		} else {
			start = uint32(startI64)
		}
	} else {
		start = *c.RangeStart
	}

	end := uint32(bestHeight)
	if c.RangeEnd != nil {
		end = *c.RangeEnd
	}
	if start > end {
		return nil, rpcInvalidError("Start height %v is beyond end "+
			"height %v", start, end)
	}
	if end > uint32(bestHeight) {
		return nil, rpcInvalidError("End height %v is beyond "+
			"blockchain tip height %v", end, bestHeight)
	}

	feeInfo, err := ticketFeeInfoForRange(s, int64(start), int64(end+1),
		stake.TxTypeRegular)
	if err != nil {
		return nil, rpcInternalError(err.Error(),
			"Could not obtain ticket fee info")
	}

	feeInfoRange = types.FeeInfoRange{
		Number: feeInfo.Number,
		Min:    feeInfo.Min,
		Max:    feeInfo.Max,
		Mean:   feeInfo.Mean,
		Median: feeInfo.Median,
		StdDev: feeInfo.StdDev,
	}

	return &types.TxFeeInfoResult{
		FeeInfoMempool: *feeInfoMempool,
		FeeInfoBlocks:  feeInfoBlocks,
		FeeInfoRange:   feeInfoRange,
	}, nil
}

// handleValidateAddress implements the validateaddress command.
func handleValidateAddress(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.ValidateAddressCmd)
	result := types.ValidateAddressChainResult{}
	addr, err := dcrutil.DecodeAddress(c.Address, s.cfg.ChainParams)
	if err != nil {
		// Return the default value (false) for IsValid.
		return result, nil
	}

	result.Address = addr.Address()
	result.IsValid = true
	return result, nil
}

func verifyChain(_ context.Context, s *rpcServer, level, depth int64) error {
	best := s.cfg.Chain.BestSnapshot()
	finishHeight := best.Height - depth
	if finishHeight < 0 {
		finishHeight = 0
	}
	rpcsLog.Infof("Verifying chain for %d blocks at level %d",
		best.Height-finishHeight, level)

	for height := best.Height; height > finishHeight; height-- {
		// Level 0 just looks up the block.
		block, err := s.cfg.Chain.BlockByHeight(height)
		if err != nil {
			rpcsLog.Errorf("Verify is unable to fetch block at "+
				"height %d: %v", height, err)
			return err
		}

		// Level 1 does basic chain sanity checks.
		if level > 0 {
			err := blockchain.CheckBlockSanity(block, s.cfg.TimeSource,
				s.cfg.ChainParams)
			if err != nil {
				rpcsLog.Errorf("Verify is unable to validate "+
					"block at hash %v height %d: %v",
					block.Hash(), height, err)
				return err
			}
		}
	}
	rpcsLog.Infof("Chain verify completed successfully")

	return nil
}

// handleVerifyChain implements the verifychain command.
func handleVerifyChain(ctx context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.VerifyChainCmd)

	var checkLevel, checkDepth int64
	if c.CheckLevel != nil {
		checkLevel = *c.CheckLevel
	}
	if c.CheckDepth != nil {
		checkDepth = *c.CheckDepth
	}

	err := verifyChain(ctx, s, checkLevel, checkDepth)
	return err == nil, nil
}

// handleVerifyMessage implements the verifymessage command.
func handleVerifyMessage(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	c := cmd.(*types.VerifyMessageCmd)

	// Decode the provided address.  This also ensures the network encoded with
	// the address matches the network the server is currently on.
	addr, err := dcrutil.DecodeAddress(c.Address, s.cfg.ChainParams)
	if err != nil {
		return nil, rpcAddressKeyError("Could not decode address: %v",
			err)
	}

	// Only P2PKH addresses are valid for signing.
	if _, ok := addr.(*dcrutil.AddressPubKeyHash); !ok {
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCType,
			Message: "Address is not a pay-to-pubkey-hash address",
		}
	}

	// Decode base64 signature.
	sig, err := base64.StdEncoding.DecodeString(c.Signature)
	if err != nil {
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCParse.Code,
			Message: "Malformed base64 encoding: " + err.Error(),
		}
	}

	// Validate the signature - this just shows that it was valid at all.
	// we will compare it with the key next.
	var buf bytes.Buffer
	wire.WriteVarString(&buf, 0, "Decred Signed Message:\n")
	wire.WriteVarString(&buf, 0, c.Message)
	expectedMessageHash := chainhash.HashB(buf.Bytes())
	pk, wasCompressed, err := ecdsa.RecoverCompact(sig,
		expectedMessageHash)
	if err != nil {
		// Mirror Bitcoin Core behavior, which treats error in
		// RecoverCompact as invalid signature.
		return false, nil
	}

	// Reconstruct the pubkey hash.
	dcrPK := pk
	var serializedPK []byte
	if wasCompressed {
		serializedPK = dcrPK.SerializeCompressed()
	} else {
		serializedPK = dcrPK.SerializeUncompressed()
	}
	address, err := dcrutil.NewAddressSecpPubKey(serializedPK,
		s.cfg.ChainParams)
	if err != nil {
		// Again mirror Bitcoin Core behavior, which treats error in
		// public key reconstruction as invalid signature.
		return false, nil
	}

	// Return boolean if addresses match.
	return address.Address() == c.Address, nil
}

// handleVersion implements the version command.
func handleVersion(_ context.Context, s *rpcServer, cmd interface{}) (interface{}, error) {
	runtimeVer := strings.Replace(runtime.Version(), ".", "-", -1)
	buildMeta := version.NormalizeBuildString(runtimeVer)
	build := version.NormalizeBuildString(version.BuildMetadata)
	if build != "" {
		buildMeta = fmt.Sprintf("%s.%s", build, buildMeta)
	}
	result := map[string]types.VersionResult{
		"dcrdjsonrpcapi": {
			VersionString: jsonrpcSemverString,
			Major:         jsonrpcSemverMajor,
			Minor:         jsonrpcSemverMinor,
			Patch:         jsonrpcSemverPatch,
		},
		"dcrd": {
			VersionString: version.String(),
			Major:         uint32(version.Major),
			Minor:         uint32(version.Minor),
			Patch:         uint32(version.Patch),
			Prerelease:    version.NormalizePreRelString(version.PreRelease),
			BuildMetadata: buildMeta,
		},
	}
	return result, nil
}

// rpcServer provides a concurrent safe RPC server to a chain server.
type rpcServer struct {
	cfg                    rpcserverConfig
	authsha                [sha256.Size]byte
	limitauthsha           [sha256.Size]byte
	ntfnMgr                *wsNotificationManager
	numClients             int32
	statusLines            map[int]string
	statusLock             sync.RWMutex
	wg                     sync.WaitGroup
	workState              *workState
	helpCacher             *helpCacher
	requestProcessShutdown chan struct{}
}

// httpStatusLine returns a response Status-Line (RFC 2616 Section 6.1) for the
// given request and response status code.  This function was lifted and
// adapted from the standard library HTTP server code since it's not exported.
func (s *rpcServer) httpStatusLine(req *http.Request, code int) string {
	// Fast path:
	key := code
	proto11 := req.ProtoAtLeast(1, 1)
	if !proto11 {
		key = -key
	}
	s.statusLock.RLock()
	line, ok := s.statusLines[key]
	s.statusLock.RUnlock()
	if ok {
		return line
	}

	// Slow path:
	proto := "HTTP/1.0"
	if proto11 {
		proto = "HTTP/1.1"
	}
	codeStr := strconv.Itoa(code)
	text := http.StatusText(code)
	if text != "" {
		line = proto + " " + codeStr + " " + text + "\r\n"
		s.statusLock.Lock()
		s.statusLines[key] = line
		s.statusLock.Unlock()
	} else {
		text = "status code " + codeStr
		line = proto + " " + codeStr + " " + text + "\r\n"
	}

	return line
}

// writeHTTPResponseHeaders writes the necessary response headers prior to
// writing an HTTP body given a request to use for protocol negotiation,
// headers to write, a status code, and a writer.
func (s *rpcServer) writeHTTPResponseHeaders(req *http.Request, headers http.Header, code int, w io.Writer) error {
	_, err := io.WriteString(w, s.httpStatusLine(req, code))
	if err != nil {
		return err
	}

	err = headers.Write(w)
	if err != nil {
		return err
	}

	_, err = io.WriteString(w, "\r\n")
	return err
}

// shutdown terminates the processes of the rpc server.
func (s *rpcServer) shutdown() error {
	rpcsLog.Warnf("RPC server shutting down")
	for _, listener := range s.cfg.Listeners {
		err := listener.Close()
		if err != nil {
			rpcsLog.Errorf("Problem shutting down rpc: %v", err)
			return err
		}
	}
	s.wg.Wait()
	rpcsLog.Infof("RPC server shutdown complete")
	return nil
}

// RequestedProcessShutdown returns a channel that is sent to when an
// authorized RPC client requests the process to shutdown.  If the request can
// not be read immediately, it is dropped.
func (s *rpcServer) RequestedProcessShutdown() <-chan struct{} {
	return s.requestProcessShutdown
}

// NotifyNewTransactions notifies both websocket and getblocktemplate long
// poll clients of the passed transactions.  This function should be called
// whenever new transactions are added to the mempool.
func (s *rpcServer) NotifyNewTransactions(txns []*dcrutil.Tx) {
	for _, tx := range txns {
		// Notify websocket clients about mempool transactions.
		s.ntfnMgr.NotifyMempoolTx(tx, true)
	}
}

// limitConnections responds with a 503 service unavailable and returns true if
// adding another client would exceed the maximum allow RPC clients.
//
// This function is safe for concurrent access.
func (s *rpcServer) limitConnections(w http.ResponseWriter, remoteAddr string) bool {
	if int(atomic.LoadInt32(&s.numClients)+1) > cfg.RPCMaxClients {
		rpcsLog.Infof("Max RPC clients exceeded [%d] - "+
			"disconnecting client %s", cfg.RPCMaxClients,
			remoteAddr)
		http.Error(w, "503 Too busy.  Try again later.",
			http.StatusServiceUnavailable)
		return true
	}
	return false
}

// incrementClients adds one to the number of connected RPC clients.  Note this
// only applies to standard clients.  Websocket clients have their own limits
// and are tracked separately.
//
// This function is safe for concurrent access.
func (s *rpcServer) incrementClients() {
	atomic.AddInt32(&s.numClients, 1)
}

// decrementClients subtracts one from the number of connected RPC clients.
// Note this only applies to standard clients.  Websocket clients have their
// own limits and are tracked separately.
//
// This function is safe for concurrent access.
func (s *rpcServer) decrementClients() {
	atomic.AddInt32(&s.numClients, -1)
}

// checkAuth checks the HTTP Basic authentication supplied by a wallet or RPC
// client in the HTTP request r.  If the supplied authentication does not match
// the username and password expected, a non-nil error is returned.
//
// This check is time-constant.
//
// The first bool return value signifies auth success (true if successful) and
// the second bool return value specifies whether the user can change the state
// of the server (true) or whether the user is limited (false). The second is
// always false if the first is.
func (s *rpcServer) checkAuth(r *http.Request, require bool) (bool, bool, error) {
	authhdr := r.Header["Authorization"]
	if len(authhdr) <= 0 {
		if require {
			rpcsLog.Warnf("RPC authentication failure from %s",
				r.RemoteAddr)
			return false, false, errors.New("auth failure")
		}

		return false, false, nil
	}

	authsha := sha256.Sum256([]byte(authhdr[0]))

	// Check for limited auth first as in environments with limited users,
	// those are probably expected to have a higher volume of calls
	limitcmp := subtle.ConstantTimeCompare(authsha[:], s.limitauthsha[:])
	if limitcmp == 1 {
		return true, false, nil
	}

	// Check for admin-level auth
	cmp := subtle.ConstantTimeCompare(authsha[:], s.authsha[:])
	if cmp == 1 {
		return true, true, nil
	}

	// Request's auth doesn't match either user
	rpcsLog.Warnf("RPC authentication failure from %s", r.RemoteAddr)
	return false, false, errors.New("auth failure")
}

// parsedRPCCmd represents a JSON-RPC request object that has been parsed into
// a known concrete command along with any error that might have happened while
// parsing it.
type parsedRPCCmd struct {
	jsonrpc string
	id      interface{}
	method  types.Method
	params  interface{}
	err     *dcrjson.RPCError
}

// standardCmdResult checks that a parsed command is a standard Bitcoin
// JSON-RPC command and runs the appropriate handler to reply to the command.
// Any commands which are not recognized or not implemented will return an
// error suitable for use in replies.
func (s *rpcServer) standardCmdResult(ctx context.Context, cmd *parsedRPCCmd) (interface{}, error) {
	handler, ok := rpcHandlers[cmd.method]
	if ok {
		goto handled
	}
	_, ok = rpcAskWallet[string(cmd.method)]
	if ok {
		handler = handleAskWallet
		goto handled
	}
	_, ok = rpcUnimplemented[string(cmd.method)]
	if ok {
		handler = handleUnimplemented
		goto handled
	}
	return nil, dcrjson.ErrRPCMethodNotFound
handled:
	return handler(ctx, s, cmd.params)
}

// parseCmd parses a JSON-RPC request object into known concrete command.  The
// err field of the returned parsedRPCCmd struct will contain an RPC error that
// is suitable for use in replies if the command is invalid in some way such as
// an unregistered command or invalid parameters.
func parseCmd(request *dcrjson.Request) *parsedRPCCmd {
	parsedCmd := parsedRPCCmd{
		jsonrpc: request.Jsonrpc,
		id:      request.ID,
		method:  types.Method(request.Method),
	}

	params, err := dcrjson.ParseParams(types.Method(request.Method), request.Params)
	if err != nil {
		// When the error is because the method is not registered,
		// produce a method not found RPC error.
		var jerr dcrjson.Error
		if errors.As(err, &jerr) &&
			jerr.Code == dcrjson.ErrUnregisteredMethod {
			parsedCmd.err = dcrjson.ErrRPCMethodNotFound
			return &parsedCmd
		}

		// Otherwise, some type of invalid parameters is the cause, so
		// produce the equivalent RPC error.
		parsedCmd.err = rpcInvalidError("Failed to parse request: %v", err)
		return &parsedCmd
	}

	parsedCmd.params = params
	return &parsedCmd
}

// createMarshalledReply returns a new marshalled JSON-RPC response given the
// passed parameters.  It will automatically convert errors that are not of the
// type *dcrjson.RPCError to the appropriate type as needed.
func createMarshalledReply(rpcVersion string, id interface{}, result interface{}, replyErr error) ([]byte, error) {
	var jsonErr *dcrjson.RPCError
	if replyErr != nil && !errors.As(replyErr, &jsonErr) {
		jsonErr = rpcInternalError(replyErr.Error(), "")
	}

	return dcrjson.MarshalResponse(rpcVersion, id, result, jsonErr)
}

// processRequest determines the incoming request type (single or batched),
// parses it and returns a marshalled response.
func (s *rpcServer) processRequest(ctx context.Context, request *dcrjson.Request, isAdmin bool) []byte {
	var result interface{}
	var jsonErr error

	if !isAdmin {
		if _, ok := rpcLimited[request.Method]; !ok {
			jsonErr = rpcInvalidError("limited user not " +
				"authorized for this method")
		}
	}

	if jsonErr == nil {
		if request.Method == "" {
			jsonErr = &dcrjson.RPCError{
				Code:    dcrjson.ErrRPCInvalidRequest.Code,
				Message: "Invalid request: malformed",
			}
			msg, err := createMarshalledReply(request.Jsonrpc, request.ID, result, jsonErr)
			if err != nil {
				rpcsLog.Errorf("Failed to marshal reply: %v", err)
				return nil
			}
			return msg
		}

		// Valid requests with no ID (notifications) must not have a response
		// per the JSON-RPC spec.
		if request.ID == nil {
			return nil
		}

		// Attempt to parse the JSON-RPC request into a known
		// concrete command.
		parsedCmd := parseCmd(request)
		if parsedCmd.err != nil {
			jsonErr = parsedCmd.err
		} else {
			result, jsonErr = s.standardCmdResult(ctx, parsedCmd)
		}
	}

	// Marshal the response.
	msg, err := createMarshalledReply(request.Jsonrpc, request.ID, result, jsonErr)
	if err != nil {
		rpcsLog.Errorf("Failed to marshal reply: %v", err)
		return nil
	}
	return msg
}

// jsonRPCRead handles reading and responding to RPC messages.
func (s *rpcServer) jsonRPCRead(sCtx context.Context, w http.ResponseWriter, r *http.Request, isAdmin bool) {
	select {
	case <-sCtx.Done():
		return
	default:
	}

	// Read and close the JSON-RPC request body from the caller.
	body, err := ioutil.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		errMsg := fmt.Sprintf("error reading JSON message: %v", err)
		errCode := http.StatusBadRequest
		http.Error(w, strconv.Itoa(errCode)+" "+errMsg,
			errCode)
		return
	}

	// Unfortunately, the http server doesn't provide the ability to change
	// the read deadline for the new connection and having one breaks long
	// polling.  However, not having a read deadline on the initial
	// connection would mean clients can connect and idle forever.  Thus,
	// hijack the connection from the HTTP server, clear the read deadline,
	// and handle writing the response manually.
	hj, ok := w.(http.Hijacker)
	if !ok {
		errMsg := "webserver doesn't support hijacking"
		rpcsLog.Warnf(errMsg)
		errCode := http.StatusInternalServerError
		http.Error(w, strconv.Itoa(errCode)+" "+errMsg,
			errCode)
		return
	}

	conn, buf, err := hj.Hijack()
	if err != nil {
		rpcsLog.Warnf("Failed to hijack HTTP connection: %v", err)
		errCode := http.StatusInternalServerError
		http.Error(w, strconv.Itoa(errCode)+" "+
			err.Error(), errCode)
		return
	}

	defer conn.Close()
	defer buf.Flush()
	conn.SetReadDeadline(timeZeroVal)
	// Setup a close notifier.  Since the connection is hijacked,
	// the CloseNotifier on the ResponseWriter is not available.
	ctx, cancel := context.WithCancel(sCtx)
	defer cancel()

	go func() {
		_, err := conn.Read(make([]byte, 1))
		if err != nil {
			cancel()
		}
	}()

	var results []json.RawMessage
	var batchSize int
	var batchedRequest bool

	// Determine request type
	if bytes.HasPrefix(body, batchedRequestPrefix) {
		batchedRequest = true
	}

	// Process a single request
	if !batchedRequest {
		var req dcrjson.Request
		var resp json.RawMessage
		err = json.Unmarshal(body, &req)
		if err != nil {
			jsonErr := &dcrjson.RPCError{
				Code:    dcrjson.ErrRPCParse.Code,
				Message: fmt.Sprintf("Failed to parse request: %v", err),
			}
			resp, err = dcrjson.MarshalResponse("1.0", nil, nil, jsonErr)
			if err != nil {
				rpcsLog.Errorf("Failed to create reply: %v", err)
			}
		} else {
			resp = s.processRequest(ctx, &req, isAdmin)
		}

		if resp != nil {
			results = append(results, resp)
		}
	}

	// Process a batched request
	if batchedRequest {
		var batchedRequests []json.RawMessage
		var resp json.RawMessage
		err = json.Unmarshal(body, &batchedRequests)
		if err != nil {
			jsonErr := &dcrjson.RPCError{
				Code:    dcrjson.ErrRPCParse.Code,
				Message: fmt.Sprintf("Failed to parse request: %v", err),
			}
			resp, err = dcrjson.MarshalResponse("2.0", nil, nil, jsonErr)
			if err != nil {
				rpcsLog.Errorf("Failed to create reply: %v", err)
			}

			if resp != nil {
				results = append(results, resp)
			}
		}

		if err == nil {
			// Response with an empty batch error if the batch size is zero
			if len(batchedRequests) == 0 {
				jsonErr := &dcrjson.RPCError{
					Code:    dcrjson.ErrRPCInvalidRequest.Code,
					Message: "Invalid request: empty batch",
				}
				resp, err = dcrjson.MarshalResponse("2.0", nil, nil, jsonErr)
				if err != nil {
					rpcsLog.Errorf("Failed to marshal reply: %v", err)
				}

				if resp != nil {
					results = append(results, resp)
				}
			}

			// Process each batch entry individually
			if len(batchedRequests) > 0 {
				batchSize = len(batchedRequests)

				for _, entry := range batchedRequests {
					var req dcrjson.Request
					err := json.Unmarshal(entry, &req)
					if err != nil {
						jsonErr := &dcrjson.RPCError{
							Code: dcrjson.ErrRPCInvalidRequest.Code,
							Message: fmt.Sprintf("Invalid request: %v",
								err),
						}
						resp, err = dcrjson.MarshalResponse("", nil, nil, jsonErr)
						if err != nil {
							rpcsLog.Errorf("Failed to create reply: %v", err)
						}

						if resp != nil {
							results = append(results, resp)
						}
						continue
					}

					resp = s.processRequest(ctx, &req, isAdmin)
					if resp != nil {
						results = append(results, resp)
					}
				}
			}
		}
	}

	var msg = []byte{}
	if batchedRequest && batchSize > 0 {
		if len(results) > 0 {
			// Form the batched response json
			var buffer bytes.Buffer
			buffer.WriteByte('[')
			for idx, reply := range results {
				if idx == len(results)-1 {
					buffer.Write(reply)
					buffer.WriteByte(']')
					break
				}
				buffer.Write(reply)
				buffer.WriteByte(',')
			}
			msg = buffer.Bytes()
		}
	}

	if !batchedRequest || batchSize == 0 {
		// Respond with the first results entry for single requests
		if len(results) > 0 {
			msg = results[0]
		}
	}

	// Write the response.
	err = s.writeHTTPResponseHeaders(r, w.Header(), http.StatusOK, buf)
	if err != nil {
		rpcsLog.Error(err)
		return
	}
	if _, err := buf.Write(msg); err != nil {
		rpcsLog.Errorf("Failed to write marshalled reply: %v", err)
	}

	// Terminate with newline to maintain compatibility with Bitcoin Core.
	if err := buf.WriteByte('\n'); err != nil {
		rpcsLog.Errorf("Failed to append terminating newline to reply: %v", err)
	}
}

// jsonAuthFail sends a message back to the client if the http auth is rejected.
func jsonAuthFail(w http.ResponseWriter) {
	w.Header().Add("WWW-Authenticate", `Basic realm="dcrd RPC"`)
	http.Error(w, "401 Unauthorized.", http.StatusUnauthorized)
}

// route sets up the endpoints of the rpc server.
func (s *rpcServer) route(ctx context.Context) *http.Server {
	rpcServeMux := http.NewServeMux()
	httpServer := &http.Server{
		Handler: rpcServeMux,

		// Timeout connections which don't complete the initial
		// handshake within the allowed timeframe.
		ReadTimeout: time.Second * rpcAuthTimeoutSeconds,
	}
	rpcServeMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		w.Header().Set("Content-Type", "application/json")
		r.Close = true

		// Limit the number of connections to max allowed.
		if s.limitConnections(w, r.RemoteAddr) {
			return
		}

		// Keep track of the number of connected clients.
		s.incrementClients()
		defer s.decrementClients()
		_, isAdmin, err := s.checkAuth(r, true)
		if err != nil {
			jsonAuthFail(w)
			return
		}

		// Read and respond to the request.
		s.jsonRPCRead(ctx, w, r, isAdmin)
	})

	// Websocket endpoint.
	rpcServeMux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		authenticated, isAdmin, err := s.checkAuth(r, false)
		if err != nil {
			jsonAuthFail(w)
			return
		}

		// Attempt to upgrade the connection to a websocket connection
		// using the default size for read/write buffers.
		ws, err := websocket.Upgrade(w, r, nil, 0, 0)
		if err != nil {
			var herr websocket.HandshakeError
			if !errors.As(err, &herr) {
				rpcsLog.Errorf("Unexpected websocket error: %v",
					err)
			}
			http.Error(w, "400 Bad Request.", http.StatusBadRequest)
			return
		}
		ws.SetPingHandler(func(payload string) error {
			err := ws.WriteControl(websocket.PongMessage, []byte(payload),
				time.Now().Add(time.Second))
			rpcsLog.Debugf("ping received: len %d", len(payload))
			rpcsLog.Tracef("ping payload: %s", payload)
			if err != nil {
				rpcsLog.Errorf("Failed to send pong: %v", err)
				return err
			}
			return nil
		})
		ws.SetPongHandler(func(payload string) error {
			rpcsLog.Debugf("pong received: len %d", len(payload))
			rpcsLog.Tracef("pong payload: %s", payload)
			return nil
		})
		s.WebsocketHandler(ws, r.RemoteAddr, authenticated, isAdmin)
	})
	return httpServer
}

// Run starts the rpc server and its listeners. It blocks until the
// provided context is cancelled.
func (s *rpcServer) Run(ctx context.Context) {
	rpcsLog.Trace("Starting RPC server")
	server := s.route(ctx)
	for _, listener := range s.cfg.Listeners {
		s.wg.Add(1)
		go func(listener net.Listener) {
			rpcsLog.Infof("RPC server listening on %s", listener.Addr())
			server.Serve(listener)
			rpcsLog.Tracef("RPC listener done for %s", listener.Addr())
			s.wg.Done()
		}(listener)
	}

	s.ntfnMgr.Run(ctx)
	err := s.shutdown()
	if err != nil {
		rpcsLog.Error(err)
		return
	}
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

// rpcserverConfig is a descriptor containing the RPC server configuration.
type rpcserverConfig struct {
	// Listeners defines a slice of listeners for which the RPC server will
	// take ownership of and accept connections.  Since the RPC server takes
	// ownership of these listeners, they will be closed when the RPC server
	// is stopped.
	Listeners []net.Listener

	// StartupTime is the unix timestamp for when the server that is hosting
	// the RPC server started.
	StartupTime int64

	// ConnMgr defines the connection manager for the RPC server to use.  It
	// provides the RPC server with a means to do things such as add,
	// remove, connect, disconnect, and query peers as well as other
	// connection-related data and tasks.
	ConnMgr rpcserver.ConnManager

	// SyncMgr defines the sync manager for the RPC server to use.
	SyncMgr rpcserver.SyncManager

	// PeerNotifier provides an interface for server peer notifications.
	PeerNotifier PeerNotifier

	// These fields allow the RPC server to interface with the local block
	// chain data and state.
	TimeSource   blockchain.MedianTimeSource
	Chain        rpcserver.Chain
	ChainParams  *chaincfg.Params
	DB           database.DB
	FeeEstimator rpcserver.FeeEstimator
	Services     wire.ServiceFlag

	// SubsidyCache defines a cache for efficient access to consensus-critical
	// subsidy calculations.
	SubsidyCache *standalone.SubsidyCache

	// AddrManager defines a concurrency safe address manager for caching
	// potential peers on the network.
	AddrManager rpcserver.AddrManager

	// Clock defines the clock for the RPC server to use.
	Clock rpcserver.Clock

	// TxMemPool defines the transaction memory pool to interact with.
	TxMemPool *mempool.TxPool

	// These fields allow the RPC server to interface with mining.
	//
	// BgBlkTmplGenerator generates blocks as a background process, CPUMiner
	// solves templates using the CPU.  CPU mining is typically only useful
	// for test purposes when doing regression or simulation testing.
	BgBlkTmplGenerator func() *BgBlkTmplGenerator
	CPUMiner           *CPUMiner

	// These fields define any optional indexes the RPC server can make use
	// of to provide additional data when queried.
	TxIndex   *indexers.TxIndex
	AddrIndex *indexers.AddrIndex
}

// newRPCServer returns a new instance of the rpcServer struct.
func newRPCServer(config *rpcserverConfig) (*rpcServer, error) {
	rpc := rpcServer{
		cfg:                    *config,
		statusLines:            make(map[int]string),
		workState:              newWorkState(),
		helpCacher:             newHelpCacher(),
		requestProcessShutdown: make(chan struct{}),
	}
	if cfg.RPCUser != "" && cfg.RPCPass != "" {
		login := cfg.RPCUser + ":" + cfg.RPCPass
		auth := "Basic " +
			base64.StdEncoding.EncodeToString([]byte(login))
		rpc.authsha = sha256.Sum256([]byte(auth))
	}
	if cfg.RPCLimitUser != "" && cfg.RPCLimitPass != "" {
		login := cfg.RPCLimitUser + ":" + cfg.RPCLimitPass
		auth := "Basic " +
			base64.StdEncoding.EncodeToString([]byte(login))
		rpc.limitauthsha = sha256.Sum256([]byte(auth))
	}
	rpc.ntfnMgr = newWsNotificationManager(&rpc)

	return &rpc, nil
}

func init() {
	rpcHandlers = rpcHandlersBeforeInit
	rand.Seed(time.Now().UnixNano())

	// blake256Pad is the extra blake256 internal padding needed for the
	// data of the getwork RPC.  The internal blake256 padding consists of
	// a single 1 bit followed by zeros and a final 1 bit in order to pad
	// the message out to 56 bytes followed by length of the message in
	// bits encoded as a big-endian uint64 (8 bytes).  Thus, the resulting
	// length is a multiple of the blake256 block size (64 bytes).  Since
	// the block header is a fixed size, it only needs to be calculated
	// once.
	blake256Pad = make([]byte, getworkDataLen-wire.MaxBlockHeaderPayload)
	blake256Pad[0] = 0x80
	blake256Pad[len(blake256Pad)-9] |= 0x01
	binary.BigEndian.PutUint64(blake256Pad[len(blake256Pad)-8:],
		wire.MaxBlockHeaderPayload*8)
}
