// Copyright (c) 2015-2016 The btcsuite developers
// Copyright (c) 2016-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer

import (
	"fmt"
	"time"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/txscript/v4"
	"github.com/decred/dcrd/wire"
	"github.com/decred/slog"
)

// log is a logger that is initialized with no output filters.  This
// means the package will not perform any logging by default until the caller
// requests it.
// The default amount of logging is none.
var log = slog.Disabled

// DisableLog disables all library log output.  Logging output is disabled
// by default until UseLogger is called.
//
// Deprecated: Use UseLogger(slog.Disabled) instead.
func DisableLog() {
	log = slog.Disabled
}

// UseLogger uses a specified Logger to output package logging info.
func UseLogger(logger slog.Logger) {
	log = logger
}

// directionString is a helper function that returns a string that represents
// the direction of a connection (inbound or outbound).
func directionString(inbound bool) string {
	if inbound {
		return "inbound"
	}
	return "outbound"
}

// pickNoun returns the singular or plural form of a noun depending on the
// provided count.
func pickNoun(n uint64, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}

// formatLockTime returns a transaction lock time as a human-readable string.
func formatLockTime(lockTime uint32) string {
	// The lock time field of a transaction is either a block height at
	// which the transaction is finalized or a timestamp depending on if the
	// value is before the lockTimeThreshold.  When it is under the
	// threshold it is a block height.
	if lockTime < txscript.LockTimeThreshold {
		return fmt.Sprintf("height %d", lockTime)
	}

	return time.Unix(int64(lockTime), 0).String()
}

// invSummary returns an inventory message as a human-readable string.
func invSummary(invList []*wire.InvVect) string {
	// No inventory.
	invLen := len(invList)
	if invLen == 0 {
		return "empty"
	}

	// One inventory item.
	if invLen == 1 {
		iv := invList[0]
		switch iv.Type {
		case wire.InvTypeError:
			return fmt.Sprintf("error %s", iv.Hash)
		case wire.InvTypeBlock:
			return fmt.Sprintf("block %s", iv.Hash)
		case wire.InvTypeTx:
			return fmt.Sprintf("tx %s", iv.Hash)
		case wire.InvTypeFilteredBlock:
			return fmt.Sprintf("filtered block %s", iv.Hash)
		}

		return fmt.Sprintf("unknown (%d) %s", uint32(iv.Type), iv.Hash)
	}

	// More than one inv item.
	var numTxns, numBlocks uint64
	for _, iv := range invList {
		switch iv.Type {
		case wire.InvTypeTx:
			numTxns++
		case wire.InvTypeBlock:
			numBlocks++
		}
	}

	diff := uint64(invLen) - (numTxns + numBlocks)
	return fmt.Sprintf("txns %d, blocks %d, other %d", numTxns, numBlocks, diff)
}

// locatorSummary returns a block locator as a human-readable string.
func locatorSummary(locator []*chainhash.Hash, stopHash *chainhash.Hash) string {
	if len(locator) > 0 {
		return fmt.Sprintf("locator %s, stop %s", locator[0], stopHash)
	}

	return fmt.Sprintf("no locator, stop %s", stopHash)
}

// messageSummary returns a human-readable string which summarizes a message.
// Not all messages have or need a summary.  This is used for debug logging.
func messageSummary(msg wire.Message) string {
	switch msg := msg.(type) {
	case *wire.MsgVersion:
		return fmt.Sprintf("agent %s, pver %d, block %d",
			msg.UserAgent, msg.ProtocolVersion, msg.LastBlock)

	case *wire.MsgVerAck:
		// No summary.

	case *wire.MsgGetAddr:
		// No summary.

	case *wire.MsgGetAddrV2:
		// No summary.

	case *wire.MsgAddr:
		addrLen := len(msg.AddrList)
		addrNoun := pickNoun(uint64(addrLen), "addr", "addrs")
		return fmt.Sprintf("%d %s", addrLen, addrNoun)

	case *wire.MsgAddrV2:
		addrLen := len(msg.AddrList)
		addrNoun := pickNoun(uint64(addrLen), "addr", "addrs")
		return fmt.Sprintf("%d %s", addrLen, addrNoun)

	case *wire.MsgPing:
		// No summary - perhaps add nonce.

	case *wire.MsgPong:
		// No summary - perhaps add nonce.

	case *wire.MsgMemPool:
		// No summary.

	case *wire.MsgTx:
		return fmt.Sprintf("hash %s, %d inputs, %d outputs, lock %s",
			msg.TxHash(), len(msg.TxIn), len(msg.TxOut),
			formatLockTime(msg.LockTime))

	case *wire.MsgBlock:
		header := &msg.Header
		return fmt.Sprintf("hash %s, ver %d, %d tx, %s", msg.BlockHash(),
			header.Version, len(msg.Transactions), header.Timestamp)

	case *wire.MsgInv:
		return invSummary(msg.InvList)

	case *wire.MsgNotFound:
		return invSummary(msg.InvList)

	case *wire.MsgGetData:
		return invSummary(msg.InvList)

	case *wire.MsgGetBlocks:
		return locatorSummary(msg.BlockLocatorHashes, &msg.HashStop)

	case *wire.MsgGetHeaders:
		return locatorSummary(msg.BlockLocatorHashes, &msg.HashStop)

	case *wire.MsgHeaders:
		summary := fmt.Sprintf("num %d", len(msg.Headers))
		if len(msg.Headers) > 0 {
			finalHeader := msg.Headers[len(msg.Headers)-1]
			summary = fmt.Sprintf("%s, final hash %s, height %d", summary,
				finalHeader.BlockHash(), finalHeader.Height)
		}
		return summary

	case *wire.MsgGetInitState:
		return fmt.Sprintf("types %v", msg.Types)

	case *wire.MsgInitState:
		return fmt.Sprintf("blockHashes %d, voteHashes %d, tspendHashes %d",
			len(msg.BlockHashes), len(msg.VoteHashes),
			len(msg.TSpendHashes))
	}

	// No summary for other messages.
	return ""
}
