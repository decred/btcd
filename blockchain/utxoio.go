// Copyright (c) 2015-2016 The btcsuite developers
// Copyright (c) 2016-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"fmt"
	"sync"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/wire"
)

// -----------------------------------------------------------------------------
// The unspent transaction output (utxo) set consists of an entry for each
// unspent output using a format that is optimized to reduce space using domain
// specific compression algorithms.
//
// Each entry is keyed by an outpoint as specified below.  It is important to
// note that the key encoding uses a VLQ, which employs an MSB encoding so
// iteration of utxos when doing byte-wise comparisons will produce them in
// order.
//
// The serialized key format is:
//
//   <hash><tree><output index>
//
//   Field                Type             Size
//   hash                 chainhash.Hash   chainhash.HashSize
//   tree                 VLQ              variable
//   output index         VLQ              variable
//
// The serialized value format is:
//
//   <block height><block index><flags><compressed txout>
//   OPTIONAL: [<ticket min outs>]
//
//   Field                Type     Size
//   block height         VLQ      variable
//   block index          VLQ      variable
//   flags                VLQ      variable
//   compressed txout
//     compressed amount   VLQ      variable
//     script version      VLQ      variable
//     compressed script   []byte   variable
//
//   OPTIONAL
//     ticketMinOuts      []byte         variable
//
// The serialized flags format is:
//   bit  0     - containing transaction is a coinbase
//   bit  1     - containing transaction has an expiry
//   bits 2-5   - transaction type
//   bits 6-7   - unused
//
// The ticket min outs field contains minimally encoded outputs for all outputs
// of a ticket transaction. It is only encoded for ticket submission outputs.
//
// -----------------------------------------------------------------------------

// maxUint32VLQSerializeSize is the maximum number of bytes a max uint32 takes
// to serialize as a VLQ.
var maxUint32VLQSerializeSize = serializeSizeVLQ(1<<32 - 1)

// maxUint8VLQSerializeSize is the maximum number of bytes a max uint8 takes to
// serialize as a VLQ.
var maxUint8VLQSerializeSize = serializeSizeVLQ(1<<8 - 1)

// utxoSetDbPrefixSize is the number of bytes that the prefx for UTXO set
// entries takes.
var utxoSetDbPrefixSize = len(utxoPrefixUtxoSet)

// outpointKeyPool defines a concurrent safe free list of byte slices used to
// provide temporary buffers for outpoint database keys.
var outpointKeyPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, utxoSetDbPrefixSize+chainhash.HashSize+
			maxUint8VLQSerializeSize+maxUint32VLQSerializeSize)
		return &b // Pointer to slice to avoid boxing alloc.
	},
}

// outpointKey returns a key suitable for use as a database key in the utxo set
// while making use of a free list.  A new buffer is allocated if there are not
// already any available on the free list.  The returned byte slice should be
// returned to the free list by using the recycleOutpointKey function when the
// caller is done with it _unless_ the slice will need to live for longer than
// the caller can calculate such as when used to write to the database.
func outpointKey(outpoint wire.OutPoint) *[]byte {
	// A VLQ employs an MSB encoding, so they are useful not only to reduce the
	// amount of storage space, but also so iteration of utxos when doing
	// byte-wise comparisons will produce them in order.
	key := outpointKeyPool.Get().(*[]byte)
	tree := uint64(outpoint.Tree)
	idx := uint64(outpoint.Index)
	*key = (*key)[:utxoSetDbPrefixSize+chainhash.HashSize+
		serializeSizeVLQ(tree)+serializeSizeVLQ(idx)]
	copy(*key, utxoPrefixUtxoSet)
	offset := utxoSetDbPrefixSize
	copy((*key)[offset:], outpoint.Hash[:])
	offset += chainhash.HashSize
	offset += putVLQ((*key)[offset:], tree)
	putVLQ((*key)[offset:], idx)
	return key
}

// decodeOutpointKey decodes the passed serialized key into the passed outpoint.
func decodeOutpointKey(serialized []byte, outpoint *wire.OutPoint) error {
	if utxoSetDbPrefixSize+chainhash.HashSize >= len(serialized) {
		return errDeserialize("unexpected length for serialized outpoint key")
	}

	// Ignore the UTXO set prefix.
	offset := utxoSetDbPrefixSize

	// Deserialize the hash.
	var hash chainhash.Hash
	copy(hash[:], serialized[offset:offset+chainhash.HashSize])
	offset += chainhash.HashSize

	// Deserialize the tree.
	tree, bytesRead := deserializeVLQ(serialized[offset:])
	offset += bytesRead
	if offset >= len(serialized) {
		return errDeserialize("unexpected end of data after tree")
	}

	// Deserialize the index.
	idx, _ := deserializeVLQ(serialized[offset:])

	// Populate the outpoint.
	outpoint.Hash = hash
	outpoint.Tree = int8(tree)
	outpoint.Index = uint32(idx)

	return nil
}

// recycleOutpointKey puts the provided byte slice, which should have been
// obtained via the outpointKey function, back on the free list.
func recycleOutpointKey(key *[]byte) {
	outpointKeyPool.Put(key)
}

// serializeUtxoEntry returns the entry serialized to a format that is suitable
// for long-term storage.  The format is described in detail above.
func serializeUtxoEntry(entry *UtxoEntry) ([]byte, error) {
	// Spent entries have no serialization.
	if entry.IsSpent() {
		return nil, nil
	}

	// Calculate the size needed to serialize the entry.
	const hasAmount = true
	flags := encodeFlags(entry.IsCoinBase(), entry.HasExpiry(),
		entry.TransactionType())
	size := serializeSizeVLQ(uint64(entry.blockHeight)) +
		serializeSizeVLQ(uint64(entry.blockIndex)) +
		serializeSizeVLQ(uint64(flags)) +
		compressedTxOutSize(uint64(entry.amount), entry.scriptVersion,
			entry.pkScript, hasAmount)

	if entry.ticketMinOuts != nil {
		size += len(entry.ticketMinOuts.data)
	}

	// Serialize the entry.
	serialized := make([]byte, size)
	offset := putVLQ(serialized, uint64(entry.blockHeight))
	offset += putVLQ(serialized[offset:], uint64(entry.blockIndex))
	offset += putVLQ(serialized[offset:], uint64(flags))
	offset += putCompressedTxOut(serialized[offset:], uint64(entry.amount),
		entry.scriptVersion, entry.pkScript, hasAmount)

	if entry.ticketMinOuts != nil {
		copy(serialized[offset:], entry.ticketMinOuts.data)
	}

	return serialized, nil
}

// deserializeUtxoEntry decodes a utxo entry from the passed serialized byte
// slice into a new UtxoEntry using a format that is suitable for long-term
// storage.  The format is described in detail above.
func deserializeUtxoEntry(serialized []byte, txOutIndex uint32) (*UtxoEntry, error) {
	// Deserialize the block height.
	blockHeight, bytesRead := deserializeVLQ(serialized)
	offset := bytesRead
	if offset >= len(serialized) {
		return nil, errDeserialize("unexpected end of data after height")
	}

	// Deserialize the block index.
	blockIndex, bytesRead := deserializeVLQ(serialized[offset:])
	offset += bytesRead
	if offset >= len(serialized) {
		return nil, errDeserialize("unexpected end of data after index")
	}

	// Deserialize the flags.
	flags, bytesRead := deserializeVLQ(serialized[offset:])
	offset += bytesRead
	if offset >= len(serialized) {
		return nil, errDeserialize("unexpected end of data after flags")
	}
	isCoinBase, hasExpiry, txType := decodeFlags(txOutFlags(flags))

	// Decode the compressed unspent transaction output.
	amount, scriptVersion, script, bytesRead, err :=
		decodeCompressedTxOut(serialized[offset:], true)
	if err != nil {
		return nil, errDeserialize(fmt.Sprintf("unable to decode utxo: %v", err))
	}
	offset += bytesRead

	// Create a new utxo entry with the details deserialized above.
	entry := &UtxoEntry{
		amount:        amount,
		pkScript:      script,
		blockHeight:   uint32(blockHeight),
		blockIndex:    uint32(blockIndex),
		scriptVersion: scriptVersion,
		packedFlags:   encodeUtxoFlags(isCoinBase, hasExpiry, txType),
	}

	// Copy the minimal outputs if this was a ticket submission output.
	if isTicketSubmissionOutput(txType, txOutIndex) {
		sz, err := readDeserializeSizeOfMinimalOutputs(serialized[offset:])
		if err != nil {
			return nil, errDeserialize(fmt.Sprintf("unable to decode "+
				"ticket outputs: %v", err))
		}
		entry.ticketMinOuts = &ticketMinimalOutputs{
			data: make([]byte, sz),
		}
		copy(entry.ticketMinOuts.data, serialized[offset:offset+sz])
	}

	return entry, nil
}

// -----------------------------------------------------------------------------
// The utxo set state contains information regarding the current state of the
// utxo set.  In particular, it tracks the block height and block hash of the
// last completed flush.
//
// The utxo set state is tracked in the database since at any given time, the
// utxo cache may not be consistent with the utxo set in the database.  This is
// due to the fact that the utxo cache only flushes changes to the database
// periodically.  Therefore, during initialization, the utxo set state is used
// to identify the last flushed state of the utxo set and it can be caught up
// to the current best state of the main chain.
//
// Note: The utxo set state MUST always be updated in the same database
// transaction that the utxo set is updated in to guarantee that they stay in
// sync in the database.
//
// The serialized format is:
//
//   <block height><block hash>
//
//   Field          Type             Size
//   block height   VLQ              variable
//   block hash     chainhash.Hash   chainhash.HashSize
//
// -----------------------------------------------------------------------------

// UtxoSetState represents the current state of the utxo set.  In particular,
// it tracks the block height and block hash of the last completed flush.
type UtxoSetState struct {
	lastFlushHeight uint32
	lastFlushHash   chainhash.Hash
}

// serializeUtxoSetState serializes the provided utxo set state.  The format is
// described in detail above.
func serializeUtxoSetState(state *UtxoSetState) []byte {
	// Calculate the size needed to serialize the utxo set state.
	size := serializeSizeVLQ(uint64(state.lastFlushHeight)) + chainhash.HashSize

	// Serialize the utxo set state and return it.
	serialized := make([]byte, size)
	offset := putVLQ(serialized, uint64(state.lastFlushHeight))
	copy(serialized[offset:], state.lastFlushHash[:])
	return serialized
}

// deserializeUtxoSetState deserializes the passed serialized byte slice into
// the utxo set state.  The format is described in detail above.
func deserializeUtxoSetState(serialized []byte) (*UtxoSetState, error) {
	// Deserialize the block height.
	blockHeight, bytesRead := deserializeVLQ(serialized)
	offset := bytesRead
	if offset >= len(serialized) {
		return nil, errDeserialize("unexpected end of data after height")
	}

	// Deserialize the hash.
	if len(serialized[offset:]) != chainhash.HashSize {
		return nil, errDeserialize("unexpected length for serialized hash")
	}
	var hash chainhash.Hash
	copy(hash[:], serialized[offset:offset+chainhash.HashSize])

	// Create the utxo set state and return it.
	return &UtxoSetState{
		lastFlushHeight: uint32(blockHeight),
		lastFlushHash:   hash,
	}, nil
}
