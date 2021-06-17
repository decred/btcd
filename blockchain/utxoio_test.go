// Copyright (c) 2015-2016 The btcsuite developers
// Copyright (c) 2015-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/decred/dcrd/blockchain/stake/v4"
	"github.com/decred/dcrd/wire"
)

// TestUtxoSerialization ensures serializing and deserializing unspent
// transaction output entries works as expected.
func TestUtxoSerialization(t *testing.T) {
	t.Parallel()

	// Define constants for indicating flags.
	const (
		noCoinbase   = false
		withCoinbase = true
		noExpiry     = false
		withExpiry   = true
	)

	tests := []struct {
		name       string
		entry      *UtxoEntry
		serialized []byte
		txOutIndex uint32
	}{
		{
			name: "Coinbase, even uncomp pubkey",
			entry: &UtxoEntry{
				amount: 5000000000,
				pkScript: hexToBytes("410496b538e853519c726a2c91e61ec11600ae1390813a6" +
					"27c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621" +
					"e73a82cbf2342c858eeac"),
				blockHeight:   12345,
				blockIndex:    54321,
				scriptVersion: 0,
				packedFlags: encodeUtxoFlags(
					withCoinbase,
					noExpiry,
					stake.TxTypeRegular,
				),
			},
			serialized: hexToBytes("df3982a7310132000496b538e853519c726a2c91e61ec11" +
				"600ae1390813a627c66fb8be7947be63c52"),
			txOutIndex: 0,
		}, {
			name: "Coinbase, odd uncomp pubkey",
			entry: &UtxoEntry{
				amount: 5000000000,
				pkScript: hexToBytes("410496b538e853519c726a2c91e61ec11600ae1390813a6" +
					"27c66fb8be7947be63c52258a76c86aea2b1f59fb07ebe87e19dd6b8dee99409de" +
					"18c57d340dbbd37a341ac"),
				blockHeight:   12345,
				blockIndex:    54321,
				scriptVersion: 0,
				packedFlags: encodeUtxoFlags(
					withCoinbase,
					noExpiry,
					stake.TxTypeRegular,
				),
			},
			serialized: hexToBytes("df3982a7310132000596b538e853519c726a2c91e61ec11" +
				"600ae1390813a627c66fb8be7947be63c52"),
			txOutIndex: 0,
		}, {
			name: "Non-coinbase regular tx",
			entry: &UtxoEntry{
				amount: 1000000,
				pkScript: hexToBytes("76a914ee8bd501094a7d5ca318da2506de35e1cb025ddc8" +
					"8ac"),
				blockHeight:   55555,
				blockIndex:    1,
				scriptVersion: 0,
				packedFlags: encodeUtxoFlags(
					noCoinbase,
					noExpiry,
					stake.TxTypeRegular,
				),
			},
			serialized: hexToBytes("82b1030100070000ee8bd501094a7d5ca318da2506de35e" +
				"1cb025ddc"),
			txOutIndex: 0,
		}, {
			name: "Ticket tx",
			entry: &UtxoEntry{
				amount: 1000000,
				pkScript: hexToBytes("76a914ee8bd501094a7d5ca318da2506de35e1cb025ddc8" +
					"8ac"),
				blockHeight:   55555,
				blockIndex:    1,
				scriptVersion: 0,
				packedFlags: encodeUtxoFlags(
					noCoinbase,
					withExpiry,
					stake.TxTypeSStx,
				),
				ticketMinOuts: &ticketMinimalOutputs{
					data: hexToBytes("030f001aba76a9140cdf9941c0c221243cb8672cd1ad2c4c0" +
						"933850588ac0000206a1e1a221182c26bbae681e4d96d452794e1951e70a2085" +
						"20000000000000054b5f466001abd76a9146c4f8b15918566534d134be7d7004" +
						"b7f481bf36988ac"),
				},
			},
			serialized: hexToBytes("82b1030106070000ee8bd501094a7d5ca318da2506de35e" +
				"1cb025ddc030f001aba76a9140cdf9941c0c221243cb8672cd1ad2c4c0933850588a" +
				"c0000206a1e1a221182c26bbae681e4d96d452794e1951e70a208520000000000000" +
				"054b5f466001abd76a9146c4f8b15918566534d134be7d7004b7f481bf36988ac"),
			txOutIndex: 0,
		}, {
			name: "Output 2, coinbase, non-zero script version",
			entry: &UtxoEntry{
				amount: 100937281,
				pkScript: hexToBytes("76a914da33f77cee27c2a975ed5124d7e4f7f9751351018" +
					"8ac"),
				blockHeight:   12345,
				blockIndex:    1,
				scriptVersion: 0xffff,
				packedFlags: encodeUtxoFlags(
					withCoinbase,
					noExpiry,
					stake.TxTypeRegular,
				),
			},
			serialized: hexToBytes("df39010182b095bf4182fe7f00da33f77cee27c2a975ed5" +
				"124d7e4f7f975135101"),
			txOutIndex: 2,
		}, {
			name: "Has expiry",
			entry: &UtxoEntry{
				amount: 20000000,
				pkScript: hexToBytes("76a914e2ccd6ec7c6e2e581349c77e067385fa8236bf8a8" +
					"8ac"),
				blockHeight:   99999,
				blockIndex:    3,
				scriptVersion: 0,
				packedFlags: encodeUtxoFlags(
					noCoinbase,
					withExpiry,
					stake.TxTypeRegular,
				),
			},
			serialized: hexToBytes("858c1f0302120000e2ccd6ec7c6e2e581349c77e067385f" +
				"a8236bf8a"),
			txOutIndex: 0,
		}, {
			name: "Coinbase, spent",
			entry: &UtxoEntry{
				amount: 5000000000,
				pkScript: hexToBytes("410496b538e853519c726a2c91e61ec11600ae1390813a6" +
					"27c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621" +
					"e73a82cbf2342c858eeac"),
				blockHeight:   33333,
				blockIndex:    3,
				scriptVersion: 0,
				state:         utxoStateModified | utxoStateSpent,
				packedFlags: encodeUtxoFlags(
					withCoinbase,
					withExpiry,
					stake.TxTypeRegular,
				),
			},
			serialized: nil,
			txOutIndex: 0,
		},
	}

	for _, test := range tests {
		// Ensure the utxo entry serializes to the expected value.
		gotBytes, err := serializeUtxoEntry(test.entry)
		if err != nil {
			t.Errorf("%q: unexpected error: %v", test.name, err)
			continue
		}
		if !bytes.Equal(gotBytes, test.serialized) {
			t.Errorf("%q: mismatched bytes - got %x, want %x", test.name, gotBytes,
				test.serialized)
			continue
		}

		// Don't try to deserialize if the test entry was spent since it will have a
		// nil serialization.
		if test.entry.IsSpent() {
			continue
		}

		// Ensure that the serialized bytes are decoded back to the expected utxo.
		gotUtxo, err := deserializeUtxoEntry(test.serialized, test.txOutIndex)
		if err != nil {
			t.Errorf("%q: unexpected error: %v", test.name, err)
			continue
		}
		if !reflect.DeepEqual(gotUtxo, test.entry) {
			t.Errorf("%q: mismatched entry:\nwant: %+v\n got: %+v\n", test.name,
				test.entry, gotUtxo)
		}
	}
}

// TestUtxoEntryDeserializeErrors performs negative tests against deserializing
// unspent transaction outputs to ensure error paths work as expected.
func TestUtxoEntryDeserializeErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		serialized []byte
		txOutIndex uint32
		errType    error
	}{{
		// [EOF]
		name:       "nothing serialized (no block height)",
		serialized: hexToBytes("01"),
		txOutIndex: 0,
		errType:    errDeserialize(""),
	}, {
		// [<block height 01> EOF]
		name:       "no data after block height",
		serialized: hexToBytes("01"),
		txOutIndex: 0,
		errType:    errDeserialize(""),
	}, {
		// [<block height 01> <block index 01> EOF]
		name:       "no data after block index",
		serialized: hexToBytes("0101"),
		txOutIndex: 0,
		errType:    errDeserialize(""),
	}, {
		// [<block height 01> <block index 01> <flags 01> EOF]
		name:       "no data after flags",
		serialized: hexToBytes("010101"),
		txOutIndex: 0,
		errType:    errDeserialize(""),
	}, {
		// [<block height 01> <block index 01> <flags 01> <compressed amount 49>
		//  <script version 00> <compressed pk script 12> EOF]
		name:       "incomplete compressed txout",
		serialized: hexToBytes("010101490012"),
		txOutIndex: 0,
		errType:    errDeserialize(""),
	}, {
		// [<block height 01> <block index 01> <flags 06> <compressed amount 49>
		//  <script version 00> <compressed pk script 01 6e ...> EOF]
		name: "no minimal output data after script for a ticket submission " +
			"output",
		serialized: hexToBytes("0101064900016edbc6c4d31bae9f1ccc38538a114bf42de65" +
			"e86"),
		txOutIndex: 0,
		errType:    errDeserialize(""),
	}, {
		// [<block height 01> <block index 01> <flags 06> <compressed amount 49>
		//  <script version 00> <compressed pk script 01 6e ...>
		//  <ticket min outs {num outputs 01}> EOF]
		name: "truncated minimal output data after script for a ticket " +
			"submission output (num outputs only)",
		serialized: hexToBytes("0101064900016edbc6c4d31bae9f1ccc38538a114bf42de65" +
			"e8601"),
		txOutIndex: 0,
		errType:    errDeserialize(""),
	}, {
		// [<block height 01> <block index 01> <flags 06> <compressed amount 49>
		//  <script version 00> <compressed pk script 01 6e ...>
		//  <ticket min outs {num outputs 01} {amount 0f}> EOF]
		name: "truncated minimal output data after script for a ticket " +
			"submission output (num outputs and amount only)",
		serialized: hexToBytes("0101064900016edbc6c4d31bae9f1ccc38538a114bf42de65" +
			"e86010f"),
		txOutIndex: 0,
		errType:    errDeserialize(""),
	}, {
		// [<block height 01> <block index 01> <flags 06> <compressed amount 49>
		//  <script version 00> <compressed pk script 01 6e ...>
		//  <ticket min outs {num outputs 01} {amount 0f} {script version 00}> EOF]
		name: "truncated minimal output data after script for a ticket " +
			"submission output (num outputs, amount, and script version only)",
		serialized: hexToBytes("0101064900016edbc6c4d31bae9f1ccc38538a114bf42de65" +
			"e86010f00"),
		txOutIndex: 0,
		errType:    errDeserialize(""),
	}, {
		// [<block height 01> <block index 01> <flags 06> <compressed amount 49>
		//  <script version 00> <compressed pk script 01 6e ...>
		//  <ticket min outs {num outputs 01} {amount 0f} {script version 00}
		//  {script size 1a} {25 bytes of script instead of 26}> EOF]
		name: "truncated minimal output data after script for a ticket " +
			"submission output (script size specified as 0x1a, but only 0x19 bytes " +
			"provided)",
		serialized: hexToBytes("0101064900016edbc6c4d31bae9f1ccc38538a114bf42de65" +
			"e86010f001aba76a9140cdf9941c0c221243cb8672cd1ad2c4c0933850588"),
		txOutIndex: 0,
		errType:    errDeserialize(""),
	}}

	for _, test := range tests {
		// Ensure the expected error type is returned and the returned
		// entry is nil.
		entry, err := deserializeUtxoEntry(test.serialized, test.txOutIndex)
		if !errors.As(err, &test.errType) {
			t.Errorf("%q: expected error type does not match - got %T, want %T",
				test.name, err, test.errType)
			continue
		}
		if entry != nil {
			t.Errorf("%q: returned entry is not nil", test.name)
			continue
		}
	}
}

// TestUtxoSetStateSerialization ensures that serializing and deserializing
// the utxo set state works as expected.
func TestUtxoSetStateSerialization(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		state      *UtxoSetState
		serialized []byte
	}{{
		name: "last flush height and hash updated",
		state: &UtxoSetState{
			lastFlushHeight: 432100,
			lastFlushHash: *mustParseHash("000000000000000023455b4328635d8e014dbeea" +
				"99c6140aa715836cc7e55981"),
		},
		serialized: hexToBytes("99ae648159e5c76c8315a70a14c699eabe4d018e5d6328435" +
			"b45230000000000000000"),
	}, {
		name: "last flush height and hash are the genesis block",
		state: &UtxoSetState{
			lastFlushHeight: 0,
			lastFlushHash: *mustParseHash("298e5cc3d985bfe7f81dc135f360abe089edd439" +
				"6b86d2de66b0cef42b21d980"),
		},
		serialized: hexToBytes("0080d9212bf4ceb066ded2866b39d4ed89e0ab60f335c11df" +
			"8e7bf85d9c35c8e29"),
	}}

	for _, test := range tests {
		// Ensure the utxo set state serializes to the expected value.
		gotBytes := serializeUtxoSetState(test.state)
		if !bytes.Equal(gotBytes, test.serialized) {
			t.Errorf("%q: mismatched bytes - got %x, want %x", test.name, gotBytes,
				test.serialized)
			continue
		}

		// Ensure that the serialized bytes are decoded back to the expected utxo
		// set state.
		gotUtxoSetState, err := deserializeUtxoSetState(test.serialized)
		if err != nil {
			t.Errorf("%q: unexpected error: %v", test.name, err)
			continue
		}
		if !reflect.DeepEqual(gotUtxoSetState, test.state) {
			t.Errorf("%q: mismatched state:\nwant: %+v\n got: %+v\n", test.name,
				test.state, gotUtxoSetState)
		}
	}
}

// TestUtxoSetStateDeserializeErrors performs negative tests against
// deserializing the utxo set state to ensure error paths work as expected.
func TestUtxoSetStateDeserializeErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		serialized []byte
		errType    error
	}{{
		// [EOF]
		name:       "nothing serialized (no last flush height)",
		serialized: hexToBytes(""),
		errType:    errDeserialize(""),
	}, {
		// [<height 99ae64><EOF>]
		name:       "no data after last flush height",
		serialized: hexToBytes("99ae64"),
		errType:    errDeserialize(""),
	}, {
		// [<height 99ae64><truncated hash 8159e5c76c8315a70a14c699>]
		name:       "truncated hash",
		serialized: hexToBytes("99ae648159e5c76c8315a70a14c699"),
		errType:    errDeserialize(""),
	}}

	for _, test := range tests {
		// Ensure the expected error type is returned and the returned
		// utxo set state is nil.
		entry, err := deserializeUtxoSetState(test.serialized)
		if !errors.As(err, &test.errType) {
			t.Errorf("%q: expected error type does not match - got %T, want %T",
				test.name, err, test.errType)
			continue
		}
		if entry != nil {
			t.Errorf("%q: returned utxo set state is not nil", test.name)
			continue
		}
	}
}

// TestOutpointKey ensures that encoding and decoding outpoint keys works as
// expected.
func TestOutpointKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		outpoint   *wire.OutPoint
		serialized []byte
	}{{
		name: "outpoint in regular tree at index 2",
		outpoint: &wire.OutPoint{
			Hash: *mustParseHash("72914cae2d4bc75f7777373b7c085c4b92d59f3e059fc7fd3" +
				"9def71c9fe188b5"),
			Index: 2,
			Tree:  wire.TxTreeRegular,
		},
		// [<prefix 0303><hash b588...9172><tree 00><index 02>]
		serialized: hexToBytes("0303b588e19f1cf7de39fdc79f053e9fd5924b5c087c3b377" +
			"7775fc74b2dae4c91720002"),
	}, {
		name: "outpoint in stake tree at index 0",
		outpoint: &wire.OutPoint{
			Hash: *mustParseHash("d3bce77da2747baa85fb7ca4f6f8e123f31cd15ac691b2f82" +
				"543780158587d3a"),
			Index: 0,
			Tree:  wire.TxTreeStake,
		},
		// [<prefix 0303><hash 3a7d...bcd3><tree 01><index 00>]
		serialized: hexToBytes("03033a7d585801784325f8b291c65ad11cf323e1f8f6a47cf" +
			"b85aa7b74a27de7bcd30100"),
	}}

	for _, test := range tests {
		// Ensure that the outpoint serializes to the expected outpoint key.
		gotBytes := outpointKey(*test.outpoint)
		if !bytes.Equal(*gotBytes, test.serialized) {
			t.Errorf("%q: mismatched bytes - got %x, want %x", test.name, *gotBytes,
				test.serialized)
			continue
		}

		// Ensure that the serialized bytes are decoded back to the expected
		// outpoint.
		var gotOutpoint wire.OutPoint
		err := decodeOutpointKey(test.serialized, &gotOutpoint)
		if err != nil {
			t.Errorf("%q: unexpected error: %v", test.name, err)
			continue
		}
		if !reflect.DeepEqual(gotOutpoint, *test.outpoint) {
			t.Errorf("%q: mismatched outpoint:\nwant: %+v\n got: %+v\n", test.name,
				*test.outpoint, gotOutpoint)
			continue
		}
	}
}

// TestDecodeOutpointKeyErrors performs negative tests against decoding outpoint
// keys to ensure error paths work as expected.
func TestDecodeOutpointKeyErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		serialized []byte
		errType    error
	}{{
		// [EOF]
		name:       "nothing serialized",
		serialized: hexToBytes(""),
		errType:    errDeserialize(""),
	}, {
		// [<prefix 0303>]
		name:       "no data after prefix",
		serialized: hexToBytes("0303"),
		errType:    errDeserialize(""),
	}, {
		// [<prefix 0303><truncated hash b588>]
		name:       "truncated hash",
		serialized: hexToBytes("0303b588"),
		errType:    errDeserialize(""),
	}, {
		// [<prefix 0303><hash b588...9172>]
		name: "no data after hash",
		serialized: hexToBytes("0303b588e19f1cf7de39fdc79f053e9fd5924b5c087c3b377" +
			"7775fc74b2dae4c9172"),
		errType: errDeserialize(""),
	}, {
		// [<prefix 0303><hash b588...9172><tree 00>]
		name: "no data after tree",
		serialized: hexToBytes("0303b588e19f1cf7de39fdc79f053e9fd5924b5c087c3b377" +
			"7775fc74b2dae4c917200"),
		errType: errDeserialize(""),
	}}

	for _, test := range tests {
		// Ensure the expected error type is returned.
		var gotOutpoint wire.OutPoint
		err := decodeOutpointKey(test.serialized, &gotOutpoint)
		if !errors.As(err, &test.errType) {
			t.Errorf("%q: expected error type does not match - got %T, want %T",
				test.name, err, test.errType)
			continue
		}
	}
}
