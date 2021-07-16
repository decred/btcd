// Copyright (c) 2017 The btcsuite developers
// Copyright (c) 2015-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txscript

import (
	"errors"
	"io"
	"testing"
)

// TestErrorKindStringer tests the stringized output for the ErrorKind type.
func TestErrorKindStringer(t *testing.T) {
	tests := []struct {
		in   ErrorKind
		want string
	}{
		{ErrInvalidIndex, "ErrInvalidIndex"},
		{ErrInvalidSigHashSingleIndex, "ErrInvalidSigHashSingleIndex"},
		{ErrTooManyRequiredSigs, "ErrTooManyRequiredSigs"},
		{ErrTooMuchNullData, "ErrTooMuchNullData"},
		{ErrUnsupportedScriptVersion, "ErrUnsupportedScriptVersion"},
		{ErrNotMultisigScript, "ErrNotMultisigScript"},
		{ErrEarlyReturn, "ErrEarlyReturn"},
		{ErrEmptyStack, "ErrEmptyStack"},
		{ErrEvalFalse, "ErrEvalFalse"},
		{ErrScriptUnfinished, "ErrScriptUnfinished"},
		{ErrInvalidProgramCounter, "ErrInvalidProgramCounter"},
		{ErrScriptTooBig, "ErrScriptTooBig"},
		{ErrElementTooBig, "ErrElementTooBig"},
		{ErrTooManyOperations, "ErrTooManyOperations"},
		{ErrStackOverflow, "ErrStackOverflow"},
		{ErrInvalidPubKeyCount, "ErrInvalidPubKeyCount"},
		{ErrInvalidSignatureCount, "ErrInvalidSignatureCount"},
		{ErrNumOutOfRange, "ErrNumOutOfRange"},
		{ErrVerify, "ErrVerify"},
		{ErrEqualVerify, "ErrEqualVerify"},
		{ErrNumEqualVerify, "ErrNumEqualVerify"},
		{ErrCheckSigVerify, "ErrCheckSigVerify"},
		{ErrCheckMultiSigVerify, "ErrCheckMultiSigVerify"},
		{ErrCheckSigAltVerify, "ErrCheckSigAltVerify"},
		{ErrP2SHStakeOpCodes, "ErrP2SHStakeOpCodes"},
		{ErrDisabledOpcode, "ErrDisabledOpcode"},
		{ErrReservedOpcode, "ErrReservedOpcode"},
		{ErrMalformedPush, "ErrMalformedPush"},
		{ErrInvalidStackOperation, "ErrInvalidStackOperation"},
		{ErrUnbalancedConditional, "ErrUnbalancedConditional"},
		{ErrNegativeSubstrIdx, "ErrNegativeSubstrIdx"},
		{ErrOverflowSubstrIdx, "ErrOverflowSubstrIdx"},
		{ErrNegativeRotation, "ErrNegativeRotation"},
		{ErrOverflowRotation, "ErrOverflowRotation"},
		{ErrDivideByZero, "ErrDivideByZero"},
		{ErrNegativeShift, "ErrNegativeShift"},
		{ErrOverflowShift, "ErrOverflowShift"},
		{ErrP2SHTreasuryOpCodes, "ErrP2SHTreasuryOpCodes"},
		{ErrMinimalData, "ErrMinimalData"},
		{ErrInvalidSigHashType, "ErrInvalidSigHashType"},
		{ErrSigTooShort, "ErrSigTooShort"},
		{ErrSigTooLong, "ErrSigTooLong"},
		{ErrSigInvalidSeqID, "ErrSigInvalidSeqID"},
		{ErrSigInvalidDataLen, "ErrSigInvalidDataLen"},
		{ErrSigMissingSTypeID, "ErrSigMissingSTypeID"},
		{ErrSigMissingSLen, "ErrSigMissingSLen"},
		{ErrSigInvalidSLen, "ErrSigInvalidSLen"},
		{ErrSigInvalidRIntID, "ErrSigInvalidRIntID"},
		{ErrSigZeroRLen, "ErrSigZeroRLen"},
		{ErrSigNegativeR, "ErrSigNegativeR"},
		{ErrSigTooMuchRPadding, "ErrSigTooMuchRPadding"},
		{ErrSigInvalidSIntID, "ErrSigInvalidSIntID"},
		{ErrSigZeroSLen, "ErrSigZeroSLen"},
		{ErrSigNegativeS, "ErrSigNegativeS"},
		{ErrSigTooMuchSPadding, "ErrSigTooMuchSPadding"},
		{ErrSigHighS, "ErrSigHighS"},
		{ErrNotPushOnly, "ErrNotPushOnly"},
		{ErrPubKeyType, "ErrPubKeyType"},
		{ErrCleanStack, "ErrCleanStack"},
		{ErrDiscourageUpgradableNOPs, "ErrDiscourageUpgradableNOPs"},
		{ErrNegativeLockTime, "ErrNegativeLockTime"},
		{ErrUnsatisfiedLockTime, "ErrUnsatisfiedLockTime"},
	}

	for i, test := range tests {
		result := test.in.Error()
		if result != test.want {
			t.Errorf("#%d: got: %s want: %s", i, result, test.want)
			continue
		}
	}
}

// TestError tests the error output for the Error type.
func TestError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   Error
		want string
	}{
		{
			Error{Description: "some error"},
			"some error",
		},
		{
			Error{Description: "human-readable error"},
			"human-readable error",
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		result := test.in.Error()
		if result != test.want {
			t.Errorf("#%d: got: %s want: %s", i, result, test.want)
			continue
		}
	}
}

// TestIsDERSigError ensures IsDERSigError returns true for all error kinds that
// can be returned as a result of non-canonically-encoded DER signatures.
func TestIsDERSigError(t *testing.T) {
	tests := []struct {
		kind ErrorKind
		want bool
	}{
		{ErrSigTooShort, true},
		{ErrSigTooLong, true},
		{ErrSigInvalidSeqID, true},
		{ErrSigInvalidDataLen, true},
		{ErrSigMissingSTypeID, true},
		{ErrSigMissingSLen, true},
		{ErrSigInvalidSLen, true},
		{ErrSigInvalidRIntID, true},
		{ErrSigZeroRLen, true},
		{ErrSigNegativeR, true},
		{ErrSigTooMuchRPadding, true},
		{ErrSigInvalidSIntID, true},
		{ErrSigZeroSLen, true},
		{ErrSigNegativeS, true},
		{ErrSigTooMuchSPadding, true},
		{ErrSigHighS, true},
		{ErrEvalFalse, false},
		{ErrInvalidIndex, false},
	}
	for _, test := range tests {
		result := IsDERSigError(Error{Err: test.kind})
		if result != test.want {
			t.Errorf("%v: unexpected result -- got: %v want: %v", test.kind,
				result, test.want)
		}
	}
}

// TestErrorKindIsAs ensures both ErrorKind and Error can be identified as being
// a specific error kind via errors.Is and unwrapped via errors.As.
func TestErrorKindIsAs(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		target    error
		wantMatch bool
		wantAs    ErrorKind
	}{{
		name:      "ErrInvalidIndex == ErrInvalidIndex",
		err:       ErrInvalidIndex,
		target:    ErrInvalidIndex,
		wantMatch: true,
		wantAs:    ErrInvalidIndex,
	}, {
		name:      "Error.ErrInvalidIndex == ErrInvalidIndex",
		err:       scriptError(ErrInvalidIndex, ""),
		target:    ErrInvalidIndex,
		wantMatch: true,
		wantAs:    ErrInvalidIndex,
	}, {
		name:      "ErrEarlyReturn != ErrInvalidIndex",
		err:       ErrEarlyReturn,
		target:    ErrInvalidIndex,
		wantMatch: false,
		wantAs:    ErrEarlyReturn,
	}, {
		name:      "Error.ErrEarlyReturn != ErrInvalidIndex",
		err:       scriptError(ErrEarlyReturn, ""),
		target:    ErrInvalidIndex,
		wantMatch: false,
		wantAs:    ErrEarlyReturn,
	}, {
		name:      "ErrEarlyReturn != Error.ErrInvalidIndex",
		err:       ErrEarlyReturn,
		target:    scriptError(ErrInvalidIndex, ""),
		wantMatch: false,
		wantAs:    ErrEarlyReturn,
	}, {
		name:      "Error.ErrEarlyReturn != Error.ErrInvalidIndex",
		err:       scriptError(ErrEarlyReturn, ""),
		target:    scriptError(ErrInvalidIndex, ""),
		wantMatch: false,
		wantAs:    ErrEarlyReturn,
	}, {
		name:      "Error.ErrEarlyReturn != io.EOF",
		err:       scriptError(ErrEarlyReturn, ""),
		target:    io.EOF,
		wantMatch: false,
		wantAs:    ErrEarlyReturn,
	}}

	for _, test := range tests {
		// Ensure the error matches or not depending on the expected result.
		result := errors.Is(test.err, test.target)
		if result != test.wantMatch {
			t.Errorf("%s: incorrect error identification -- got %v, want %v",
				test.name, result, test.wantMatch)
			continue
		}

		// Ensure the underlying error kind can be unwrapped and is the
		// expected kind.
		var kind ErrorKind
		if !errors.As(test.err, &kind) {
			t.Errorf("%s: unable to unwrap to error kind", test.name)
			continue
		}
		if kind != test.wantAs {
			t.Errorf("%s: unexpected unwrapped error kind -- got %v, want %v",
				test.name, kind, test.wantAs)
			continue
		}
	}
}
