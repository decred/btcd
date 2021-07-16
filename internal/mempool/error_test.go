// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mempool

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
		{ErrInvalid, "ErrInvalid"},
		{ErrOrphanPolicyViolation, "ErrOrphanPolicyViolation"},
		{ErrMempoolDoubleSpend, "ErrMempoolDoubleSpend"},
		{ErrAlreadyVoted, "ErrorAlreadyVoted"},
		{ErrDuplicate, "ErrDuplicate"},
		{ErrCoinbase, "ErrCoinbase"},
		{ErrExpired, "ErrExpired"},
		{ErrNonStandard, "ErrNonStandard"},
		{ErrDustOutput, "ErrDustOutput"},
		{ErrInsufficientFee, "ErrInsufficientFee"},
		{ErrTooManyVotes, "ErrTooManyVotes"},
		{ErrDuplicateRevocation, "ErrDuplicateRevocation"},
		{ErrOldVote, "ErrOldVote"},
		{ErrAlreadyExists, "ErrAlreadyExists"},
		{ErrSeqLockUnmet, "ErrSeqLockUnmet"},
		{ErrInsufficientPriority, "ErrInsufficientPriority"},
		{ErrFeeTooHigh, "ErrFeeTooHigh"},
		{ErrOrphan, "ErrOrphan"},
		{ErrTooManyTSpends, "ErrTooManyTSpends"},
		{ErrTSpendMinedOnAncestor, "ErrTSpendMinedOnAncestor"},
		{ErrTSpendInvalidExpiry, "ErrTSpendInvalidExpiry"},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		result := test.in.Error()
		if result != test.want {
			t.Errorf("#%d\n got: %s want: %s", i, result,
				test.want)
			continue
		}
	}
}

// TestRuleError tests the error output for the RuleError type.
func TestRuleError(t *testing.T) {
	tests := []struct {
		in   RuleError
		want string
	}{
		{
			RuleError{Description: "duplicate block"},
			"duplicate block",
		},
		{
			RuleError{Description: "human-readable error"},
			"human-readable error",
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		result := test.in.Error()
		if result != test.want {
			t.Errorf("#%d\n got: %s want: %s", i, result, test.want)
			continue
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
		name:      "ErrOrphanPolicyViolation == ErrOrphanPolicyViolation",
		err:       ErrOrphanPolicyViolation,
		target:    ErrOrphanPolicyViolation,
		wantMatch: true,
		wantAs:    ErrOrphanPolicyViolation,
	}, {
		name:      "RuleError.ErrOrphanPolicyViolation == ErrOrphanPolicyViolation",
		err:       txRuleError(ErrOrphanPolicyViolation, ""),
		target:    ErrOrphanPolicyViolation,
		wantMatch: true,
		wantAs:    ErrOrphanPolicyViolation,
	}, {
		name:      "RuleError.ErrOrphanPolicyViolation == RuleError.ErrOrphanPolicyViolation",
		err:       txRuleError(ErrOrphanPolicyViolation, ""),
		target:    txRuleError(ErrOrphanPolicyViolation, ""),
		wantMatch: true,
		wantAs:    ErrOrphanPolicyViolation,
	}, {
		name:      "ErrOrphanPolicyViolation != ErrMempoolDoubleSpend",
		err:       ErrOrphanPolicyViolation,
		target:    ErrMempoolDoubleSpend,
		wantMatch: false,
		wantAs:    ErrOrphanPolicyViolation,
	}, {
		name:      "RuleError.ErrOrphanPolicyViolation != ErrMempoolDoubleSpend",
		err:       txRuleError(ErrOrphanPolicyViolation, ""),
		target:    ErrMempoolDoubleSpend,
		wantMatch: false,
		wantAs:    ErrOrphanPolicyViolation,
	}, {
		name:      "ErrOrphanPolicyViolation != RuleError.ErrMempoolDoubleSpend",
		err:       ErrOrphanPolicyViolation,
		target:    txRuleError(ErrMempoolDoubleSpend, ""),
		wantMatch: false,
		wantAs:    ErrOrphanPolicyViolation,
	}, {
		name:      "RuleError.ErrOrphanPolicyViolation != RuleError.ErrMempoolDoubleSpend",
		err:       txRuleError(ErrOrphanPolicyViolation, ""),
		target:    txRuleError(ErrMempoolDoubleSpend, ""),
		wantMatch: false,
		wantAs:    ErrOrphanPolicyViolation,
	}, {
		name:      "RuleError.ErrOrphanPolicyViolation != io.EOF",
		err:       txRuleError(ErrOrphanPolicyViolation, ""),
		target:    io.EOF,
		wantMatch: false,
		wantAs:    ErrOrphanPolicyViolation,
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
