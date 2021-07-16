// Copyright (c) 2014 Conformal Systems LLC.
// Copyright (c) 2015-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package stake

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
		{ErrSStxTooManyInputs, "ErrSStxTooManyInputs"},
		{ErrSStxTooManyOutputs, "ErrSStxTooManyOutputs"},
		{ErrSStxNoOutputs, "ErrSStxNoOutputs"},
		{ErrSStxInvalidInputs, "ErrSStxInvalidInputs"},
		{ErrSStxInvalidOutputs, "ErrSStxInvalidOutputs"},
		{ErrSStxInOutProportions, "ErrSStxInOutProportions"},
		{ErrSStxBadCommitAmount, "ErrSStxBadCommitAmount"},
		{ErrSStxBadChangeAmts, "ErrSStxBadChangeAmts"},
		{ErrSStxVerifyCalcAmts, "ErrSStxVerifyCalcAmts"},
		{ErrSSGenWrongNumInputs, "ErrSSGenWrongNumInputs"},
		{ErrSSGenTooManyOutputs, "ErrSSGenTooManyOutputs"},
		{ErrSSGenNoOutputs, "ErrSSGenNoOutputs"},
		{ErrSSGenWrongIndex, "ErrSSGenWrongIndex"},
		{ErrSSGenWrongTxTree, "ErrSSGenWrongTxTree"},
		{ErrSSGenNoStakebase, "ErrSSGenNoStakebase"},
		{ErrSSGenNoReference, "ErrSSGenNoReference"},
		{ErrSSGenBadReference, "ErrSSGenBadReference"},
		{ErrSSGenNoVotePush, "ErrSSGenNoVotePush"},
		{ErrSSGenBadVotePush, "ErrSSGenBadVotePush"},
		{ErrSSGenInvalidDiscriminatorLength, "ErrSSGenInvalidDiscriminatorLength"},
		{ErrSSGenInvalidNullScript, "ErrSSGenInvalidNullScript"},
		{ErrSSGenInvalidTVLength, "ErrSSGenInvalidTVLength"},
		{ErrSSGenInvalidTreasuryVote, "ErrSSGenInvalidTreasuryVote"},
		{ErrSSGenDuplicateTreasuryVote, "ErrSSGenDuplicateTreasuryVote"},
		{ErrSSGenInvalidTxVersion, "ErrSSGenInvalidTxVersion"},
		{ErrSSGenUnknownDiscriminator, "ErrSSGenUnknownDiscriminator"},
		{ErrSSGenBadGenOuts, "ErrSSGenBadGenOuts"},
		{ErrSSRtxWrongNumInputs, "ErrSSRtxWrongNumInputs"},
		{ErrSSRtxTooManyOutputs, "ErrSSRtxTooManyOutputs"},
		{ErrSSRtxNoOutputs, "ErrSSRtxNoOutputs"},
		{ErrSSRtxWrongTxTree, "ErrSSRtxWrongTxTree"},
		{ErrSSRtxBadOuts, "ErrSSRtxBadOuts"},
		{ErrVerSStxAmts, "ErrVerSStxAmts"},
		{ErrVerifyInput, "ErrVerifyInput"},
		{ErrVerifyOutType, "ErrVerifyOutType"},
		{ErrVerifyTooMuchFees, "ErrVerifyTooMuchFees"},
		{ErrVerifySpendTooMuch, "ErrVerifySpendTooMuch"},
		{ErrVerifyOutputAmt, "ErrVerifyOutputAmt"},
		{ErrVerifyOutPkhs, "ErrVerifyOutPkhs"},
		{ErrDatabaseCorrupt, "ErrDatabaseCorrupt"},
		{ErrMissingDatabaseTx, "ErrMissingDatabaseTx"},
		{ErrMemoryCorruption, "ErrMemoryCorruption"},
		{ErrFindTicketIdxs, "ErrFindTicketIdxs"},
		{ErrMissingTicket, "ErrMissingTicket"},
		{ErrDuplicateTicket, "ErrDuplicateTicket"},
		{ErrUnknownTicketSpent, "ErrUnknownTicketSpent"},
		{ErrTAddInvalidTxVersion, "ErrTAddInvalidTxVersion"},
		{ErrTAddInvalidCount, "ErrTAddInvalidCount"},
		{ErrTAddInvalidVersion, "ErrTAddInvalidVersion"},
		{ErrTAddInvalidScriptLength, "ErrTAddInvalidScriptLength"},
		{ErrTAddInvalidLength, "ErrTAddInvalidLength"},
		{ErrTAddInvalidOpcode, "ErrTAddInvalidOpcode"},
		{ErrTAddInvalidChange, "ErrTAddInvalidChange"},
		{ErrTSpendInvalidTxVersion, "ErrTSpendInvalidTxVersion"},
		{ErrTSpendInvalidLength, "ErrTSpendInvalidLength"},
		{ErrTSpendInvalidVersion, "ErrTSpendInvalidVersion"},
		{ErrTSpendInvalidScriptLength, "ErrTSpendInvalidScriptLength"},
		{ErrTSpendInvalidPubkey, "ErrTSpendInvalidPubkey"},
		{ErrTSpendInvalidScript, "ErrTSpendInvalidScript"},
		{ErrTSpendInvalidTransaction, "ErrTSpendInvalidTransaction"},
		{ErrTSpendInvalidTGen, "ErrTSpendInvalidTGen"},
		{ErrTSpendInvalidSpendScript, "ErrTSpendInvalidSpendScript"},
		{ErrTreasuryBaseInvalidTxVersion, "ErrTreasuryBaseInvalidTxVersion"},
		{ErrTreasuryBaseInvalidCount, "ErrTreasuryBaseInvalidCount"},
		{ErrTreasuryBaseInvalidLength, "ErrTreasuryBaseInvalidLength"},
		{ErrTreasuryBaseInvalidVersion, "ErrTreasuryBaseInvalidVersion"},
		{ErrTreasuryBaseInvalidOpcode0, "ErrTreasuryBaseInvalidOpcode0"},
		{ErrTreasuryBaseInvalidOpcode1, "ErrTreasuryBaseInvalidOpcode1"},
		{ErrTreasuryBaseInvalid, "ErrTreasuryBaseInvalid"},
	}

	for i, test := range tests {
		result := test.in.Error()
		if result != test.want {
			t.Errorf("%d: got: %s want: %s", i, result, test.want)
			continue
		}
	}
}

// TestRuleError tests the error output for the RuleError type.
func TestRuleError(t *testing.T) {
	tests := []struct {
		in   RuleError
		want string
	}{{
		RuleError{Description: "duplicate block"},
		"duplicate block",
	}, {
		RuleError{Description: "human-readable error"},
		"human-readable error",
	}}

	for i, test := range tests {
		result := test.in.Error()
		if result != test.want {
			t.Errorf("#%d: got: %s want: %s", i, result, test.want)
			continue
		}
	}
}

// TestRuleErrorKindIsAs ensures both ErrorKind and RuleError can be
// identified as being a specific error kind via errors.Is and unwrapped
// via errors.As.
func TestRuleErrorKindIsAs(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		target    error
		wantMatch bool
		wantAs    ErrorKind
	}{{
		name:      "ErrSStxTooManyInputs == ErrSStxTooManyInputs",
		err:       ErrSStxTooManyInputs,
		target:    ErrSStxTooManyInputs,
		wantMatch: true,
		wantAs:    ErrSStxTooManyInputs,
	}, {
		name:      "RuleError.ErrSStxTooManyInputs == ErrSStxTooManyInputs",
		err:       stakeRuleError(ErrSStxTooManyInputs, ""),
		target:    ErrSStxTooManyInputs,
		wantMatch: true,
		wantAs:    ErrSStxTooManyInputs,
	}, {
		name:      "RuleError.ErrSStxTooManyInputs == RuleError.ErrSStxTooManyInputs",
		err:       stakeRuleError(ErrSStxTooManyInputs, ""),
		target:    stakeRuleError(ErrSStxTooManyInputs, ""),
		wantMatch: true,
		wantAs:    ErrSStxTooManyInputs,
	}, {
		name:      "ErrSStxTooManyInputs != ErrSSGenNoOutputs",
		err:       ErrSStxTooManyInputs,
		target:    ErrSSGenNoOutputs,
		wantMatch: false,
		wantAs:    ErrSStxTooManyInputs,
	}, {
		name:      "RuleError.ErrSStxTooManyInputs != ErrSSGenNoOutputs",
		err:       stakeRuleError(ErrSStxTooManyInputs, ""),
		target:    ErrSSGenNoOutputs,
		wantMatch: false,
		wantAs:    ErrSStxTooManyInputs,
	}, {
		name:      "ErrSStxTooManyInputs != RuleError.ErrSSGenNoOutputs",
		err:       ErrSStxTooManyInputs,
		target:    stakeRuleError(ErrSSGenNoOutputs, ""),
		wantMatch: false,
		wantAs:    ErrSStxTooManyInputs,
	}, {
		name:      "RulError.ErrSStxTooManyInputs != RuleError.ErrSSGenNoOutputs",
		err:       stakeRuleError(ErrSStxTooManyInputs, ""),
		target:    stakeRuleError(ErrSSGenNoOutputs, ""),
		wantMatch: false,
		wantAs:    ErrSStxTooManyInputs,
	}, {
		name:      "RuleError.ErrDuplicateTicket != io.EOF",
		err:       stakeRuleError(ErrDuplicateTicket, ""),
		target:    io.EOF,
		wantMatch: false,
		wantAs:    ErrDuplicateTicket,
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
