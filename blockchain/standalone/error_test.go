// Copyright (c) 2019-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package standalone

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
		{ErrUnexpectedDifficulty, "ErrUnexpectedDifficulty"},
		{ErrHighHash, "ErrHighHash"},
		{ErrInvalidTSpendExpiry, "ErrInvalidTSpendExpiry"},
	}

	t.Logf("Running %d tests", len(tests))
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
		RuleError{Description: "unexpected difficulty"},
		"unexpected difficulty",
	}, {
		RuleError{Description: "human-readable error"},
		"human-readable error",
	},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		result := test.in.Error()
		if result != test.want {
			t.Errorf("%d: got: %s want: %s", i, result, test.want)
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
		name:      "ErrUnexpectedDifficulty == ErrUnexpectedDifficulty",
		err:       ErrUnexpectedDifficulty,
		target:    ErrUnexpectedDifficulty,
		wantMatch: true,
		wantAs:    ErrUnexpectedDifficulty,
	}, {
		name:      "RuleError.ErrUnexpectedDifficulty == ErrUnexpectedDifficulty",
		err:       ruleError(ErrUnexpectedDifficulty, ""),
		target:    ErrUnexpectedDifficulty,
		wantMatch: true,
		wantAs:    ErrUnexpectedDifficulty,
	}, {
		name:      "RuleError.ErrUnexpectedDifficulty == RuleError.ErrUnexpectedDifficulty",
		err:       ruleError(ErrUnexpectedDifficulty, ""),
		target:    ruleError(ErrUnexpectedDifficulty, ""),
		wantMatch: true,
		wantAs:    ErrUnexpectedDifficulty,
	}, {
		name:      "ErrUnexpectedDifficulty != ErrHighHash",
		err:       ErrUnexpectedDifficulty,
		target:    ErrHighHash,
		wantMatch: false,
		wantAs:    ErrUnexpectedDifficulty,
	}, {
		name:      "RuleError.ErrUnexpectedDifficulty != ErrHighHash",
		err:       ruleError(ErrUnexpectedDifficulty, ""),
		target:    ErrHighHash,
		wantMatch: false,
		wantAs:    ErrUnexpectedDifficulty,
	}, {
		name:      "ErrUnexpectedDifficulty != RuleError.ErrHighHash",
		err:       ErrUnexpectedDifficulty,
		target:    ruleError(ErrHighHash, ""),
		wantMatch: false,
		wantAs:    ErrUnexpectedDifficulty,
	}, {
		name:      "RuleError.ErrUnexpectedDifficulty != RuleError.ErrHighHash",
		err:       ruleError(ErrUnexpectedDifficulty, ""),
		target:    ruleError(ErrHighHash, ""),
		wantMatch: false,
		wantAs:    ErrUnexpectedDifficulty,
	}, {
		name:      "RuleError.ErrUnexpectedDifficulty != io.EOF",
		err:       ruleError(ErrUnexpectedDifficulty, ""),
		target:    io.EOF,
		wantMatch: false,
		wantAs:    ErrUnexpectedDifficulty,
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
