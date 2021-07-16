// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package spendpruner

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
		{ErrNoConsumer, "ErrNoConsumer"},
		{ErrLoadSpendDeps, "ErrLoadSpendDeps"},
		{ErrNeedSpendData, "ErrNeedSpendData"},
		{ErrUpdateConsumerDeps, "ErrUpdateConsumerDeps"},
	}

	for i, test := range tests {
		result := test.in.Error()
		if result != test.want {
			t.Errorf("%d: got: %s want: %s", i, result, test.want)
			continue
		}
	}
}

// TestPruneError tests the error output for the PruneError type.
func TestPruneError(t *testing.T) {
	tests := []struct {
		in   PruneError
		want string
	}{{
		PruneError{Description: "duplicate block"},
		"duplicate block",
	}, {
		PruneError{Description: "human-readable error"},
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

// TestPruneErrorKindIsAs ensures both ErrorKind and PruneError can be
// identified as being a specific error kind via errors.Is and unwrapped
// via errors.As.
func TestPruneErrorKindIsAs(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		target    error
		wantMatch bool
		wantAs    ErrorKind
	}{{
		name:      "ErrNoConsumer == ErrNoConsumer",
		err:       ErrNoConsumer,
		target:    ErrNoConsumer,
		wantMatch: true,
		wantAs:    ErrNoConsumer,
	}, {
		name:      "PruneError.ErrNoConsumer == ErrNoConsumer",
		err:       pruneError(ErrNoConsumer, ""),
		target:    ErrNoConsumer,
		wantMatch: true,
		wantAs:    ErrNoConsumer,
	}, {
		name:      "PruneError.ErrNoConsumer == PruneError.ErrNoConsumer",
		err:       pruneError(ErrNoConsumer, ""),
		target:    pruneError(ErrNoConsumer, ""),
		wantMatch: true,
		wantAs:    ErrNoConsumer,
	}, {
		name:      "ErrNoConsumer != ErrNeedSpendData",
		err:       ErrNoConsumer,
		target:    ErrNeedSpendData,
		wantMatch: false,
		wantAs:    ErrNoConsumer,
	}, {
		name:      "PruneError.ErrNoConsumer != ErrNeedSpendData",
		err:       pruneError(ErrNoConsumer, ""),
		target:    ErrNeedSpendData,
		wantMatch: false,
		wantAs:    ErrNoConsumer,
	}, {
		name:      "ErrNoConsumer != PruneError.ErrNeedSpendData",
		err:       ErrNoConsumer,
		target:    pruneError(ErrNeedSpendData, ""),
		wantMatch: false,
		wantAs:    ErrNoConsumer,
	}, {
		name:      "PruneError.ErrNoConsumer != PruneError.ErrNeedSpendData",
		err:       pruneError(ErrNoConsumer, ""),
		target:    pruneError(ErrNeedSpendData, ""),
		wantMatch: false,
		wantAs:    ErrNoConsumer,
	}, {
		name:      "PruneError.ErrNoConsumer != io.EOF",
		err:       pruneError(ErrNoConsumer, ""),
		target:    io.EOF,
		wantMatch: false,
		wantAs:    ErrNoConsumer,
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
