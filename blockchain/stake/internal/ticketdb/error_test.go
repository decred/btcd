// Copyright (c) 2014 Conformal Systems LLC.
// Copyright (c) 2015-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketdb

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
		{ErrUndoDataShortRead, "ErrUndoDataShortRead"},
		{ErrUndoDataCorrupt, "ErrUndoDataCorrupt"},
		{ErrTicketHashesShortRead, "ErrTicketHashesShortRead"},
		{ErrTicketHashesCorrupt, "ErrTicketHashesCorrupt"},
		{ErrUninitializedBucket, "ErrUninitializedBucket"},
		{ErrMissingKey, "ErrMissingKey"},
		{ErrChainStateShortRead, "ErrChainStateShortRead"},
		{ErrDatabaseInfoShortRead, "ErrDatabaseInfoShortRead"},
		{ErrLoadAllTickets, "ErrLoadAllTickets"},
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

// TestDBError tests the error output for the DBError type.
func TestDBError(t *testing.T) {
	tests := []struct {
		in   DBError
		want string
	}{{
		DBError{Description: "duplicate block"},
		"duplicate block",
	}, {
		DBError{Description: "human-readable error"},
		"human-readable error",
	}}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		result := test.in.Error()
		if result != test.want {
			t.Errorf("#%d: got: %s want: %s", i, result, test.want)
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
		name:      "ErrUndoDataShortRead == ErrUndoDataShortRead",
		err:       ErrUndoDataShortRead,
		target:    ErrUndoDataShortRead,
		wantMatch: true,
		wantAs:    ErrUndoDataShortRead,
	}, {
		name:      "DBError.ErrUndoDataShortRead == ErrUndoDataShortRead",
		err:       ticketDBError(ErrUndoDataShortRead, ""),
		target:    ErrUndoDataShortRead,
		wantMatch: true,
		wantAs:    ErrUndoDataShortRead,
	}, {
		name:      "DBError.ErrUndoDataShortRead == DBError.ErrUndoDataShortRead",
		err:       ticketDBError(ErrUndoDataShortRead, ""),
		target:    ticketDBError(ErrUndoDataShortRead, ""),
		wantMatch: true,
		wantAs:    ErrUndoDataShortRead,
	}, {
		name:      "ErrUndoDataShortRead != ErrUndoDataCorrupt",
		err:       ErrUndoDataShortRead,
		target:    ErrUndoDataCorrupt,
		wantMatch: false,
		wantAs:    ErrUndoDataShortRead,
	}, {
		name:      "DBError.ErrUndoDataShortRead != ErrUndoDataCorrupt",
		err:       ticketDBError(ErrUndoDataShortRead, ""),
		target:    ErrUndoDataCorrupt,
		wantMatch: false,
		wantAs:    ErrUndoDataShortRead,
	}, {
		name:      "ErrUndoDataShortRead != DBError.ErrUndoDataCorrupt",
		err:       ErrUndoDataShortRead,
		target:    ticketDBError(ErrUndoDataCorrupt, ""),
		wantMatch: false,
		wantAs:    ErrUndoDataShortRead,
	}, {
		name:      "DBError.ErrUndoDataShortRead != DBError.ErrUndoDataCorrupt",
		err:       ticketDBError(ErrUndoDataShortRead, ""),
		target:    ticketDBError(ErrUndoDataCorrupt, ""),
		wantMatch: false,
		wantAs:    ErrUndoDataShortRead,
	}, {
		name:      "DBError.ErrUndoDataShortRead != io.EOF",
		err:       ticketDBError(ErrUndoDataShortRead, ""),
		target:    io.EOF,
		wantMatch: false,
		wantAs:    ErrUndoDataShortRead,
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
		if !errors.Is(kind, test.wantAs) {
			t.Errorf("%s: unexpected unwrapped error kind -- got %v, want %v",
				test.name, kind, test.wantAs)
			continue
		}
	}
}
