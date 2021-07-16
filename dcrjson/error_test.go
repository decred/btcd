// Copyright (c) 2014 The btcsuite developers
// Copyright (c) 2015-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package dcrjson

import (
	"errors"
	"io"
	"testing"
)

// TestErrorKindStringer tests the stringized output for the ErrorKind type.
func TestErrorKindStringer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   ErrorKind
		want string
	}{
		{ErrDuplicateMethod, "ErrDuplicateMethod"},
		{ErrInvalidUsageFlags, "ErrInvalidUsageFlags"},
		{ErrInvalidType, "ErrInvalidType"},
		{ErrEmbeddedType, "ErrEmbeddedType"},
		{ErrUnexportedField, "ErrUnexportedField"},
		{ErrUnsupportedFieldType, "ErrUnsupportedFieldType"},
		{ErrNonOptionalField, "ErrNonOptionalField"},
		{ErrNonOptionalDefault, "ErrNonOptionalDefault"},
		{ErrMismatchedDefault, "ErrMismatchedDefault"},
		{ErrUnregisteredMethod, "ErrUnregisteredMethod"},
		{ErrNumParams, "ErrNumParams"},
		{ErrMissingDescription, "ErrMissingDescription"},
	}

	for i, test := range tests {
		result := test.in.Error()
		if result != test.want {
			t.Errorf("%d: got: %s want: %s", i, result, test.want)
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
	}{{
		Error{Description: "some error"},
		"some error",
	}, {
		Error{Description: "human-readable error"},
		"human-readable error",
	}}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		result := test.in.Error()
		if result != test.want {
			t.Errorf("Error #%d\n got: %s want: %s", i, result,
				test.want)
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
		name:      "ErrDuplicateMethod == ErrDuplicateMethod",
		err:       ErrDuplicateMethod,
		target:    ErrDuplicateMethod,
		wantMatch: true,
		wantAs:    ErrDuplicateMethod,
	}, {
		name:      "Error.ErrDuplicateMethod == ErrDuplicateMethod",
		err:       makeError(ErrDuplicateMethod, ""),
		target:    ErrDuplicateMethod,
		wantMatch: true,
		wantAs:    ErrDuplicateMethod,
	}, {
		name:      "Error.ErrDuplicateMethod == Error.ErrDuplicateMethod",
		err:       makeError(ErrDuplicateMethod, ""),
		target:    makeError(ErrDuplicateMethod, ""),
		wantMatch: true,
		wantAs:    ErrDuplicateMethod,
	}, {
		name:      "ErrDuplicateMethod != ErrInvalidType",
		err:       ErrDuplicateMethod,
		target:    ErrInvalidType,
		wantMatch: false,
		wantAs:    ErrDuplicateMethod,
	}, {
		name:      "Error.ErrDuplicateMethod != ErrInvalidType",
		err:       makeError(ErrDuplicateMethod, ""),
		target:    ErrInvalidType,
		wantMatch: false,
		wantAs:    ErrDuplicateMethod,
	}, {
		name:      "ErrDuplicateMethod != Error.ErrInvalidType",
		err:       ErrDuplicateMethod,
		target:    makeError(ErrInvalidType, ""),
		wantMatch: false,
		wantAs:    ErrDuplicateMethod,
	}, {
		name:      "Error.ErrDuplicateMethod != Error.ErrInvalidType",
		err:       makeError(ErrDuplicateMethod, ""),
		target:    makeError(ErrInvalidType, ""),
		wantMatch: false,
		wantAs:    ErrDuplicateMethod,
	}, {
		name:      "Error.ErrUnregisteredMethod != io.EOF",
		err:       makeError(ErrUnregisteredMethod, ""),
		target:    io.EOF,
		wantMatch: false,
		wantAs:    ErrUnregisteredMethod,
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
