// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package stdscript

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
		{ErrUnsupportedScriptVersion, "ErrUnsupportedScriptVersion"},
		{ErrTooManyRequiredSigs, "ErrTooManyRequiredSigs"},
		{ErrPubKeyType, "ErrPubKeyType"},
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
	}{{
		Error{Description: "some error"},
		"some error",
	}, {
		Error{Description: "human-readable error"},
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
		name:      "ErrUnsupportedScriptVersion == ErrUnsupportedScriptVersion",
		err:       ErrUnsupportedScriptVersion,
		target:    ErrUnsupportedScriptVersion,
		wantMatch: true,
		wantAs:    ErrUnsupportedScriptVersion,
	}, {
		name:      "Error.ErrUnsupportedScriptVersion == ErrUnsupportedScriptVersion",
		err:       makeError(ErrUnsupportedScriptVersion, ""),
		target:    ErrUnsupportedScriptVersion,
		wantMatch: true,
		wantAs:    ErrUnsupportedScriptVersion,
	}, {
		name:      "ErrTooManyRequiredSigs != ErrPubKeyType",
		err:       ErrTooManyRequiredSigs,
		target:    ErrPubKeyType,
		wantMatch: false,
		wantAs:    ErrTooManyRequiredSigs,
	}, {
		name:      "Error.ErrTooManyRequiredSigs != ErrPubKeyType",
		err:       makeError(ErrTooManyRequiredSigs, ""),
		target:    ErrPubKeyType,
		wantMatch: false,
		wantAs:    ErrTooManyRequiredSigs,
	}, {
		name:      "ErrTooManyRequiredSigs != Error.ErrPubKeyType",
		err:       ErrTooManyRequiredSigs,
		target:    makeError(ErrPubKeyType, ""),
		wantMatch: false,
		wantAs:    ErrTooManyRequiredSigs,
	}, {
		name:      "Error.ErrTooManyRequiredSigs != Error.ErrPubKeyType",
		err:       makeError(ErrTooManyRequiredSigs, ""),
		target:    makeError(ErrPubKeyType, ""),
		wantMatch: false,
		wantAs:    ErrTooManyRequiredSigs,
	}, {
		name:      "Error.ErrUnsupportedScriptVersion != io.EOF",
		err:       makeError(ErrUnsupportedScriptVersion, ""),
		target:    io.EOF,
		wantMatch: false,
		wantAs:    ErrUnsupportedScriptVersion,
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
