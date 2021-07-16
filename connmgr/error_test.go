// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package connmgr

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
		{ErrDialNil, "ErrDialNil"},
		{ErrBothDialsFilled, "ErrBothDialsFilled"},
		{ErrTorInvalidAddressResponse, "ErrTorInvalidAddressResponse"},
		{ErrTorInvalidProxyResponse, "ErrTorInvalidProxyResponse"},
		{ErrTorUnrecognizedAuthMethod, "ErrTorUnrecognizedAuthMethod"},
		{ErrTorGeneralError, "ErrTorGeneralError"},
		{ErrTorNotAllowed, "ErrTorNotAllowed"},
		{ErrTorNetUnreachable, "ErrTorNetUnreachable"},
		{ErrTorHostUnreachable, "ErrTorHostUnreachable"},
		{ErrTorConnectionRefused, "ErrTorConnectionRefused"},
		{ErrTorTTLExpired, "ErrTorTTLExpired"},
		{ErrTorCmdNotSupported, "ErrTorCmdNotSupported"},
		{ErrTorAddrNotSupported, "ErrTorAddrNotSupported"},
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
		name:      "ErrDialNil == ErrDialNil",
		err:       ErrDialNil,
		target:    ErrDialNil,
		wantMatch: true,
		wantAs:    ErrDialNil,
	}, {
		name:      "Error.ErrDialNil == ErrDialNil",
		err:       MakeError(ErrDialNil, ""),
		target:    ErrDialNil,
		wantMatch: true,
		wantAs:    ErrDialNil,
	}, {
		name:      "Error.ErrDialNil == Error.ErrDialNil",
		err:       MakeError(ErrDialNil, ""),
		target:    MakeError(ErrDialNil, ""),
		wantMatch: true,
		wantAs:    ErrDialNil,
	}, {
		name:      "ErrBothDialsFilled != ErrDialNil",
		err:       ErrBothDialsFilled,
		target:    ErrDialNil,
		wantMatch: false,
		wantAs:    ErrBothDialsFilled,
	}, {
		name:      "Error.ErrBothDialsFilled != ErrDialNil",
		err:       MakeError(ErrBothDialsFilled, ""),
		target:    ErrDialNil,
		wantMatch: false,
		wantAs:    ErrBothDialsFilled,
	}, {
		name:      "ErrBothDialsFilled != Error.ErrDialNil",
		err:       ErrBothDialsFilled,
		target:    MakeError(ErrDialNil, ""),
		wantMatch: false,
		wantAs:    ErrBothDialsFilled,
	}, {
		name:      "Error.ErrBothDialsFilled != Error.ErrDialNil",
		err:       MakeError(ErrBothDialsFilled, ""),
		target:    MakeError(ErrDialNil, ""),
		wantMatch: false,
		wantAs:    ErrBothDialsFilled,
	}, {
		name:      "Error.ErrBothDialsFilled != io.EOF",
		err:       MakeError(ErrBothDialsFilled, ""),
		target:    io.EOF,
		wantMatch: false,
		wantAs:    ErrBothDialsFilled,
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
