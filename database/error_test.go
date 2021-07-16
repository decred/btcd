// Copyright (c) 2015-2016 The btcsuite developers
// Copyright (c) 2016-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package database

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
		{ErrDbTypeRegistered, "ErrDbTypeRegistered"},
		{ErrDbUnknownType, "ErrDbUnknownType"},
		{ErrDbDoesNotExist, "ErrDbDoesNotExist"},
		{ErrDbExists, "ErrDbExists"},
		{ErrDbNotOpen, "ErrDbNotOpen"},
		{ErrDbAlreadyOpen, "ErrDbAlreadyOpen"},
		{ErrInvalid, "ErrInvalid"},
		{ErrCorruption, "ErrCorruption"},
		{ErrTxClosed, "ErrTxClosed"},
		{ErrTxNotWritable, "ErrTxNotWritable"},
		{ErrBucketNotFound, "ErrBucketNotFound"},
		{ErrBucketExists, "ErrBucketExists"},
		{ErrBucketNameRequired, "ErrBucketNameRequired"},
		{ErrKeyRequired, "ErrKeyRequired"},
		{ErrKeyTooLarge, "ErrKeyTooLarge"},
		{ErrValueTooLarge, "ErrValueTooLarge"},
		{ErrIncompatibleValue, "ErrIncompatibleValue"},
		{ErrValueNotFound, "ErrValueNotFound"},
		{ErrBlockNotFound, "ErrBlockNotFound"},
		{ErrBlockExists, "ErrBlockExists"},
		{ErrBlockRegionInvalid, "ErrBlockRegionInvalid"},
		{ErrDriverSpecific, "ErrDriverSpecific"},
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
		name:      "ErrDbTypeRegistered == ErrDbTypeRegistered",
		err:       ErrDbTypeRegistered,
		target:    ErrDbTypeRegistered,
		wantMatch: true,
		wantAs:    ErrDbTypeRegistered,
	}, {
		name:      "Error.ErrDbTypeRegistered == ErrDbTypeRegistered",
		err:       makeError(ErrDbTypeRegistered, ""),
		target:    ErrDbTypeRegistered,
		wantMatch: true,
		wantAs:    ErrDbTypeRegistered,
	}, {
		name:      "Error.ErrDbTypeRegistered == Error.ErrDbTypeRegistered",
		err:       makeError(ErrDbTypeRegistered, ""),
		target:    makeError(ErrDbTypeRegistered, ""),
		wantMatch: true,
		wantAs:    ErrDbTypeRegistered,
	}, {
		name:      "ErrBucketNotFound != ErrDbTypeRegistered",
		err:       ErrBucketNotFound,
		target:    ErrDbTypeRegistered,
		wantMatch: false,
		wantAs:    ErrBucketNotFound,
	}, {
		name:      "Error.ErrBucketNotFound != ErrDbTypeRegistered",
		err:       makeError(ErrBucketNotFound, ""),
		target:    ErrDbTypeRegistered,
		wantMatch: false,
		wantAs:    ErrBucketNotFound,
	}, {
		name:      "ErrBucketNotFound != Error.ErrDbTypeRegistered",
		err:       ErrBucketNotFound,
		target:    makeError(ErrDbTypeRegistered, ""),
		wantMatch: false,
		wantAs:    ErrBucketNotFound,
	}, {
		name:      "Error.ErrBucketNotFound != Error.ErrDbTypeRegistered",
		err:       makeError(ErrBucketNotFound, ""),
		target:    makeError(ErrDbTypeRegistered, ""),
		wantMatch: false,
		wantAs:    ErrBucketNotFound,
	}, {
		name:      "Error.ErrKeyRequired != io.EOF",
		err:       makeError(ErrKeyRequired, ""),
		target:    io.EOF,
		wantMatch: false,
		wantAs:    ErrKeyRequired,
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
