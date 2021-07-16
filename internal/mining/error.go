// Copyright (c) 2015-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mining

// ErrorKind identifies a kind of error.  It has full support for errors.Is
// and errors.As, so the caller can directly check against an error kind
// when determining the reason for an error.
type ErrorKind string

// These constants are used to identify a specific RuleError.
const (
	// ErrNotEnoughVoters indicates that there were not enough voters to
	// build a block on top of HEAD.
	ErrNotEnoughVoters = ErrorKind("ErrNotEnoughVoters")

	// ErrFailedToGetGeneration specifies that the current generation for
	// a block could not be obtained from blockchain.
	ErrFailedToGetGeneration = ErrorKind("ErrFailedToGetGeneration")

	// ErrGetTopBlock indicates that the current top block of the
	// blockchain could not be obtained.
	ErrGetTopBlock = ErrorKind("ErrGetTopBlock")

	// ErrGettingDifficulty indicates that there was an error getting the
	// PoW difficulty.
	ErrGettingDifficulty = ErrorKind("ErrGettingDifficulty")

	// ErrTransactionAppend indicates there was a problem adding a msgtx
	// to a msgblock.
	ErrTransactionAppend = ErrorKind("ErrTransactionAppend")

	// ErrTicketExhaustion indicates that there will not be enough mature
	// tickets by the end of the next ticket maturity period to progress the
	// chain.
	ErrTicketExhaustion = ErrorKind("ErrTicketExhaustion")

	// ErrCheckConnectBlock indicates that a newly created block template
	// failed blockchain.CheckConnectBlock.
	ErrCheckConnectBlock = ErrorKind("ErrCheckConnectBlock")

	// ErrFraudProofIndex indicates that there was an error finding the index
	// for a fraud proof.
	ErrFraudProofIndex = ErrorKind("ErrFraudProofIndex")

	// ErrFetchTxStore indicates a transaction store failed to fetch.
	ErrFetchTxStore = ErrorKind("ErrFetchTxStore")

	// ErrCalcCommitmentRoot indicates that creating the header commitments and
	// calculating the associated commitment root for a newly created block
	// template failed.
	ErrCalcCommitmentRoot = ErrorKind("ErrCalcCommitmentRoot")
)

// Error satisfies the error interface and prints human-readable errors.
func (e ErrorKind) Error() string {
	return string(e)
}

// Error identifies a mining rule rule violation. It has full support for
// errors.Is and errors.As, so the caller can ascertain the specific reason
// for the error by checking the underlying error. It is used to indicate
// that processing of a block or transaction failed due to one of the many
// validation rules.
type Error struct {
	Err         error
	Description string
}

// Error satisfies the error interface and prints human-readable errors.
func (e Error) Error() string {
	return e.Description
}

// Unwrap returns the underlying wrapped error.
func (e Error) Unwrap() error {
	return e.Err
}

// makeError creates an Error given a set of arguments.
func makeError(kind ErrorKind, desc string) Error {
	return Error{Err: kind, Description: desc}
}
