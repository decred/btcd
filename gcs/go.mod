module github.com/decred/dcrd/gcs/v3

go 1.13

require (
	github.com/dchest/siphash v1.2.1
	github.com/decred/dcrd/blockchain/stake/v4 v4.0.0
	github.com/decred/dcrd/chaincfg/chainhash v1.0.2
	github.com/decred/dcrd/crypto/blake256 v1.0.0
	github.com/decred/dcrd/txscript/v4 v4.0.0
	github.com/decred/dcrd/wire v1.4.0
)

replace (
	github.com/decred/dcrd/blockchain/stake/v4 => ../blockchain/stake
	github.com/decred/dcrd/txscript/v4 => ../txscript
)
