module github.com/decred/dcrd/connmgr/v3

go 1.13

require (
	github.com/decred/dcrd/peer/v2 v2.2.0
	github.com/decred/dcrd/wire v1.4.0
	github.com/decred/go-socks v1.1.0
	github.com/decred/slog v1.1.0
)

replace (
	github.com/decred/dcrd/dcrec/secp256k1/v4 => ../dcrec/secp256k1
	github.com/decred/dcrd/dcrutil/v4 => ../dcrutil
	github.com/decred/dcrd/peer/v2 => ../peer
	github.com/decred/dcrd/txscript/v4 => ../txscript
)
