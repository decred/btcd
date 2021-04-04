module github.com/decred/dcrd/peer/v3

go 1.11

require (
	github.com/davecgh/go-spew v1.1.1
	github.com/decred/dcrd/addrmgr/v2 v2.0.0
	github.com/decred/dcrd/chaincfg/chainhash v1.0.2
	github.com/decred/dcrd/lru v1.1.0
	github.com/decred/dcrd/txscript/v4 v4.0.0-20210129190127-4ebd135a82f1
	github.com/decred/dcrd/wire v1.4.0
	github.com/decred/go-socks v1.1.0
	github.com/decred/slog v1.1.0
)

replace (
	github.com/decred/dcrd/addrmgr/v2 => ../addrmgr
	github.com/decred/dcrd/dcrec/secp256k1/v4 => ../dcrec/secp256k1
	github.com/decred/dcrd/dcrutil/v4 => ../dcrutil
	github.com/decred/dcrd/txscript/v4 => ../txscript
)
