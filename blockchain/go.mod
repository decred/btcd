module github.com/decred/dcrd/blockchain/v4

go 1.14

require (
	github.com/decred/dcrd/blockchain/stake/v4 v4.0.0-20210409183916-7f402345f0a6
	github.com/decred/dcrd/blockchain/standalone/v2 v2.0.0
	github.com/decred/dcrd/chaincfg/chainhash v1.0.2
	github.com/decred/dcrd/chaincfg/v3 v3.0.0
	github.com/decred/dcrd/database/v2 v2.0.3-0.20210514034330-bdccd3e3f7b0
	github.com/decred/dcrd/dcrec v1.0.0
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.0-20210127014238-b33b46cf1a24
	github.com/decred/dcrd/dcrutil/v4 v4.0.0-20210129181600-6ae0142d3b28
	github.com/decred/dcrd/gcs/v3 v3.0.0-20210129195202-a4265d63b619
	github.com/decred/dcrd/lru v1.1.0
	github.com/decred/dcrd/txscript/v4 v4.0.0-20210415215133-96b98390a9a9
	github.com/decred/dcrd/wire v1.4.0
	github.com/decred/slog v1.1.0
	github.com/syndtr/goleveldb v1.0.1-0.20200815110645-5c35d600f0ca
)

replace (
	github.com/decred/dcrd/blockchain/stake/v4 => ./stake
	github.com/decred/dcrd/blockchain/standalone/v2 => ./standalone
	github.com/decred/dcrd/database/v2 => ../database
	github.com/decred/dcrd/dcrec/secp256k1/v4 => ../dcrec/secp256k1
	github.com/decred/dcrd/dcrutil/v4 => ../dcrutil
	github.com/decred/dcrd/gcs/v3 => ../gcs
	github.com/decred/dcrd/lru => ../lru
	github.com/decred/dcrd/txscript/v4 => ../txscript
)
