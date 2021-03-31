module github.com/decred/dcrd/wire

go 1.13

require (
	github.com/davecgh/go-spew v1.1.1
	github.com/decred/dcrd/addrmgr/v2 v2.0.0
	github.com/decred/dcrd/chaincfg/chainhash v1.0.2
)

replace github.com/decred/dcrd/addrmgr/v2 => ../addrmgr
