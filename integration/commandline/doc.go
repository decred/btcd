// Copyright (c) 2018 The btcsuite developers
// Copyright (c) 2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

/*
Package commandline

Provides helpers to run external command-line tools,
e.g `go` code builder, `dcrd` and `dcrwallet` executables.

Ensures proper disposal of the external processes to avoid CPU leaks.

See `example_test.go` for the usage.

*/

package commandline
