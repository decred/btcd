// Copyright (c) 2018 The btcsuite developers
// Copyright (c) 2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package gobuilder

import (
	"os"
	"testing"

	"github.com/decred/dcrd/integration"
)

// TestGoBuider builds current project executable
func TestGoBuider(t *testing.T) {
	defer integration.VerifyNoAssetsLeaked()
	runExample()
}

func runExample() {
	testWorkingDir := integration.NewTempDir(os.TempDir(), "test-go-builder")

	testWorkingDir.MakeDir()
	defer testWorkingDir.Dispose()

	builder := &GoBuider{
		GoProjectPath:    DetermineProjectPackagePath("dcrd"),
		OutputFolderPath: testWorkingDir.Path(),
		BuildFileName:    "dcrd",
	}

	builder.Build()
	defer builder.Dispose()
}
