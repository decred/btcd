package simpleregtest

import (
	"github.com/decred/dcrd/integration/harness"
	"testing"
)

func TestP2PConnect(t *testing.T) {
	// Skip tests when running with -short
	//if testing.Short() {
	//	t.Skip("Skipping RPC harness tests in short mode")
	//}
	r := ObtainHarness(mainHarnessName)

	// Create a fresh test harness.
	harness := testSetup.Regnet25.NewInstance("TestP2PConnect").(*harness.Harness)
	defer testSetup.Regnet25.Dispose(harness)

	// Establish a p2p connection from our new local harness to the main
	// harness.
	if err := ConnectNode(harness, r); err != nil {
		t.Fatalf("unable to connect local to main harness: %v", err)
	}

	// The main harness should show up in our local harness' peer's list,
	// and vice verse.
	assertConnectedTo(t, harness, r)
}
