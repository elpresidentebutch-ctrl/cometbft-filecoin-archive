package main

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	exampleCAR = "../../examples/synthos-mainnet-1/synthos-mainnet-1-000001-000100.car"
	genesis    = "../../examples/synthos-mainnet-1/genesis-validators.json"
)

// silence stops the commands' JSON output from cluttering test logs.
func silence(t *testing.T) {
	t.Helper()
	old := os.Stdout
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = devnull
	t.Cleanup(func() { os.Stdout = old; devnull.Close() })
}

func TestVerifyCommand(t *testing.T) {
	silence(t)
	if err := runVerify([]string{"--car", exampleCAR}); err != nil {
		t.Fatalf("plain verify: %v", err)
	}
	if err := runVerify([]string{"--car", exampleCAR, "--genesis", genesis}); err != nil {
		t.Fatalf("verify with genesis: %v", err)
	}
	// The v1 example has no commit for its last block, so --strict refuses it.
	if err := runVerify([]string{"--car", exampleCAR, "--genesis", genesis, "--strict"}); err == nil {
		t.Fatal("--strict should refuse a v1 archive")
	}
	if err := runVerify([]string{}); err == nil {
		t.Fatal("--car is required")
	}
}

func TestVerifyOptions(t *testing.T) {
	if _, err := verifyOptions("", "missing.json", "", false); err == nil {
		t.Fatal("missing genesis file must error")
	}
	if _, err := verifyOptions("", "", "zz", false); err == nil {
		t.Fatal("bad hex must error")
	}
	opts, err := verifyOptions("http://127.0.0.1:1", genesis, "0x40E599CBC6C9B5E14E45C5AE8D5E560BB5DFEF2AB25468E256BF1B3216EC29E6", true)
	if err != nil || opts.Client == nil || opts.GenesisValidators == nil || len(opts.TrustedValidatorsHash) != 32 || !opts.Strict {
		t.Fatalf("options not built: %+v %v", opts, err)
	}
}

func TestRestoreAndInspectCommands(t *testing.T) {
	silence(t)
	out := filepath.Join(t.TempDir(), "restored")
	if err := runRestore([]string{"--car", exampleCAR, "--out", out}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out, "blocks", "block_000100.json")); err != nil {
		t.Fatal(err)
	}
	if err := runInspect([]string{"--car", exampleCAR}); err != nil {
		t.Fatal(err)
	}
	if err := runRestore([]string{}); err == nil {
		t.Fatal("--car is required")
	}
	if err := runInspect([]string{}); err == nil {
		t.Fatal("--car is required")
	}
}

func TestArchiveCommandRejectsUnreachableNode(t *testing.T) {
	silence(t)
	err := runArchive([]string{"--rpc", "http://127.0.0.1:1", "--from", "1", "--to", "2", "--out", t.TempDir()})
	if err == nil {
		t.Fatal("an unreachable node must be an error")
	}
}
