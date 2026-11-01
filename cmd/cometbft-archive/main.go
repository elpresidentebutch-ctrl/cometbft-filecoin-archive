// Copyright 2026 James Isham Williams (SYNTHOS Collective)
// Dual-licensed under MIT or Apache-2.0 at your option.

// Command cometbft-archive packs CometBFT block ranges into IPLD CARv1
// archives for Filecoin storage deals, publishes a public height-range-to-CID
// index, and verifies and restores archived history.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/elpresidentebutch-ctrl/cometbft-filecoin-archive/internal/archive"
	"github.com/elpresidentebutch-ctrl/cometbft-filecoin-archive/internal/comet"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "archive":
		err = runArchive(args)
	case "verify":
		err = runVerify(args)
	case "restore":
		err = runRestore(args)
	case "inspect":
		err = runInspect(args)
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `cometbft-archive — CometBFT Chain Archive on Filecoin (CARv1)

Usage:
  cometbft-archive archive --rpc <url> --from <height> --to <height> [--out ./archives] [--index ./archives/index.json]
  cometbft-archive verify  --car <path.car> [--genesis genesis.json | --trusted-validators-hash HEX] [--strict] [--rpc <url>]
  cometbft-archive restore --car <path.car> --out <dir>
  cometbft-archive inspect --car <path.car>
`)
}

func runArchive(args []string) error {
	fs := flag.NewFlagSet("archive", flag.ExitOnError)
	rpcURL := fs.String("rpc", "http://127.0.0.1:26657", "CometBFT HTTP RPC endpoint")
	from := fs.Int64("from", 1, "starting block height (inclusive)")
	to := fs.Int64("to", 100, "ending block height (inclusive)")
	outDir := fs.String("out", "./archives", "output directory for .car files")
	indexPath := fs.String("index", "", "path to index.json (defaults to <out>/index.json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *indexPath == "" {
		*indexPath = filepath.Join(*outDir, "index.json")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	client := comet.NewClient(*rpcURL)
	entry, err := archive.ArchiveRange(ctx, client, *from, *to, *outDir, *indexPath)
	if err != nil {
		return err
	}
	return printJSON(entry)
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	carPath := fs.String("car", "", "path to .car file to verify")
	rpcURL := fs.String("rpc", "", "optional CometBFT RPC endpoint to cross-check boundary hashes")
	genesisPath := fs.String("genesis", "", "the chain's CometBFT genesis.json: trust its validator set as the anchor for signature checks")
	trustedHash := fs.String("trusted-validators-hash", "", "hex validators_hash you trust as the anchor (for ranges that don't start at genesis)")
	strict := fs.Bool("strict", false, "fail unless every block's signatures were checked against an anchored validator set")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *carPath == "" {
		return fmt.Errorf("--car is required")
	}
	opts, err := verifyOptions(*rpcURL, *genesisPath, *trustedHash, *strict)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	report, _, _, err := archive.VerifyCARFile(ctx, *carPath, opts)
	if err != nil {
		return err
	}
	return printJSON(report)
}

func runRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	carPath := fs.String("car", "", "path to .car file to restore from")
	outDir := fs.String("out", "./restored", "target directory for restored block files")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *carPath == "" {
		return fmt.Errorf("--car is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	report, err := archive.RestoreCARFile(ctx, *carPath, *outDir)
	if err != nil {
		return err
	}
	return printJSON(map[string]any{
		"ok":           true,
		"restored_to":  *outDir,
		"verification": report,
	})
}

func runInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	carPath := fs.String("car", "", "path to .car file to inspect")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *carPath == "" {
		return fmt.Errorf("--car is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	_, _, manifest, err := archive.VerifyCARFile(ctx, *carPath, archive.VerifyOptions{})
	if err != nil {
		return err
	}
	return printJSON(manifest)
}

// verifyOptions builds verification options from the verify command's flags.
func verifyOptions(rpcURL, genesisPath, trustedHash string, strict bool) (archive.VerifyOptions, error) {
	opts := archive.VerifyOptions{Strict: strict}
	if rpcURL != "" {
		opts.Client = comet.NewClient(rpcURL)
	}
	if genesisPath != "" {
		raw, err := os.ReadFile(genesisPath)
		if err != nil {
			return opts, fmt.Errorf("--genesis: %w", err)
		}
		chainID, vs, err := comet.ParseGenesisValidators(raw)
		if err != nil {
			return opts, fmt.Errorf("--genesis: %w", err)
		}
		opts.GenesisChainID, opts.GenesisValidators = chainID, vs
	}
	if trustedHash != "" {
		b, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(trustedHash), "0x"))
		if err != nil || len(b) != 32 {
			return opts, fmt.Errorf("--trusted-validators-hash must be 32 bytes of hex")
		}
		opts.TrustedValidatorsHash = b
	}
	return opts, nil
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
