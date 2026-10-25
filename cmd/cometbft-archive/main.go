// Copyright 2026 James Isham Williams (SYNTHOS Collective)
// Dual-licensed under MIT or Apache-2.0 at your option.

// Command cometbft-archive packs CometBFT block ranges into IPLD CARv1
// archives for Filecoin storage deals, publishes a public height-range-to-CID
// index, and verifies and restores archived history.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gitlab.com/synthos-collective-group/cometbft-filecoin-archive/internal/archive"
	"gitlab.com/synthos-collective-group/cometbft-filecoin-archive/internal/comet"
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
  cometbft-archive verify  --car <path.car> [--rpc <url>]
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *carPath == "" {
		return fmt.Errorf("--car is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var client *comet.Client
	if *rpcURL != "" {
		client = comet.NewClient(*rpcURL)
	}
	report, _, _, err := archive.VerifyCARFile(ctx, *carPath, client)
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
		"ok":          true,
		"restored_to": *outDir,
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

	_, _, manifest, err := archive.VerifyCARFile(ctx, *carPath, nil)
	if err != nil {
		return err
	}
	return printJSON(manifest)
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
