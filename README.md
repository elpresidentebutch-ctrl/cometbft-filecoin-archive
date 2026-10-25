# CometBFT Chain Archive on Filecoin

A zero-dependency Go command-line tool and library that archives a CometBFT blockchain's blocks into content-addressed IPLD **CARv1** (`.car`) files for Filecoin storage deals, maintains a public height-range-to-CID index (`index.json`), and cryptographically verifies and restores archived history without trusting a single server.

First production deployment: **[SYNTHOS Collective (`synthos-mainnet-1`)](https://gitlab.com/synthos-collective-group/synthos-collective)**.

---

## Features & Commands

- **`archive`**: Queries a CometBFT node's RPC endpoint (`/block?height=H`), verifies contiguous heights and parent block hash linkage (`header.last_block_id.hash == parent.block_id.hash`), computes SHA2-256 **CIDv1** (`bafkrei...`) identifiers for every block and for the range manifest, writes a deterministic **CARv1** file (`<chain-id>-<from>-<to>.car`), and updates the public `index.json`.
- **`verify`**: Reads a `.car` archive, recomputes and verifies the SHA2-256 multihash CIDv1 of every IPLD block in the stream, validates the embedded `RangeManifest`, verifies the full CometBFT parent-hash chain across the range, and optionally cross-checks boundary block hashes against a live CometBFT RPC endpoint.
- **`restore`**: Verifies a `.car` archive and extracts the verified CometBFT block JSON payloads (`blocks/block_<height>.json`) and `manifest.json` so a fresh node or indexer can inspect or replay the archived history.
- **`inspect`**: Prints the verified `RangeManifest` embedded in the root block of a `.car` archive.

---

## Quick Start

### 1. Archive a range of CometBFT blocks into a `.car` file

```bash
go run ./cmd/cometbft-archive archive \
  --rpc http://127.0.0.1:26657 \
  --from 1 \
  --to 100 \
  --out ./examples/synthos-mainnet-1 \
  --index ./examples/synthos-mainnet-1/index.json
```

### 2. Verify a `.car` archive (offline + against a live CometBFT node)

```bash
go run ./cmd/cometbft-archive verify \
  --car ./examples/synthos-mainnet-1/synthos-mainnet-1-000001-000100.car \
  --rpc http://127.0.0.1:26657
```

### 3. Restore verified blocks from a `.car` archive

```bash
go run ./cmd/cometbft-archive restore \
  --car ./examples/synthos-mainnet-1/synthos-mainnet-1-000001-000100.car \
  --out ./restored
```

### 4. Run unit tests

```bash
go test -v ./...
```

---

## Architecture & Repository Layout

```text
cometbft-filecoin-archive/
├── cmd/
│   └── cometbft-archive/     # CLI entrypoint (archive, verify, restore, inspect)
├── internal/
│   ├── car/                  # IPLD CARv1 binary encoder/decoder & CIDv1 (SHA2-256)
│   ├── comet/                # CometBFT RPC fetcher & parent-hash chain verifier
│   └── archive/              # RangeManifest packager, index.json manager & restorer
└── examples/
    └── synthos-mainnet-1/    # Real archived CARv1 range (blocks 1..100) + index.json
```

---

## License

Dual-licensed under either of:

- MIT license ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.

## Contributions

This project is maintained by James Isham Williams and does not accept outside code contributions. Bug reports are welcome as issues.
