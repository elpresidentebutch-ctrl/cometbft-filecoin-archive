# CometBFT Chain Archive on Filecoin

A zero-dependency Go command-line tool and library that archives a CometBFT blockchain's blocks into content-addressed IPLD **CARv1** (`.car`) files for Filecoin storage deals, maintains a public height-range-to-CID index (`index.json`), and verifies and restores archived history.

Verification doesn't take the archive's word for anything: it recomputes every block hash from its header and checks the validators' signatures on every block. Anchored to the chain's genesis validator set, that proves an archive is the real chain without trusting whoever produced or stored it.

First production deployment: **[Synthos Collective (`synthos-mainnet-1`)](https://github.com/elpresidentebutch-ctrl/synthos-collective)**.

---

## Features & Commands

- **`archive`**: Fetches blocks from a CometBFT node's RPC (`/block?height=H`), recomputes each block's hashes, checks contiguous heights and parent-hash links, and writes a deterministic **CARv1** file (`<chain-id>-<from>-<to>.car`) with SHA2-256 **CIDv1** (`bafkrei...`) identifiers for every block and the range manifest. It also stores the validator set behind every `validators_hash` in the range (`/validators`) and the commit for the last block (`/commit`), so the archive can be signature-checked offline (archive format v2). It updates the public `index.json`.
- **`verify`**: Reads a `.car` archive and checks, in order:
  1. the SHA2-256 CID of every IPLD block, and the embedded `RangeManifest`;
  2. every **block hash recomputed from its header** (CometBFT v0.38 Merkle hashing), plus each block's `data_hash` from its transactions and `last_commit_hash` from its commit;
  3. the parent-hash chain across the range;
  4. the **validators' precommit signatures** on every block, which must carry more than 2/3 of the voting power. Each validator set must hash to the header's `validators_hash`;
  5. that those validator sets trace back to one you trust (`--genesis genesis.json` or `--trusted-validators-hash`), following each signed header's `next_validators_hash`, the way a CometBFT light client does.

  `--strict` fails unless every block was signature-checked against an anchored validator set. `--rpc` additionally compares the first and last block hashes with a live node.
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

### 2. Verify a `.car` archive

```bash
go run ./cmd/cometbft-archive verify \
  --car ./examples/synthos-mainnet-1/synthos-mainnet-1-000001-000100.car \
  --genesis ./examples/synthos-mainnet-1/genesis-validators.json
```

The report says what was proven:

| Field | Meaning |
| --- | --- |
| `header_hashes_valid` | Every block hash, `data_hash` and `last_commit_hash` was recomputed and matched |
| `commits_verified` | Blocks whose signatures from more than 2/3 of the voting power were checked |
| `all_commits_verified` | Every block in the range was signature-checked |
| `validator_set_anchored` | The validator sets trace back to your `--genesis` or `--trusted-validators-hash` |
| `warnings` | Anything that was not checked, and why |

Without `--genesis` or `--trusted-validators-hash`, valid signatures only show the archive is internally consistent: a forger could sign a fake chain with their own keys. The anchor is what ties it to the real chain.

The example is a v1 archive (made before v2 existed), so it doesn't contain the commit for its last block: verify checks blocks 1–99 and reports block 100 as unchecked. Archives made with the current `archive` command are v2 and check every block.

### 3. Restore verified blocks from a `.car` archive

```bash
go run ./cmd/cometbft-archive restore \
  --car ./examples/synthos-mainnet-1/synthos-mainnet-1-000001-000100.car \
  --out ./restored
```

### 4. Install or run the tests

```bash
go install github.com/elpresidentebutch-ctrl/cometbft-filecoin-archive/cmd/cometbft-archive@latest
go test -race ./...
```

---

## Architecture & Repository Layout

```text
cometbft-filecoin-archive/
├── cmd/
│   └── cometbft-archive/     # CLI entrypoint (archive, verify, restore, inspect)
├── internal/
│   ├── car/                  # IPLD CARv1 binary encoder/decoder & CIDv1 (SHA2-256)
│   ├── comet/                # CometBFT RPC client, header/commit hashing & signature checks
│   └── archive/              # RangeManifest packager, index.json manager & restorer
└── examples/
    └── synthos-mainnet-1/    # Real archived CARv1 range (blocks 1..100), index.json
                              # and the genesis validator set (genesis-validators.json)
```

---

## License

Dual-licensed under either of:

- MIT license ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.

## Contributions

This project is maintained by James Isham Williams and does not accept outside code contributions. Bug reports are welcome as issues.
