# CometBFT Chain Archive on Filecoin

A command-line tool, written in Go, that archives a CometBFT chain's blocks and state snapshots on Filecoin, so any node can download and verify the chain's history without trusting a single server.

Planned commands:

- `archive`: pack block ranges and snapshots into CAR files, store them on Filecoin, and publish a height range to CID index.
- `verify`: fetch an archived range from Filecoin and check every block hash and its link to the previous block.
- `restore`: rebuild a fresh node's block store from the Filecoin archive.

First deployment: [SYNTHOS Collective](https://gitlab.com/synthos-collective-group/synthos-collective).

## Status

Planning stage. Code will land here as the milestones are built.

## License

Dual-licensed under either of

- MIT license ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.

## Contributions

This project is maintained by James Isham Williams and does not accept outside code contributions. Bug reports are welcome as issues.
