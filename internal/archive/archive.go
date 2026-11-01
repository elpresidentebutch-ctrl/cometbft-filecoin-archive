// Copyright 2026 James Isham Williams (SYNTHOS Collective)
// Dual-licensed under MIT or Apache-2.0 at your option.

// Package archive packs ranges of CometBFT blocks into IPLD CARv1 archives,
// maintains the public height-range-to-CID index, and verifies and restores
// archived block ranges.
package archive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/elpresidentebutch-ctrl/cometbft-filecoin-archive/internal/car"
	"github.com/elpresidentebutch-ctrl/cometbft-filecoin-archive/internal/comet"
)

// SchemaV1 identifies v1 archives: the manifest plus the blocks.
const SchemaV1 = "cometbft-filecoin-archive/v1"

// SchemaV2 archives also carry what is needed to check validator signatures
// offline: the validator set behind every validators_hash in the range and
// the commit for the last block.
const SchemaV2 = "cometbft-filecoin-archive/v2"

// BlockDescriptor summarizes a single CometBFT block inside a RangeManifest.
type BlockDescriptor struct {
	Height        int64  `json:"height"`
	BlockHash     string `json:"block_hash"`
	LastBlockHash string `json:"last_block_hash"`
	Time          string `json:"time"`
	AppHash       string `json:"app_hash,omitempty"`
	TxCount       int    `json:"tx_count"`
	CID           string `json:"cid"`
	SizeBytes     int    `json:"size_bytes"`
}

// RangeManifest is serialized as canonical JSON and stored as the root IPLD
// block of a CARv1 archive.
type RangeManifest struct {
	Schema         string            `json:"schema"`
	ChainID        string            `json:"chain_id"`
	StartHeight    int64             `json:"start_height"`
	EndHeight      int64             `json:"end_height"`
	BlockCount     int               `json:"block_count"`
	FirstBlockHash string            `json:"first_block_hash"`
	LastBlockHash  string            `json:"last_block_hash"`
	FirstBlockTime string            `json:"first_block_time"`
	LastBlockTime  string            `json:"last_block_time"`
	Blocks         []BlockDescriptor `json:"blocks"`
	// v2 only.
	ValidatorSets []ArtifactRef `json:"validator_sets,omitempty"`
	FinalCommit   *ArtifactRef  `json:"final_commit,omitempty"`
}

// ArtifactRef points at an extra CAR block: a /validators response (Hash is
// the validators_hash it must produce) or the /commit for the last height.
type ArtifactRef struct {
	Height int64  `json:"height"`
	Hash   string `json:"hash,omitempty"`
	CID    string `json:"cid"`
}

// Extras is the signature-checking material packed into a v2 archive.
type Extras struct {
	// ValidatorSets maps an upper-case validators_hash to a merged
	// /validators response and the height it was fetched at.
	ValidatorSets map[string]FetchedValidators
	// FinalCommit is the /commit response for the last height in the range.
	FinalCommit []byte
}

// FetchedValidators is a /validators response and the height it describes.
type FetchedValidators struct {
	Height int64
	Raw    []byte
}

// IndexEntry maps a block height range to its CARv1 root CID, file metadata,
// and optional Filecoin deal records.
type IndexEntry struct {
	ChainID        string   `json:"chain_id"`
	StartHeight    int64    `json:"start_height"`
	EndHeight      int64    `json:"end_height"`
	BlockCount     int      `json:"block_count"`
	RootCID        string   `json:"root_cid"`
	CARFile        string   `json:"car_file"`
	CARSHA256      string   `json:"car_sha256"`
	CARSizeBytes   int64    `json:"car_size_bytes"`
	FirstBlockHash string   `json:"first_block_hash"`
	LastBlockHash  string   `json:"last_block_hash"`
	FirstBlockTime string   `json:"first_block_time"`
	LastBlockTime  string   `json:"last_block_time"`
	FilecoinDeals  []string `json:"filecoin_deals,omitempty"`
	ArchivedAt     string   `json:"archived_at"`
}

// IndexFile is the public JSON index mapping block height ranges to Filecoin
// CAR root CIDs.
type IndexFile struct {
	Schema    string       `json:"schema"`
	ChainID   string       `json:"chain_id"`
	UpdatedAt string       `json:"updated_at"`
	Ranges    []IndexEntry `json:"ranges"`
}

// PackBlocks builds a deterministic CARv1 byte stream from an ordered slice of
// CometBFT blocks and returns the CAR bytes, the root CID, and the
// RangeManifest. Every block's hashes are recomputed first. With extras it
// writes a v2 archive that can be signature-checked offline; with nil
// extras, a v1 archive.
func PackBlocks(records []*comet.BlockRecord, extras *Extras) ([]byte, car.CID, *RangeManifest, error) {
	if err := comet.VerifyChainLinkage(records); err != nil {
		return nil, car.CID{}, nil, err
	}
	for _, rec := range records {
		fb, err := comet.ParseFullBlock(rec.RawJSON)
		if err != nil {
			return nil, car.CID{}, nil, fmt.Errorf("archive: height %d: %w", rec.Height, err)
		}
		if err := fb.Check(); err != nil {
			return nil, car.CID{}, nil, fmt.Errorf("archive: %w", err)
		}
	}

	descriptors := make([]BlockDescriptor, 0, len(records))
	ipldBlocks := make([]car.Block, 0, len(records)+1)

	for _, rec := range records {
		blkCID := car.NewCID(car.CodecRaw, rec.RawJSON)
		descriptors = append(descriptors, BlockDescriptor{
			Height:        rec.Height,
			BlockHash:     rec.BlockHash,
			LastBlockHash: rec.LastBlockHash,
			Time:          rec.Time,
			AppHash:       rec.AppHash,
			TxCount:       rec.TxCount,
			CID:           blkCID.String(),
			SizeBytes:     len(rec.RawJSON),
		})
		ipldBlocks = append(ipldBlocks, car.Block{
			CID:  blkCID,
			Data: rec.RawJSON,
		})
	}

	first := records[0]
	last := records[len(records)-1]
	manifest := &RangeManifest{
		Schema:         SchemaV1,
		ChainID:        first.ChainID,
		StartHeight:    first.Height,
		EndHeight:      last.Height,
		BlockCount:     len(records),
		FirstBlockHash: first.BlockHash,
		LastBlockHash:  last.BlockHash,
		FirstBlockTime: first.Time,
		LastBlockTime:  last.Time,
		Blocks:         descriptors,
	}

	if extras != nil {
		manifest.Schema = SchemaV2
		hashes := make([]string, 0, len(extras.ValidatorSets))
		for h := range extras.ValidatorSets {
			hashes = append(hashes, h)
		}
		sort.Strings(hashes)
		for _, h := range hashes {
			fv := extras.ValidatorSets[h]
			cid := car.NewCID(car.CodecRaw, fv.Raw)
			manifest.ValidatorSets = append(manifest.ValidatorSets, ArtifactRef{Height: fv.Height, Hash: h, CID: cid.String()})
			ipldBlocks = append(ipldBlocks, car.Block{CID: cid, Data: fv.Raw})
		}
		if len(extras.FinalCommit) > 0 {
			cid := car.NewCID(car.CodecRaw, extras.FinalCommit)
			manifest.FinalCommit = &ArtifactRef{Height: last.Height, CID: cid.String()}
			ipldBlocks = append(ipldBlocks, car.Block{CID: cid, Data: extras.FinalCommit})
		}
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, car.CID{}, nil, fmt.Errorf("archive: marshal manifest: %w", err)
	}
	rootCID := car.NewCID(car.CodecRaw, manifestBytes)

	// Place the root manifest block first in the CARv1 stream, followed by the
	// ordered CometBFT blocks.
	allBlocks := make([]car.Block, 0, len(ipldBlocks)+1)
	allBlocks = append(allBlocks, car.Block{
		CID:  rootCID,
		Data: manifestBytes,
	})
	allBlocks = append(allBlocks, ipldBlocks...)

	var buf bytes.Buffer
	if err := car.WriteCAR(&buf, rootCID, allBlocks); err != nil {
		return nil, car.CID{}, nil, err
	}
	return buf.Bytes(), rootCID, manifest, nil
}

// ArchiveRange fetches blocks [fromHeight..toHeight] from a CometBFT RPC node,
// packs them into a CARv1 file inside outDir, and updates indexPath.
func ArchiveRange(ctx context.Context, client *comet.Client, fromHeight, toHeight int64, outDir, indexPath string) (*IndexEntry, error) {
	if fromHeight <= 0 || toHeight < fromHeight {
		return nil, fmt.Errorf("archive: invalid height range %d..%d", fromHeight, toHeight)
	}
	var err error
	records := make([]*comet.BlockRecord, 0, toHeight-fromHeight+1)
	for h := fromHeight; h <= toHeight; h++ {
		rec, err := client.FetchBlock(ctx, h)
		if err != nil {
			return nil, fmt.Errorf("archive: fetch height %d: %w", h, err)
		}
		records = append(records, rec)
	}

	// Fetch the validator set behind each validators_hash in the range, and
	// the commit that finalizes the last block, so signatures can be
	// checked later without a live node.
	extras := &Extras{ValidatorSets: map[string]FetchedValidators{}}
	for _, rec := range records {
		if _, ok := extras.ValidatorSets[rec.ValidatorsHash]; ok {
			continue
		}
		raw, err := client.FetchValidators(ctx, rec.Height)
		if err != nil {
			return nil, fmt.Errorf("archive: validators at height %d: %w", rec.Height, err)
		}
		vs, err := comet.ParseValidators(raw)
		if err != nil {
			return nil, fmt.Errorf("archive: validators at height %d: %w", rec.Height, err)
		}
		if got := fmt.Sprintf("%X", vs.Hash()); got != rec.ValidatorsHash {
			return nil, fmt.Errorf("archive: validators at height %d hash to %s, header says %s", rec.Height, got, rec.ValidatorsHash)
		}
		extras.ValidatorSets[rec.ValidatorsHash] = FetchedValidators{Height: rec.Height, Raw: raw}
	}
	if extras.FinalCommit, err = client.FetchCommit(ctx, toHeight); err != nil {
		return nil, fmt.Errorf("archive: commit for height %d: %w", toHeight, err)
	}

	carBytes, rootCID, manifest, err := PackBlocks(records, extras)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("archive: create output dir: %w", err)
	}
	carFileName := fmt.Sprintf("%s-%06d-%06d.car", sanitizeFileComponent(manifest.ChainID), manifest.StartHeight, manifest.EndHeight)
	carFullPath := filepath.Join(outDir, carFileName)
	if err := os.WriteFile(carFullPath, carBytes, 0o644); err != nil {
		return nil, fmt.Errorf("archive: write CAR file: %w", err)
	}

	sum := sha256.Sum256(carBytes)
	entry := &IndexEntry{
		ChainID:        manifest.ChainID,
		StartHeight:    manifest.StartHeight,
		EndHeight:      manifest.EndHeight,
		BlockCount:     manifest.BlockCount,
		RootCID:        rootCID.String(),
		CARFile:        carFileName,
		CARSHA256:      hex.EncodeToString(sum[:]),
		CARSizeBytes:   int64(len(carBytes)),
		FirstBlockHash: manifest.FirstBlockHash,
		LastBlockHash:  manifest.LastBlockHash,
		FirstBlockTime: manifest.FirstBlockTime,
		LastBlockTime:  manifest.LastBlockTime,
		ArchivedAt:     time.Now().UTC().Format(time.RFC3339),
	}

	if indexPath != "" {
		if err := UpsertIndex(indexPath, *entry); err != nil {
			return nil, err
		}
	}
	return entry, nil
}

// UpsertIndex loads (or initializes) the public JSON index at indexPath,
// inserts or updates the entry for [entry.StartHeight..entry.EndHeight], and
// writes the index atomically.
func UpsertIndex(indexPath string, entry IndexEntry) error {
	var idx IndexFile
	if raw, err := os.ReadFile(indexPath); err == nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, &idx)
	}
	idx.Schema = SchemaV1
	idx.ChainID = entry.ChainID
	idx.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	replaced := false
	for i, existing := range idx.Ranges {
		if existing.ChainID == entry.ChainID && existing.StartHeight == entry.StartHeight && existing.EndHeight == entry.EndHeight {
			idx.Ranges[i] = entry
			replaced = true
			break
		}
	}
	if !replaced {
		idx.Ranges = append(idx.Ranges, entry)
	}
	sort.Slice(idx.Ranges, func(i, j int) bool {
		return idx.Ranges[i].StartHeight < idx.Ranges[j].StartHeight
	})

	if err := os.MkdirAll(filepath.Dir(indexPath), 0o755); err != nil {
		return fmt.Errorf("archive: mkdir for index: %w", err)
	}
	out, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return os.WriteFile(indexPath, out, 0o644)
}

// VerificationReport summarizes the result of verifying a CARv1 archive.
type VerificationReport struct {
	CARPath              string `json:"car_path"`
	Schema               string `json:"schema"`
	RootCID              string `json:"root_cid"`
	ChainID              string `json:"chain_id"`
	StartHeight          int64  `json:"start_height"`
	EndHeight            int64  `json:"end_height"`
	VerifiedBlocks       int    `json:"verified_blocks"`
	FirstBlockHash       string `json:"first_block_hash"`
	LastBlockHash        string `json:"last_block_hash"`
	CIDIntegrityValid    bool   `json:"cid_integrity_valid"`
	ParentHashChainValid bool   `json:"parent_hash_chain_valid"`
	// HeaderHashesValid: every block hash, data_hash and last_commit_hash
	// was recomputed from the block's own contents and matched.
	HeaderHashesValid bool `json:"header_hashes_valid"`
	// CommitsVerified counts blocks whose finalizing commit carried valid
	// signatures from more than 2/3 of their validator set's voting power.
	CommitsVerified int `json:"commits_verified"`
	// AllCommitsVerified is true when every block in the range was checked.
	AllCommitsVerified bool `json:"all_commits_verified"`
	// ValidatorSetAnchored is true when the validator sets used trace back,
	// through signed headers, to a set you supplied (--genesis or
	// --trusted-validators-hash). Without it, the signatures only prove the
	// archive is internally consistent, not that it is the real chain.
	ValidatorSetAnchored bool     `json:"validator_set_anchored"`
	TrustAnchor          string   `json:"trust_anchor,omitempty"`
	LiveNodeMatched      bool     `json:"live_node_matched,omitempty"`
	Warnings             []string `json:"warnings,omitempty"`
}

// VerifyOptions controls how far VerifyCARFile goes.
type VerifyOptions struct {
	// Client, when set, cross-checks the boundary block hashes with a live node.
	Client *comet.Client
	// GenesisChainID and GenesisValidators trust the chain's genesis
	// validator set (parsed from a CometBFT genesis.json).
	GenesisChainID    string
	GenesisValidators *comet.ValidatorSet
	// TrustedValidatorsHash trusts a validator set by its hash.
	TrustedValidatorsHash []byte
	// Strict fails verification unless every block's commit was checked
	// against an anchored validator set.
	Strict bool
}

// VerifyCARFile reads a CARv1 archive and verifies it without trusting its
// producer: every IPLD block's CID; the manifest; every block hash,
// data_hash and last_commit_hash recomputed from the block contents; the
// parent-hash chain; and, where a validator set is available, the validator
// signatures that finalized each block. Options add a trust anchor for the
// validator set and a live-node cross-check.
func VerifyCARFile(ctx context.Context, carPath string, opts VerifyOptions) (*VerificationReport, []*comet.BlockRecord, *RangeManifest, error) {
	f, err := os.Open(carPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("verify: open %s: %w", carPath, err)
	}
	defer f.Close()

	hdr, blocks, err := car.ReadCAR(f)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("verify: read CAR %s: %w", carPath, err)
	}
	if len(hdr.Roots) != 1 {
		return nil, nil, nil, fmt.Errorf("verify: expected 1 root CID in CAR header, got %d", len(hdr.Roots))
	}
	if len(blocks) < 2 {
		return nil, nil, nil, fmt.Errorf("verify: CAR contains %d blocks (expected root manifest + >=1 chain block)", len(blocks))
	}
	rootCID := hdr.Roots[0]
	if blocks[0].CID != rootCID {
		return nil, nil, nil, fmt.Errorf("verify: first block CID %s does not match header root CID %s", blocks[0].CID.String(), rootCID.String())
	}

	var manifest RangeManifest
	if err := json.Unmarshal(blocks[0].Data, &manifest); err != nil {
		return nil, nil, nil, fmt.Errorf("verify: unmarshal root manifest: %w", err)
	}
	if manifest.Schema != SchemaV1 && manifest.Schema != SchemaV2 {
		return nil, nil, nil, fmt.Errorf("verify: unsupported manifest schema %q", manifest.Schema)
	}
	extraCount := len(manifest.ValidatorSets)
	if manifest.FinalCommit != nil {
		extraCount++
	}
	if manifest.Schema == SchemaV1 && extraCount > 0 {
		return nil, nil, nil, fmt.Errorf("verify: v1 manifest lists v2 artifacts")
	}
	if len(manifest.Blocks) != manifest.BlockCount || len(blocks)-1 != manifest.BlockCount+extraCount {
		return nil, nil, nil, fmt.Errorf("verify: block count mismatch: CAR has %d blocks after the manifest, manifest declares %d chain blocks + %d extras", len(blocks)-1, manifest.BlockCount, extraCount)
	}
	chainBlocks := blocks[1 : 1+manifest.BlockCount]
	extraBlocks := blocks[1+manifest.BlockCount:]

	records := make([]*comet.BlockRecord, 0, len(chainBlocks))
	full := make([]*comet.FullBlock, 0, len(chainBlocks))
	for i, blk := range chainBlocks {
		desc := manifest.Blocks[i]
		if blk.CID.String() != desc.CID {
			return nil, nil, nil, fmt.Errorf("verify: block %d CID mismatch: got %s, manifest expects %s", i, blk.CID.String(), desc.CID)
		}
		rec, err := comet.ParseBlockJSON(blk.Data)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("verify: parse CometBFT block at index %d: %w", i, err)
		}
		if rec.Height != desc.Height || !strings.EqualFold(rec.BlockHash, desc.BlockHash) {
			return nil, nil, nil, fmt.Errorf("verify: block %d header mismatch against manifest descriptor", i)
		}
		fb, err := comet.ParseFullBlock(blk.Data)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("verify: height %d: %w", rec.Height, err)
		}
		// The hash a block claims is only trusted once it is recomputed
		// from the header; otherwise a forged chain with made-up hashes
		// that point at each other would pass.
		if err := fb.Check(); err != nil {
			return nil, nil, nil, fmt.Errorf("verify: %w", err)
		}
		records = append(records, rec)
		full = append(full, fb)
	}
	if err := comet.VerifyChainLinkage(records); err != nil {
		return nil, nil, nil, err
	}
	if records[0].ChainID != manifest.ChainID || records[0].Height != manifest.StartHeight || records[len(records)-1].Height != manifest.EndHeight ||
		!strings.EqualFold(records[0].BlockHash, manifest.FirstBlockHash) || !strings.EqualFold(records[len(records)-1].BlockHash, manifest.LastBlockHash) {
		return nil, nil, nil, fmt.Errorf("verify: manifest summary does not match the blocks it contains")
	}

	report := &VerificationReport{
		CARPath:              carPath,
		Schema:               manifest.Schema,
		RootCID:              rootCID.String(),
		ChainID:              manifest.ChainID,
		StartHeight:          manifest.StartHeight,
		EndHeight:            manifest.EndHeight,
		VerifiedBlocks:       len(records),
		FirstBlockHash:       manifest.FirstBlockHash,
		LastBlockHash:        manifest.LastBlockHash,
		CIDIntegrityValid:    true,
		ParentHashChainValid: true,
		HeaderHashesValid:    true,
	}

	// Signature-checking material: validator sets carried by a v2 archive
	// (each must hash to the validators_hash it claims) and/or supplied by
	// the caller.
	valsets := map[string]*comet.ValidatorSet{}
	for i, ref := range manifest.ValidatorSets {
		blk := extraBlocks[i]
		if blk.CID.String() != ref.CID {
			return nil, nil, nil, fmt.Errorf("verify: validator set %d CID mismatch", i)
		}
		vs, err := comet.ParseValidators(blk.Data)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("verify: validator set at height %d: %w", ref.Height, err)
		}
		got := fmt.Sprintf("%X", vs.Hash())
		if !strings.EqualFold(got, ref.Hash) {
			return nil, nil, nil, fmt.Errorf("verify: validator set at height %d hashes to %s, manifest says %s", ref.Height, got, ref.Hash)
		}
		valsets[got] = vs
	}
	var finalCommit *comet.Commit
	if ref := manifest.FinalCommit; ref != nil {
		blk := extraBlocks[len(extraBlocks)-1]
		if blk.CID.String() != ref.CID {
			return nil, nil, nil, fmt.Errorf("verify: final commit CID mismatch")
		}
		h, c, err := comet.ParseSignedHeader(blk.Data)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("verify: final commit: %w", err)
		}
		if last := full[len(full)-1]; fmt.Sprintf("%X", h.Hash()) != fmt.Sprintf("%X", last.BlockID.Hash) {
			return nil, nil, nil, fmt.Errorf("verify: final commit's header does not match block %d", last.Header.Height)
		}
		finalCommit = c
	}
	trusted := map[string]string{}
	if opts.GenesisValidators != nil {
		if opts.GenesisChainID != "" && opts.GenesisChainID != manifest.ChainID {
			return nil, nil, nil, fmt.Errorf("verify: genesis is for chain %q, archive is %q", opts.GenesisChainID, manifest.ChainID)
		}
		h := fmt.Sprintf("%X", opts.GenesisValidators.Hash())
		valsets[h] = opts.GenesisValidators
		trusted[h] = "genesis validator set"
	}
	if len(opts.TrustedValidatorsHash) > 0 {
		trusted[fmt.Sprintf("%X", opts.TrustedValidatorsHash)] = "trusted validators hash"
	}

	// Walk the range like a light client: a block is anchored when its
	// validator set is trusted, or when the previous, already-verified
	// header committed to that set as its next_validators_hash.
	anchored := len(full) > 0
	prevAnchored := false
	unchecked := 0
	for i, b := range full {
		h := b.Header.Height
		vh := fmt.Sprintf("%X", b.Header.ValidatorsHash)
		vs := valsets[vh]
		if vs == nil {
			unchecked++
			prevAnchored = false
			continue
		}
		var commit *comet.Commit
		if i+1 < len(full) {
			commit = full[i+1].LastCommit
		} else {
			commit = finalCommit
		}
		if commit == nil || len(commit.Signatures) == 0 {
			unchecked++
			prevAnchored = false
			continue
		}
		if err := comet.VerifyCommit(manifest.ChainID, vs, b.BlockID, h, commit); err != nil {
			return nil, nil, nil, fmt.Errorf("verify: %w", err)
		}
		report.CommitsVerified++
		here := false
		if src, ok := trusted[vh]; ok {
			here = true
			if report.TrustAnchor == "" {
				report.TrustAnchor = fmt.Sprintf("%s at height %d", src, h)
			}
		} else if i > 0 && prevAnchored && strings.EqualFold(fmt.Sprintf("%X", full[i-1].Header.NextValidatorsHash), vh) {
			here = true
		}
		prevAnchored = here
		anchored = anchored && here
	}
	report.AllCommitsVerified = unchecked == 0
	report.ValidatorSetAnchored = anchored && report.CommitsVerified > 0
	if unchecked > 0 {
		report.Warnings = append(report.Warnings, fmt.Sprintf("%d of %d blocks' signatures were not checked: their validator set or finalizing commit is not in this archive (v1 archives need --genesis; the last block of a v1 archive has no commit)", unchecked, len(full)))
	}
	if !report.ValidatorSetAnchored && report.CommitsVerified > 0 {
		report.Warnings = append(report.Warnings, "signatures are valid, but the validator set is not anchored to one you trust; pass --genesis <genesis.json> or --trusted-validators-hash to prove this is the real chain")
	}
	if opts.Strict && (!report.AllCommitsVerified || !report.ValidatorSetAnchored) {
		return nil, nil, nil, fmt.Errorf("verify: --strict: %s", strings.Join(report.Warnings, "; "))
	}

	if opts.Client != nil {
		firstLive, err := opts.Client.FetchBlock(ctx, manifest.StartHeight)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("verify against live node (height %d): %w", manifest.StartHeight, err)
		}
		lastLive, err := opts.Client.FetchBlock(ctx, manifest.EndHeight)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("verify against live node (height %d): %w", manifest.EndHeight, err)
		}
		if !strings.EqualFold(firstLive.BlockHash, manifest.FirstBlockHash) {
			return nil, nil, nil, fmt.Errorf("verify: live block %d hash %s != archived hash %s", manifest.StartHeight, firstLive.BlockHash, manifest.FirstBlockHash)
		}
		if !strings.EqualFold(lastLive.BlockHash, manifest.LastBlockHash) {
			return nil, nil, nil, fmt.Errorf("verify: live block %d hash %s != archived hash %s", manifest.EndHeight, lastLive.BlockHash, manifest.LastBlockHash)
		}
		report.LiveNodeMatched = true
	}

	return report, records, &manifest, nil
}

// RestoreCARFile verifies a CARv1 archive and writes its verified CometBFT
// block JSON payloads and range manifest to outDir.
func RestoreCARFile(ctx context.Context, carPath, outDir string) (*VerificationReport, error) {
	report, records, manifest, err := VerifyCARFile(ctx, carPath, VerifyOptions{})
	if err != nil {
		return nil, err
	}
	blocksDir := filepath.Join(outDir, "blocks")
	if err := os.MkdirAll(blocksDir, 0o755); err != nil {
		return nil, fmt.Errorf("restore: mkdir %s: %w", blocksDir, err)
	}
	for _, rec := range records {
		name := filepath.Join(blocksDir, fmt.Sprintf("block_%06d.json", rec.Height))
		if err := os.WriteFile(name, rec.RawJSON, 0o644); err != nil {
			return nil, fmt.Errorf("restore: write %s: %w", name, err)
		}
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(outDir, "manifest.json"), append(manifestBytes, '\n'), 0o644); err != nil {
		return nil, err
	}
	return report, nil
}

func sanitizeFileComponent(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "cometbft"
	}
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return b.String()
}
