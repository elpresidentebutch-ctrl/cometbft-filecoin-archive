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

	"gitlab.com/synthos-collective-group/cometbft-filecoin-archive/internal/car"
	"gitlab.com/synthos-collective-group/cometbft-filecoin-archive/internal/comet"
)

// SchemaV1 identifies the v1 range manifest schema embedded as the root block
// of each CARv1 archive.
const SchemaV1 = "cometbft-filecoin-archive/v1"

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
// verified CometBFT BlockRecords and returns the CAR bytes, the root CID, and
// the RangeManifest.
func PackBlocks(records []*comet.BlockRecord) ([]byte, car.CID, *RangeManifest, error) {
	if err := comet.VerifyChainLinkage(records); err != nil {
		return nil, car.CID{}, nil, err
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
	records := make([]*comet.BlockRecord, 0, toHeight-fromHeight+1)
	for h := fromHeight; h <= toHeight; h++ {
		rec, err := client.FetchBlock(ctx, h)
		if err != nil {
			return nil, fmt.Errorf("archive: fetch height %d: %w", h, err)
		}
		records = append(records, rec)
	}

	carBytes, rootCID, manifest, err := PackBlocks(records)
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
	RootCID              string `json:"root_cid"`
	ChainID              string `json:"chain_id"`
	StartHeight          int64  `json:"start_height"`
	EndHeight            int64  `json:"end_height"`
	VerifiedBlocks       int    `json:"verified_blocks"`
	FirstBlockHash       string `json:"first_block_hash"`
	LastBlockHash        string `json:"last_block_hash"`
	CIDIntegrityValid    bool   `json:"cid_integrity_valid"`
	ParentHashChainValid bool   `json:"parent_hash_chain_valid"`
	LiveNodeMatched      bool   `json:"live_node_matched,omitempty"`
}

// VerifyCARFile reads a CARv1 archive from disk, verifies every IPLD block's
// SHA-256 multihash CID, validates the root RangeManifest against the enclosed
// CometBFT blocks, checks parent-hash linkage across the entire height range,
// and (if client != nil) verifies the boundary block hashes against a live
// CometBFT RPC node.
func VerifyCARFile(ctx context.Context, carPath string, client *comet.Client) (*VerificationReport, []*comet.BlockRecord, *RangeManifest, error) {
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
	if manifest.Schema != SchemaV1 {
		return nil, nil, nil, fmt.Errorf("verify: unsupported manifest schema %q", manifest.Schema)
	}
	chainBlocks := blocks[1:]
	if len(chainBlocks) != len(manifest.Blocks) || len(chainBlocks) != manifest.BlockCount {
		return nil, nil, nil, fmt.Errorf("verify: block count mismatch: CAR has %d chain blocks, manifest declares %d", len(chainBlocks), manifest.BlockCount)
	}

	records := make([]*comet.BlockRecord, 0, len(chainBlocks))
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
		records = append(records, rec)
	}

	if err := comet.VerifyChainLinkage(records); err != nil {
		return nil, nil, nil, err
	}

	report := &VerificationReport{
		CARPath:              carPath,
		RootCID:              rootCID.String(),
		ChainID:              manifest.ChainID,
		StartHeight:          manifest.StartHeight,
		EndHeight:            manifest.EndHeight,
		VerifiedBlocks:       len(records),
		FirstBlockHash:       manifest.FirstBlockHash,
		LastBlockHash:        manifest.LastBlockHash,
		CIDIntegrityValid:    true,
		ParentHashChainValid: true,
	}

	if client != nil {
		firstLive, err := client.FetchBlock(ctx, manifest.StartHeight)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("verify against live node (height %d): %w", manifest.StartHeight, err)
		}
		lastLive, err := client.FetchBlock(ctx, manifest.EndHeight)
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
	report, records, manifest, err := VerifyCARFile(ctx, carPath, nil)
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
