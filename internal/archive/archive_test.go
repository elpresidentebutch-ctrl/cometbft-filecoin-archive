package archive

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"gitlab.com/synthos-collective-group/cometbft-filecoin-archive/internal/comet"
)

func syntheticBlockRecord(t *testing.T, height int64, hash, lastHash string) *comet.BlockRecord {
	t.Helper()
	raw := []byte(fmt.Sprintf(`{
  "result": {
    "block_id": { "hash": %q },
    "block": {
      "header": {
        "chain_id": "synthos-mainnet-1",
        "height": "%d",
        "time": "2026-10-25T00:00:%02dZ",
        "app_hash": "46D84A42F285BF45578A9E409C874DFC6E825F60129BEE51A2BFCCB8F77165E9",
        "validators_hash": "AABBCCDD",
        "last_block_id": { "hash": %q }
      },
      "data": { "txs": [] }
    }
  }
}`, hash, height, height, lastHash))
	rec, err := comet.ParseBlockJSON(raw)
	if err != nil {
		t.Fatalf("ParseBlockJSON(%d): %v", height, err)
	}
	return rec
}

func TestPackVerifyAndRestoreCAR(t *testing.T) {
	b1 := syntheticBlockRecord(t, 1, "84396F133C4EC2BE2BB99280386151A8D1BB6CACA7AE559DF50B7FA25DE522E9", "")
	b2 := syntheticBlockRecord(t, 2, "1111111111111111111111111111111111111111111111111111111111111111", b1.BlockHash)
	b3 := syntheticBlockRecord(t, 3, "2222222222222222222222222222222222222222222222222222222222222222", b2.BlockHash)

	carBytes, rootCID, manifest, err := PackBlocks([]*comet.BlockRecord{b1, b2, b3})
	if err != nil {
		t.Fatalf("PackBlocks failed: %v", err)
	}
	if manifest.BlockCount != 3 || manifest.StartHeight != 1 || manifest.EndHeight != 3 {
		t.Fatalf("unexpected manifest summary: %+v", manifest)
	}

	tmpDir := t.TempDir()
	carPath := filepath.Join(tmpDir, "synthos-mainnet-1-000001-000003.car")
	if err := os.WriteFile(carPath, carBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	report, records, _, err := VerifyCARFile(context.Background(), carPath, nil)
	if err != nil {
		t.Fatalf("VerifyCARFile failed: %v", err)
	}
	if !report.CIDIntegrityValid || !report.ParentHashChainValid || report.RootCID != rootCID.String() || len(records) != 3 {
		t.Fatalf("unexpected verification report: %+v", report)
	}

	restoreDir := filepath.Join(tmpDir, "restored")
	if _, err := RestoreCARFile(context.Background(), carPath, restoreDir); err != nil {
		t.Fatalf("RestoreCARFile failed: %v", err)
	}
	for h := 1; h <= 3; h++ {
		p := filepath.Join(restoreDir, "blocks", fmt.Sprintf("block_%06d.json", h))
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected restored block file %s: %v", p, err)
		}
	}
}

func TestBrokenParentHashRejected(t *testing.T) {
	b1 := syntheticBlockRecord(t, 1, "AAAA", "")
	b2 := syntheticBlockRecord(t, 2, "BBBB", "WRONG_PARENT_HASH")
	if _, _, _, err := PackBlocks([]*comet.BlockRecord{b1, b2}); err == nil {
		t.Fatal("expected PackBlocks to reject broken parent-hash link")
	}
}
