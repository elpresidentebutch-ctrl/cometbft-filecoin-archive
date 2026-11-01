package archive

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitlab.com/synthos-collective-group/cometbft-filecoin-archive/internal/car"
	"gitlab.com/synthos-collective-group/cometbft-filecoin-archive/internal/comet"
)

const (
	exampleDir     = "../../examples/synthos-mainnet-1"
	exampleCARFile = exampleDir + "/synthos-mainnet-1-000001-000100.car"
	genesisFile    = exampleDir + "/genesis-validators.json"
)

// realBlocks returns the raw /block JSON of synthos-mainnet-1 blocks 1..100.
func realBlocks(t *testing.T) [][]byte {
	t.Helper()
	f, err := os.Open(exampleCARFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	_, blocks, err := car.ReadCAR(f)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for _, b := range blocks[1:] {
		out = append(out, b.Data)
	}
	return out
}

func records(t *testing.T, raws [][]byte) []*comet.BlockRecord {
	t.Helper()
	var out []*comet.BlockRecord
	for _, raw := range raws {
		rec, err := comet.ParseBlockJSON(raw)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, rec)
	}
	return out
}

func genesisOpts(t *testing.T) VerifyOptions {
	t.Helper()
	raw, err := os.ReadFile(genesisFile)
	if err != nil {
		t.Fatal(err)
	}
	chainID, vs, err := comet.ParseGenesisValidators(raw)
	if err != nil {
		t.Fatal(err)
	}
	return VerifyOptions{GenesisChainID: chainID, GenesisValidators: vs}
}

func writeCAR(t *testing.T, carBytes []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "range.car")
	if err := os.WriteFile(p, carBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// fakeNode serves real mainnet blocks 1..100, their validator set, and a
// /commit for height 99 built from block 100's last_commit.
func fakeNode(t *testing.T) *httptest.Server {
	t.Helper()
	blocks := realBlocks(t)
	vals, err := json.Marshal(map[string]any{"result": map[string]any{"total": "2", "validators": []map[string]any{
		{"address": "2EFA14D4903A1644185FA63E9E5F1B1872F664F6", "pub_key": map[string]string{"type": "tendermint/PubKeyEd25519", "value": "tEybm7cpmLphGbSZX6E6MMM5ejbGq6zEFcRyBR7Okb4="}, "voting_power": "1000000"},
		{"address": "80756DB8674D0D8F08843626B18051236979E7E8", "pub_key": map[string]string{"type": "tendermint/PubKeyEd25519", "value": "jJMGArhq1xdA3z6O3kySqKtr4fpAN8+Qu1aou3X2vKk="}, "voting_power": "1000000"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	type blockEnv struct {
		Result struct {
			Block struct {
				Header     json.RawMessage `json:"header"`
				LastCommit json.RawMessage `json:"last_commit"`
			} `json:"block"`
		} `json:"result"`
	}
	var b99, b100 blockEnv
	if err := json.Unmarshal(blocks[98], &b99); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(blocks[99], &b100); err != nil {
		t.Fatal(err)
	}
	commit99, err := json.Marshal(map[string]any{"result": map[string]any{"signed_header": map[string]any{
		"header": b99.Result.Block.Header, "commit": b100.Result.Block.LastCommit,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var h int
		fmt.Sscan(r.URL.Query().Get("height"), &h)
		switch {
		case r.URL.Path == "/block" && h >= 1 && h <= len(blocks):
			w.Write(blocks[h-1])
		case r.URL.Path == "/validators":
			w.Write(vals)
		case r.URL.Path == "/commit" && h == 99:
			w.Write(commit99)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestExampleArchiveVerifiesAgainstGenesis(t *testing.T) {
	report, recs, _, err := VerifyCARFile(context.Background(), exampleCARFile, genesisOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	if !report.HeaderHashesValid || report.CommitsVerified != 99 || !report.ValidatorSetAnchored || len(recs) != 100 {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.AllCommitsVerified || len(report.Warnings) == 0 {
		t.Fatal("a v1 archive has no commit for its last block; that must be reported")
	}
}

func TestArchiveRangeV2VerifiesEveryCommitOffline(t *testing.T) {
	srv := fakeNode(t)
	out := t.TempDir()
	index := filepath.Join(out, "index.json")
	entry, err := ArchiveRange(context.Background(), comet.NewClient(srv.URL), 1, 99, out, index)
	if err != nil {
		t.Fatal(err)
	}
	carPath := filepath.Join(out, entry.CARFile)

	opts := genesisOpts(t)
	opts.Strict = true
	opts.Client = comet.NewClient(srv.URL)
	report, _, manifest, err := VerifyCARFile(context.Background(), carPath, opts)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Schema != SchemaV2 || len(manifest.ValidatorSets) != 1 || manifest.FinalCommit == nil {
		t.Fatalf("v2 artifacts missing: %+v", manifest)
	}
	if report.CommitsVerified != 99 || !report.AllCommitsVerified || !report.ValidatorSetAnchored || !report.LiveNodeMatched || len(report.Warnings) != 0 {
		t.Fatalf("unexpected report: %+v", report)
	}

	// Without a trust anchor the signatures still check out, but the report
	// must say they aren't anchored, and --strict must refuse.
	report, _, _, err = VerifyCARFile(context.Background(), carPath, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if report.ValidatorSetAnchored || report.CommitsVerified != 99 || len(report.Warnings) == 0 {
		t.Fatalf("unanchored archive reported as anchored: %+v", report)
	}
	if _, _, _, err := VerifyCARFile(context.Background(), carPath, VerifyOptions{Strict: true}); err == nil {
		t.Fatal("--strict must refuse an unanchored archive")
	}

	// A wrong-chain genesis is refused outright.
	wrong := genesisOpts(t)
	wrong.GenesisChainID = "other-chain"
	if _, _, _, err := VerifyCARFile(context.Background(), carPath, wrong); err == nil {
		t.Fatal("genesis for another chain must be refused")
	}

	idx, err := os.ReadFile(index)
	if err != nil || !bytes.Contains(idx, []byte(entry.RootCID)) {
		t.Fatalf("index not written: %v", err)
	}
}

func TestRestoreWritesVerifiedBlocks(t *testing.T) {
	recs := records(t, realBlocks(t)[:5])
	carBytes, _, _, err := PackBlocks(recs, nil)
	if err != nil {
		t.Fatal(err)
	}
	carPath := writeCAR(t, carBytes)
	dir := filepath.Join(t.TempDir(), "restored")
	if _, err := RestoreCARFile(context.Background(), carPath, dir); err != nil {
		t.Fatal(err)
	}
	for h := 1; h <= 5; h++ {
		raw, err := os.ReadFile(filepath.Join(dir, "blocks", fmt.Sprintf("block_%06d.json", h)))
		if err != nil || !bytes.Equal(raw, recs[h-1].RawJSON) {
			t.Fatalf("block %d not restored byte for byte: %v", h, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "manifest.json")); err != nil {
		t.Fatal(err)
	}
}

// The old verifier trusted each block's stated hash. A fake chain whose
// made-up hashes point at each other must now be rejected.
func TestFakeChainWithMadeUpHashesIsRejected(t *testing.T) {
	fake := func(h int, hash, parent string) []byte {
		return []byte(fmt.Sprintf(`{"result":{"block_id":{"hash":%q,"parts":{"total":1,"hash":""}},"block":{"header":{"version":{"block":"11","app":"1"},"chain_id":"synthos-mainnet-1","height":"%d","time":"2026-10-25T00:00:0%dZ","last_block_id":{"hash":%q,"parts":{"total":1,"hash":""}},"last_commit_hash":"","data_hash":"E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855","validators_hash":"40E599CBC6C9B5E14E45C5AE8D5E560BB5DFEF2AB25468E256BF1B3216EC29E6","next_validators_hash":"","consensus_hash":"","app_hash":"","last_results_hash":"","evidence_hash":"","proposer_address":""},"data":{"txs":[]}}}}`, hash, h, h, parent))
	}
	raws := [][]byte{
		fake(1, "1111111111111111111111111111111111111111111111111111111111111111", ""),
		fake(2, "2222222222222222222222222222222222222222222222222222222222222222", "1111111111111111111111111111111111111111111111111111111111111111"),
	}
	recs := records(t, raws)
	if err := comet.VerifyChainLinkage(recs); err != nil {
		t.Fatalf("test setup: the fake chain's links should line up: %v", err)
	}
	if _, _, _, err := PackBlocks(recs, nil); err == nil || !strings.Contains(err.Error(), "header hashes to") {
		t.Fatalf("PackBlocks must recompute hashes, got %v", err)
	}

	// Build the CAR by hand, as a forger would, and make sure verify catches it.
	manifest := RangeManifest{Schema: SchemaV1, ChainID: "synthos-mainnet-1", StartHeight: 1, EndHeight: 2, BlockCount: 2,
		FirstBlockHash: recs[0].BlockHash, LastBlockHash: recs[1].BlockHash}
	var blocks []car.Block
	for _, r := range recs {
		cid := car.NewCID(car.CodecRaw, r.RawJSON)
		manifest.Blocks = append(manifest.Blocks, BlockDescriptor{Height: r.Height, BlockHash: r.BlockHash, LastBlockHash: r.LastBlockHash, CID: cid.String()})
		blocks = append(blocks, car.Block{CID: cid, Data: r.RawJSON})
	}
	mb, _ := json.Marshal(manifest)
	root := car.NewCID(car.CodecRaw, mb)
	var buf bytes.Buffer
	if err := car.WriteCAR(&buf, root, append([]car.Block{{CID: root, Data: mb}}, blocks...)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := VerifyCARFile(context.Background(), writeCAR(t, buf.Bytes()), VerifyOptions{}); err == nil || !strings.Contains(err.Error(), "header hashes to") {
		t.Fatalf("verify must reject made-up hashes, got %v", err)
	}
}

func TestBrokenParentHashRejected(t *testing.T) {
	recs := records(t, realBlocks(t)[:3])
	recs[2].LastBlockHash = "WRONG_PARENT_HASH"
	if _, _, _, err := PackBlocks(recs, nil); err == nil {
		t.Fatal("expected PackBlocks to reject a broken parent hash link")
	}
}

func TestSwappedValidatorSetIsRejected(t *testing.T) {
	srv := fakeNode(t)
	out := t.TempDir()
	entry, err := ArchiveRange(context.Background(), comet.NewClient(srv.URL), 1, 99, out, "")
	if err != nil {
		t.Fatal(err)
	}
	carPath := filepath.Join(out, entry.CARFile)
	f, err := os.Open(carPath)
	if err != nil {
		t.Fatal(err)
	}
	hdr, blocks, err := car.ReadCAR(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	var manifest RangeManifest
	if err := json.Unmarshal(blocks[0].Data, &manifest); err != nil {
		t.Fatal(err)
	}
	// Replace the validator set with one validator holding all the power,
	// keeping CIDs consistent so only the set-hash check can catch it.
	i := 1 + manifest.BlockCount
	swapped := []byte(`{"result":{"validators":[{"address":"x","pub_key":{"type":"tendermint/PubKeyEd25519","value":"tEybm7cpmLphGbSZX6E6MMM5ejbGq6zEFcRyBR7Okb4="},"voting_power":"5000000"}]}}`)
	cid := car.NewCID(car.CodecRaw, swapped)
	blocks[i] = car.Block{CID: cid, Data: swapped}
	manifest.ValidatorSets[0].CID = cid.String()
	mb, _ := json.Marshal(manifest)
	root := car.NewCID(car.CodecRaw, mb)
	blocks[0] = car.Block{CID: root, Data: mb}
	_ = hdr
	var buf bytes.Buffer
	if err := car.WriteCAR(&buf, root, blocks); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := VerifyCARFile(context.Background(), writeCAR(t, buf.Bytes()), VerifyOptions{}); err == nil || !strings.Contains(err.Error(), "hashes to") {
		t.Fatalf("a swapped validator set must be rejected, got %v", err)
	}
}

func TestLiveNodeMismatchIsReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve block 2 for every height: the boundary hashes won't match.
		w.Write(realBlocks(t)[1])
	}))
	defer srv.Close()
	_, _, _, err := VerifyCARFile(context.Background(), exampleCARFile, VerifyOptions{Client: comet.NewClient(srv.URL)})
	if err == nil || !strings.Contains(err.Error(), "live block") {
		t.Fatalf("expected a live-node mismatch, got %v", err)
	}
}

func TestUpsertIndexReplacesAndSorts(t *testing.T) {
	p := filepath.Join(t.TempDir(), "idx", "index.json")
	for _, e := range []IndexEntry{
		{ChainID: "c", StartHeight: 101, EndHeight: 200, RootCID: "b"},
		{ChainID: "c", StartHeight: 1, EndHeight: 100, RootCID: "a"},
		{ChainID: "c", StartHeight: 1, EndHeight: 100, RootCID: "a2"},
	} {
		if err := UpsertIndex(p, e); err != nil {
			t.Fatal(err)
		}
	}
	var idx IndexFile
	raw, _ := os.ReadFile(p)
	if err := json.Unmarshal(raw, &idx); err != nil {
		t.Fatal(err)
	}
	if len(idx.Ranges) != 2 || idx.Ranges[0].RootCID != "a2" || idx.Ranges[1].StartHeight != 101 {
		t.Fatalf("unexpected index: %+v", idx.Ranges)
	}
}
