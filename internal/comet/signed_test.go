package comet

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"gitlab.com/synthos-collective-group/cometbft-filecoin-archive/internal/car"
)

const exampleCAR = "../../examples/synthos-mainnet-1/synthos-mainnet-1-000001-000100.car"

// genesisSet is synthos-mainnet-1's genesis validator set.
func genesisSet(t *testing.T) *ValidatorSet {
	t.Helper()
	var vals []Validator
	for _, k := range []string{
		"b44c9b9bb72998ba6119b4995fa13a30c3397a36c6abacc415c472051ece91be",
		"8c930602b86ad71740df3e8ede4c92a8ab6be1fa4037cf90bb56a8bb75f6bca9",
	} {
		pk, err := hex.DecodeString(k)
		if err != nil {
			t.Fatal(err)
		}
		vals = append(vals, ValidatorFromPubKey(pk, 1000000))
	}
	return NewValidatorSet(vals)
}

// exampleBlocks returns the raw /block JSON of mainnet blocks 1..100.
func exampleBlocks(t *testing.T) [][]byte {
	t.Helper()
	f, err := os.Open(exampleCAR)
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
	if len(out) != 100 {
		t.Fatalf("expected 100 example blocks, got %d", len(out))
	}
	return out
}

func parseAll(t *testing.T, raws [][]byte) []*FullBlock {
	t.Helper()
	var out []*FullBlock
	for _, raw := range raws {
		b, err := ParseFullBlock(raw)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, b)
	}
	return out
}

func TestMerkleRoot(t *testing.T) {
	empty := sha256.Sum256(nil)
	if !bytes.Equal(MerkleRoot(nil), empty[:]) {
		t.Fatal("empty tree must be SHA-256 of nothing")
	}
	leaf := sha256.Sum256([]byte{0, 'a'})
	if !bytes.Equal(MerkleRoot([][]byte{[]byte("a")}), leaf[:]) {
		t.Fatal("single leaf must be SHA-256(0x00 || leaf)")
	}
	for n, want := range map[int]int{2: 1, 3: 2, 4: 2, 5: 4, 8: 4, 9: 8, 14: 8} {
		if got := splitPoint(n); got != want {
			t.Errorf("splitPoint(%d) = %d, want %d", n, got, want)
		}
	}
}

func TestRealMainnetBlocksRecomputeAndVerify(t *testing.T) {
	blocks := parseAll(t, exampleBlocks(t))
	vs := genesisSet(t)
	if got, want := vs.Hash(), blocks[0].Header.ValidatorsHash; !bytes.Equal(got, want) {
		t.Fatalf("genesis validator set hashes to %X, block 1 says %X", got, want)
	}
	for i, b := range blocks {
		if err := b.Check(); err != nil {
			t.Fatalf("block %d: %v", b.Header.Height, err)
		}
		if i+1 < len(blocks) {
			if err := VerifyCommit("synthos-mainnet-1", vs, b.BlockID, b.Header.Height, blocks[i+1].LastCommit); err != nil {
				t.Fatalf("block %d: %v", b.Header.Height, err)
			}
		}
	}
}

func TestTamperedHeaderIsCaught(t *testing.T) {
	raws := exampleBlocks(t)
	tampered := strings.Replace(string(raws[1]), `"app_hash":"`, `"app_hash":"00`, 1)
	if tampered == string(raws[1]) {
		t.Fatal("test setup: app_hash not found")
	}
	b, err := ParseFullBlock([]byte(tampered))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Check(); err == nil || !strings.Contains(err.Error(), "header hashes to") {
		t.Fatalf("a changed app_hash must break the block hash, got %v", err)
	}
}

// A forger can make a fake chain whose hashes are all self-consistent. Only
// the validators' signatures stop it.
func TestForgedButConsistentChainFailsSignatures(t *testing.T) {
	blocks := parseAll(t, exampleBlocks(t)[:3])
	vs := genesisSet(t)

	forged := *blocks[1]
	forged.Header.AppHash = bytes.Repeat([]byte{0xAA}, 32)
	forged.BlockID.Hash = forged.Header.Hash()
	if err := forged.Check(); err != nil {
		t.Fatalf("forged block should be internally consistent: %v", err)
	}
	err := VerifyCommit("synthos-mainnet-1", vs, forged.BlockID, forged.Header.Height, blocks[2].LastCommit)
	if err == nil {
		t.Fatal("real signatures must not cover a forged block")
	}

	// Forged signatures from keys that aren't the chain's validators fail too.
	pub, priv, _ := ed25519.GenerateKey(nil)
	fake := NewValidatorSet([]Validator{ValidatorFromPubKey(pub, 10)})
	commit := &Commit{Height: forged.Header.Height, BlockID: forged.BlockID, Signatures: []CommitSig{{Flag: FlagCommit, ValidatorAddress: fake.Validators[0].Address, Timestamp: forged.Header.Time}}}
	commit.Signatures[0].Signature = ed25519.Sign(priv, commit.voteSignBytes("synthos-mainnet-1", 0))
	if err := VerifyCommit("synthos-mainnet-1", fake, forged.BlockID, forged.Header.Height, commit); err != nil {
		t.Fatalf("self-signed fake commit should verify against its own fake set: %v", err)
	}
	// But the header still names the real validator set, so a verifier that
	// requires the set to match validators_hash (and anchors it) rejects it.
	if bytes.Equal(fake.Hash(), forged.Header.ValidatorsHash) {
		t.Fatal("fake validator set must not match the header's validators_hash")
	}
}

func TestBadSignatureAndLowPowerAreRejected(t *testing.T) {
	blocks := parseAll(t, exampleBlocks(t)[:3])
	vs := genesisSet(t)
	b, next := blocks[1], blocks[2]

	bad := *next.LastCommit
	bad.Signatures = append([]CommitSig(nil), next.LastCommit.Signatures...)
	sig := append([]byte(nil), bad.Signatures[0].Signature...)
	sig[0] ^= 0xFF
	bad.Signatures[0].Signature = sig
	if err := VerifyCommit("synthos-mainnet-1", vs, b.BlockID, b.Header.Height, &bad); err == nil || !strings.Contains(err.Error(), "invalid signature") {
		t.Fatalf("flipped signature byte must fail, got %v", err)
	}

	half := *next.LastCommit
	half.Signatures = append([]CommitSig(nil), next.LastCommit.Signatures...)
	half.Signatures[1] = CommitSig{Flag: FlagAbsent}
	if err := VerifyCommit("synthos-mainnet-1", vs, b.BlockID, b.Header.Height, &half); err == nil || !strings.Contains(err.Error(), "2/3") {
		t.Fatalf("one of two equal validators is not >2/3, got %v", err)
	}

	if err := VerifyCommit("another-chain", vs, b.BlockID, b.Header.Height, next.LastCommit); err == nil {
		t.Fatal("signatures are bound to the chain ID")
	}
	if err := VerifyCommit("synthos-mainnet-1", vs, b.BlockID, b.Header.Height+1, next.LastCommit); err == nil {
		t.Fatal("commit for the wrong height must fail")
	}
}

func TestParseValidatorsAndGenesis(t *testing.T) {
	gen, err := os.ReadFile("../../examples/synthos-mainnet-1/genesis-validators.json")
	if err != nil {
		t.Fatal(err)
	}
	chainID, vs, err := ParseGenesisValidators(gen)
	if err != nil || chainID != "synthos-mainnet-1" {
		t.Fatalf("genesis: %q %v", chainID, err)
	}
	if !bytes.Equal(vs.Hash(), genesisSet(t).Hash()) {
		t.Fatal("genesis file and known keys disagree")
	}
	raw := []byte(`{"result":{"validators":[
	 {"address":"x","pub_key":{"type":"tendermint/PubKeyEd25519","value":"jJMGArhq1xdA3z6O3kySqKtr4fpAN8+Qu1aou3X2vKk="},"voting_power":"1000000"},
	 {"address":"y","pub_key":{"type":"tendermint/PubKeyEd25519","value":"tEybm7cpmLphGbSZX6E6MMM5ejbGq6zEFcRyBR7Okb4="},"voting_power":"1000000"}]}}`)
	got, err := ParseValidators(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Hash(), vs.Hash()) {
		t.Fatal("validator order must not change the set hash: sets are sorted")
	}
	if _, err := ParseValidators([]byte(`{"result":{"validators":[{"pub_key":{"type":"tendermint/PubKeySecp256k1","value":"AA=="},"voting_power":"1"}]}}`)); err == nil {
		t.Fatal("non-ed25519 keys must be rejected")
	}
}
