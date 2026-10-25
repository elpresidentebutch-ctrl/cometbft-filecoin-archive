package car

import (
	"bytes"
	"strings"
	"testing"
)

func TestCIDRoundTripAndTamperDetection(t *testing.T) {
	payload := []byte(`{"height":"1","hash":"84396F133C4EC2BE2BB99280386151A8D1BB6CACA7AE559DF50B7FA25DE522E9"}`)
	cid := NewCID(CodecRaw, payload)
	str := cid.String()
	if !strings.HasPrefix(str, "bafkrei") {
		t.Fatalf("expected raw CIDv1 base32 string to start with 'bafkrei', got %q", str)
	}
	parsed, err := ParseCID(str)
	if err != nil {
		t.Fatalf("ParseCID failed: %v", err)
	}
	if parsed != cid {
		t.Fatalf("parsed CID mismatch: got %+v, want %+v", parsed, cid)
	}
	if !parsed.Verify(payload) {
		t.Fatal("expected Verify to succeed on unmodified payload")
	}
	if parsed.Verify([]byte(`{"height":"2"}`)) {
		t.Fatal("expected Verify to fail on modified payload")
	}
}

func TestCARv1WriteAndReadRoundTrip(t *testing.T) {
	b1Data := []byte(`{"block":1}`)
	b2Data := []byte(`{"block":2}`)
	rootData := []byte(`{"schema":"cometbft-filecoin-archive/v1","blocks":[1,2]}`)

	b1 := Block{CID: NewCID(CodecRaw, b1Data), Data: b1Data}
	b2 := Block{CID: NewCID(CodecRaw, b2Data), Data: b2Data}
	root := Block{CID: NewCID(CodecRaw, rootData), Data: rootData}

	var buf bytes.Buffer
	if err := WriteCAR(&buf, root.CID, []Block{root, b1, b2}); err != nil {
		t.Fatalf("WriteCAR failed: %v", err)
	}

	hdr, blocks, err := ReadCAR(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadCAR failed: %v", err)
	}
	if hdr.Version != 1 || len(hdr.Roots) != 1 || hdr.Roots[0] != root.CID {
		t.Fatalf("unexpected CARv1 header: %+v", hdr)
	}
	if len(blocks) != 3 {
		t.Fatalf("expected 3 blocks, got %d", len(blocks))
	}
	if !bytes.Equal(blocks[1].Data, b1Data) || !bytes.Equal(blocks[2].Data, b2Data) {
		t.Fatal("round-trip block data mismatch")
	}

	// Corrupt the last byte in the CAR stream and verify ReadCAR rejects it.
	corrupted := append([]byte(nil), buf.Bytes()...)
	corrupted[len(corrupted)-1] ^= 0xff
	if _, _, err := ReadCAR(bytes.NewReader(corrupted)); err == nil {
		t.Fatal("expected ReadCAR to reject corrupted block data")
	}
}
