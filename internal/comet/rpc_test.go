package comet

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientFetchesStatusBlockValidatorsAndCommit(t *testing.T) {
	blocks := exampleBlocks(t)
	vals := []map[string]any{
		{"address": "2EFA14D4903A1644185FA63E9E5F1B1872F664F6", "pub_key": map[string]string{"type": "tendermint/PubKeyEd25519", "value": "tEybm7cpmLphGbSZX6E6MMM5ejbGq6zEFcRyBR7Okb4="}, "voting_power": "1000000"},
		{"address": "80756DB8674D0D8F08843626B18051236979E7E8", "pub_key": map[string]string{"type": "tendermint/PubKeyEd25519", "value": "jJMGArhq1xdA3z6O3kySqKtr4fpAN8+Qu1aou3X2vKk="}, "voting_power": "1000000"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			fmt.Fprint(w, `{"result":{"node_info":{"network":"synthos-mainnet-1"},"sync_info":{"latest_block_height":"100","latest_block_hash":"abc","earliest_block_height":"1"}}}`)
		case "/block":
			var h int
			fmt.Sscan(r.URL.Query().Get("height"), &h)
			if h < 1 || h > len(blocks) {
				http.Error(w, "no such height", http.StatusInternalServerError)
				return
			}
			w.Write(blocks[h-1])
		case "/validators":
			// One validator per page, to exercise paging.
			page := r.URL.Query().Get("page")
			i := 0
			if page == "2" {
				i = 1
			}
			json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"validators": vals[i : i+1], "total": "2"}})
		case "/commit":
			fmt.Fprint(w, `{"result":{"signed_header":{}}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL + "/")
	ctx := context.Background()
	st, err := c.Status(ctx)
	if err != nil || st.ChainID != "synthos-mainnet-1" || st.LatestBlockHeight != 100 || st.LatestBlockHash != "ABC" {
		t.Fatalf("status: %+v %v", st, err)
	}
	b, err := c.FetchBlock(ctx, 2)
	if err != nil || b.Height != 2 || b.LastBlockHash != "84396F133C4EC2BE2BB99280386151A8D1BB6CACA7AE559DF50B7FA25DE522E9" {
		t.Fatalf("block: %+v %v", b, err)
	}
	if _, err := c.FetchBlock(ctx, 0); err == nil {
		t.Fatal("height 0 must be refused")
	}
	if _, err := c.FetchBlock(ctx, 500); err == nil {
		t.Fatal("HTTP errors must surface")
	}
	raw, err := c.FetchValidators(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	vs, err := ParseValidators(raw)
	if err != nil || len(vs.Validators) != 2 {
		t.Fatalf("both pages must be merged: %v", err)
	}
	if got := fmt.Sprintf("%X", vs.Hash()); got != "40E599CBC6C9B5E14E45C5AE8D5E560BB5DFEF2AB25468E256BF1B3216EC29E6" {
		t.Fatalf("validator set hash %s", got)
	}
	if _, err := c.FetchCommit(ctx, 1); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyChainLinkage(t *testing.T) {
	recs := []*BlockRecord{
		{ChainID: "c", Height: 1, BlockHash: "AA"},
		{ChainID: "c", Height: 2, BlockHash: "BB", LastBlockHash: "aa"},
	}
	if err := VerifyChainLinkage(recs); err != nil {
		t.Fatalf("valid linkage rejected: %v", err)
	}
	for name, bad := range map[string][]*BlockRecord{
		"empty":    nil,
		"gap":      {recs[0], {ChainID: "c", Height: 3, BlockHash: "CC", LastBlockHash: "AA"}},
		"parent":   {recs[0], {ChainID: "c", Height: 2, BlockHash: "BB", LastBlockHash: "XX"}},
		"chain id": {recs[0], {ChainID: "d", Height: 2, BlockHash: "BB", LastBlockHash: "AA"}},
		"no hash":  {{ChainID: "c", Height: 1}},
	} {
		if err := VerifyChainLinkage(bad); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
