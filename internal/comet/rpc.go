// Copyright 2026 James Isham Williams (SYNTHOS Collective)
// Dual-licensed under MIT or Apache-2.0 at your option.

// Package comet fetches and verifies blocks and commits from a CometBFT node
// RPC endpoint.
package comet

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Client queries a CometBFT HTTP RPC server (default port 26657).
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewClient returns a CometBFT RPC client for the given base URL.
func NewClient(baseURL string) *Client {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		baseURL = "http://127.0.0.1:26657"
	}
	return &Client{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// StatusSummary holds the chain metadata returned by /status.
type StatusSummary struct {
	ChainID             string
	EarliestBlockHeight int64
	EarliestBlockHash   string
	LatestBlockHeight   int64
	LatestBlockHash     string
	CatchingUp          bool
}

type rpcStatusEnvelope struct {
	Result struct {
		NodeInfo struct {
			Network string `json:"network"`
		} `json:"node_info"`
		SyncInfo struct {
			LatestBlockHash     string `json:"latest_block_hash"`
			LatestBlockHeight   string `json:"latest_block_height"`
			EarliestBlockHash   string `json:"earliest_block_hash"`
			EarliestBlockHeight string `json:"earliest_block_height"`
			CatchingUp          bool   `json:"catching_up"`
		} `json:"sync_info"`
	} `json:"result"`
}

// Status queries /status on the CometBFT RPC endpoint.
func (c *Client) Status(ctx context.Context) (*StatusSummary, error) {
	body, err := c.get(ctx, "/status")
	if err != nil {
		return nil, err
	}
	var env rpcStatusEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("comet: decode /status: %w", err)
	}
	latestH, err := strconv.ParseInt(env.Result.SyncInfo.LatestBlockHeight, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("comet: parse latest_block_height %q: %w", env.Result.SyncInfo.LatestBlockHeight, err)
	}
	earliestH, _ := strconv.ParseInt(env.Result.SyncInfo.EarliestBlockHeight, 10, 64)
	return &StatusSummary{
		ChainID:             env.Result.NodeInfo.Network,
		EarliestBlockHeight: earliestH,
		EarliestBlockHash:   strings.ToUpper(env.Result.SyncInfo.EarliestBlockHash),
		LatestBlockHeight:   latestH,
		LatestBlockHash:     strings.ToUpper(env.Result.SyncInfo.LatestBlockHash),
		CatchingUp:          env.Result.SyncInfo.CatchingUp,
	}, nil
}

// BlockRecord contains the parsed header metadata and canonical raw JSON bytes
// of a single CometBFT block.
type BlockRecord struct {
	ChainID        string `json:"chain_id"`
	Height         int64  `json:"height"`
	BlockHash      string `json:"block_hash"`
	LastBlockHash  string `json:"last_block_hash"`
	Time           string `json:"time"`
	AppHash        string `json:"app_hash,omitempty"`
	ValidatorsHash string `json:"validators_hash,omitempty"`
	TxCount        int    `json:"tx_count"`
	RawJSON        []byte `json:"-"`
}

type rpcBlockEnvelope struct {
	Result struct {
		BlockID struct {
			Hash string `json:"hash"`
		} `json:"block_id"`
		Block struct {
			Header struct {
				ChainID     string `json:"chain_id"`
				Height      string `json:"height"`
				Time        string `json:"time"`
				AppHash     string `json:"app_hash"`
				Validators  string `json:"validators_hash"`
				LastBlockID struct {
					Hash string `json:"hash"`
				} `json:"last_block_id"`
			} `json:"header"`
			Data struct {
				Txs []any `json:"txs"`
			} `json:"data"`
		} `json:"block"`
	} `json:"result"`
}

// FetchBlock fetches the block at height H from /block?height=H and parses its
// header linkage fields.
func (c *Client) FetchBlock(ctx context.Context, height int64) (*BlockRecord, error) {
	if height <= 0 {
		return nil, fmt.Errorf("comet: height must be >= 1 (got %d)", height)
	}
	raw, err := c.get(ctx, fmt.Sprintf("/block?height=%d", height))
	if err != nil {
		return nil, err
	}
	return ParseBlockJSON(raw)
}

// ParseBlockJSON parses the JSON response from CometBFT's /block endpoint.
func ParseBlockJSON(raw []byte) (*BlockRecord, error) {
	var env rpcBlockEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("comet: decode block json: %w", err)
	}
	hStr := env.Result.Block.Header.Height
	if hStr == "" {
		return nil, fmt.Errorf("comet: empty block.header.height in block response")
	}
	h, err := strconv.ParseInt(hStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("comet: invalid block height %q: %w", hStr, err)
	}
	hash := strings.ToUpper(strings.TrimSpace(env.Result.BlockID.Hash))
	if hash == "" {
		return nil, fmt.Errorf("comet: empty block_id.hash at height %d", h)
	}
	return &BlockRecord{
		ChainID:        env.Result.Block.Header.ChainID,
		Height:         h,
		BlockHash:      hash,
		LastBlockHash:  strings.ToUpper(strings.TrimSpace(env.Result.Block.Header.LastBlockID.Hash)),
		Time:           env.Result.Block.Header.Time,
		AppHash:        strings.ToUpper(strings.TrimSpace(env.Result.Block.Header.AppHash)),
		ValidatorsHash: strings.ToUpper(strings.TrimSpace(env.Result.Block.Header.Validators)),
		TxCount:        len(env.Result.Block.Data.Txs),
		RawJSON:        raw,
	}, nil
}

// VerifyChainLinkage verifies that an ordered slice of CometBFT blocks covers
// contiguous heights and that every block's header.last_block_id.hash equals
// the preceding block's block_id.hash.
func VerifyChainLinkage(blocks []*BlockRecord) error {
	if len(blocks) == 0 {
		return fmt.Errorf("comet: cannot verify empty block range")
	}
	chainID := blocks[0].ChainID
	for i, b := range blocks {
		if b.BlockHash == "" {
			return fmt.Errorf("comet: empty block hash at index %d (height %d)", i, b.Height)
		}
		if b.ChainID != chainID {
			return fmt.Errorf("comet: chain_id mismatch at height %d: got %q, want %q", b.Height, b.ChainID, chainID)
		}
		if i > 0 {
			prev := blocks[i-1]
			if b.Height != prev.Height+1 {
				return fmt.Errorf("comet: non-contiguous block heights: %d followed by %d", prev.Height, b.Height)
			}
			if !strings.EqualFold(b.LastBlockHash, prev.BlockHash) {
				return fmt.Errorf(
					"comet: broken parent hash link at height %d: last_block_id.hash=%s != parent(%d).block_id.hash=%s",
					b.Height, b.LastBlockHash, prev.Height, prev.BlockHash,
				)
			}
		}
	}
	return nil
}

// FetchValidators returns the validator set at height H as one /validators
// response with every page merged, so it can be stored and verified offline.
func (c *Client) FetchValidators(ctx context.Context, height int64) ([]byte, error) {
	const perPage = 100
	var all []json.RawMessage
	for page := 1; ; page++ {
		raw, err := c.get(ctx, fmt.Sprintf("/validators?height=%d&page=%d&per_page=%d", height, page, perPage))
		if err != nil {
			return nil, err
		}
		var env struct {
			Result struct {
				Validators []json.RawMessage `json:"validators"`
				Total      string            `json:"total"`
			} `json:"result"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			return nil, fmt.Errorf("comet: decode /validators: %w", err)
		}
		all = append(all, env.Result.Validators...)
		total, err := strconv.Atoi(env.Result.Total)
		if err != nil {
			return nil, fmt.Errorf("comet: /validators total %q: %w", env.Result.Total, err)
		}
		if len(all) >= total || len(env.Result.Validators) == 0 {
			break
		}
	}
	return json.Marshal(map[string]any{"result": map[string]any{
		"block_height": strconv.FormatInt(height, 10),
		"validators":   all,
		"total":        strconv.Itoa(len(all)),
	}})
}

// FetchCommit returns the /commit response (signed header) for height H.
func (c *Client) FetchCommit(ctx context.Context, height int64) ([]byte, error) {
	return c.get(ctx, fmt.Sprintf("/commit?height=%d", height))
}

func (c *Client) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("comet: GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("comet: read %s: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("comet: GET %s returned HTTP %d: %s", path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}
