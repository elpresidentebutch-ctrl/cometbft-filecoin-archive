// Copyright 2026 James Isham Williams (SYNTHOS Collective)
// Dual-licensed under MIT or Apache-2.0 at your option.

package comet

// Recomputing CometBFT v0.38 hashes and checking validator signatures, so an
// archive can be verified without trusting whoever produced it.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// BlockID identifies a block: its header hash plus its part-set header.
type BlockID struct {
	Hash      []byte
	PartTotal uint32
	PartHash  []byte
}

func (id BlockID) isZero() bool {
	return len(id.Hash) == 0 && id.PartTotal == 0 && len(id.PartHash) == 0
}

// proto is BlockID.ToProto().Marshal(); the part-set header is non-nullable.
func (id BlockID) proto() []byte {
	var psh pbuf
	psh = psh.uvarint(1, uint64(id.PartTotal))
	psh = psh.bytesField(2, id.PartHash)
	var b pbuf
	b = b.bytesField(1, id.Hash)
	return b.message(2, psh)
}

// canonical is CanonicalBlockID as signed in votes; nil for an empty ID.
func (id BlockID) canonical() []byte {
	if id.isZero() {
		return nil
	}
	return id.proto() // CanonicalBlockID has the same field layout
}

// Header is a CometBFT block header with every hashed field.
type Header struct {
	VersionBlock       uint64
	VersionApp         uint64
	ChainID            string
	Height             int64
	Time               time.Time
	LastBlockID        BlockID
	LastCommitHash     []byte
	DataHash           []byte
	ValidatorsHash     []byte
	NextValidatorsHash []byte
	ConsensusHash      []byte
	AppHash            []byte
	LastResultsHash    []byte
	EvidenceHash       []byte
	ProposerAddress    []byte
}

// Hash recomputes the block hash exactly as CometBFT's Header.Hash().
func (h *Header) Hash() []byte {
	var version pbuf
	version = version.uvarint(1, h.VersionBlock)
	version = version.uvarint(2, h.VersionApp)
	return MerkleRoot([][]byte{
		version,
		stringValue(h.ChainID),
		int64Value(h.Height),
		timestamp(h.Time),
		h.LastBlockID.proto(),
		bytesValue(h.LastCommitHash),
		bytesValue(h.DataHash),
		bytesValue(h.ValidatorsHash),
		bytesValue(h.NextValidatorsHash),
		bytesValue(h.ConsensusHash),
		bytesValue(h.AppHash),
		bytesValue(h.LastResultsHash),
		bytesValue(h.EvidenceHash),
		bytesValue(h.ProposerAddress),
	})
}

// BlockIDFlag values in CommitSig.
const (
	FlagAbsent = 1
	FlagCommit = 2
	FlagNil    = 3
)

// CommitSig is one validator's entry in a commit.
type CommitSig struct {
	Flag             int
	ValidatorAddress []byte
	Timestamp        time.Time
	Signature        []byte
}

func (s CommitSig) proto() []byte {
	var b pbuf
	b = b.uvarint(1, uint64(s.Flag))
	b = b.bytesField(2, s.ValidatorAddress)
	b = b.message(3, timestamp(s.Timestamp))
	return b.bytesField(4, s.Signature)
}

// Commit is the set of precommit signatures that finalized a block.
type Commit struct {
	Height     int64
	Round      int32
	BlockID    BlockID
	Signatures []CommitSig
}

// Hash recomputes Commit.Hash(), which the next header stores as
// last_commit_hash.
func (c *Commit) Hash() []byte {
	items := make([][]byte, len(c.Signatures))
	for i, s := range c.Signatures {
		items[i] = s.proto()
	}
	return MerkleRoot(items)
}

// voteSignBytes is what validator i signed: the length-delimited
// CanonicalVote for a precommit.
func (c *Commit) voteSignBytes(chainID string, i int) []byte {
	s := c.Signatures[i]
	var id BlockID
	if s.Flag == FlagCommit {
		id = c.BlockID
	}
	var b pbuf
	b = b.uvarint(1, 2) // SignedMsgType PRECOMMIT
	b = b.sfixed64(2, c.Height)
	b = b.sfixed64(3, int64(c.Round))
	if cb := id.canonical(); cb != nil {
		b = b.message(4, cb)
	}
	b = b.message(5, timestamp(s.Timestamp))
	b = b.bytesField(6, []byte(chainID))
	return delimited(b)
}

// Validator is one member of a validator set.
type Validator struct {
	Address     []byte
	PubKey      ed25519.PublicKey
	VotingPower int64
}

// ValidatorSet is ordered as CometBFT orders it: voting power descending,
// then address ascending.
type ValidatorSet struct {
	Validators []Validator
}

// NewValidatorSet sorts validators into CometBFT order.
func NewValidatorSet(vals []Validator) *ValidatorSet {
	out := append([]Validator(nil), vals...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].VotingPower != out[j].VotingPower {
			return out[i].VotingPower > out[j].VotingPower
		}
		return strings.Compare(hex.EncodeToString(out[i].Address), hex.EncodeToString(out[j].Address)) < 0
	})
	return &ValidatorSet{Validators: out}
}

// Hash recomputes ValidatorSet.Hash(), stored in headers as validators_hash.
func (vs *ValidatorSet) Hash() []byte {
	items := make([][]byte, len(vs.Validators))
	for i, v := range vs.Validators {
		var pk pbuf
		pk = pk.bytesField(1, v.PubKey) // PublicKey{ed25519}
		var b pbuf
		b = b.message(1, pk)
		b = b.int64v(2, v.VotingPower)
		items[i] = b
	}
	return MerkleRoot(items)
}

// TotalPower is the sum of all voting power.
func (vs *ValidatorSet) TotalPower() int64 {
	var t int64
	for _, v := range vs.Validators {
		t += v.VotingPower
	}
	return t
}

// VerifyCommit checks that commit finalizes blockID at height on chainID:
// every present signature must be valid for its validator, and validators
// holding more than 2/3 of the voting power must have signed for blockID.
func VerifyCommit(chainID string, vals *ValidatorSet, blockID BlockID, height int64, commit *Commit) error {
	if commit.Height != height {
		return fmt.Errorf("commit is for height %d, want %d", commit.Height, height)
	}
	if !equalBytes(commit.BlockID.Hash, blockID.Hash) || commit.BlockID.PartTotal != blockID.PartTotal || !equalBytes(commit.BlockID.PartHash, blockID.PartHash) {
		return fmt.Errorf("commit at height %d signs a different block (%X, want %X)", height, commit.BlockID.Hash, blockID.Hash)
	}
	if len(commit.Signatures) != len(vals.Validators) {
		return fmt.Errorf("commit at height %d has %d signatures for %d validators", height, len(commit.Signatures), len(vals.Validators))
	}
	var signed int64
	for i, s := range commit.Signatures {
		if s.Flag == FlagAbsent {
			continue
		}
		v := vals.Validators[i]
		if !equalBytes(s.ValidatorAddress, v.Address) {
			return fmt.Errorf("commit at height %d: signature %d is from %X, expected validator %X", height, i, s.ValidatorAddress, v.Address)
		}
		if !ed25519.Verify(v.PubKey, commit.voteSignBytes(chainID, i), s.Signature) {
			return fmt.Errorf("commit at height %d: invalid signature from validator %X", height, v.Address)
		}
		if s.Flag == FlagCommit {
			signed += v.VotingPower
		}
	}
	if total := vals.TotalPower(); signed*3 <= total*2 {
		return fmt.Errorf("commit at height %d: only %d of %d voting power signed (need more than 2/3)", height, signed, total)
	}
	return nil
}

// FullBlock is a parsed /block response with everything needed to verify it.
type FullBlock struct {
	BlockID    BlockID
	Header     Header
	Txs        [][]byte
	LastCommit *Commit // commit for Height-1; empty at height 1
}

// DataHash recomputes the header's data_hash: the Merkle root of each
// transaction's SHA-256.
func (b *FullBlock) DataHash() []byte {
	items := make([][]byte, len(b.Txs))
	for i, tx := range b.Txs {
		h := sha256.Sum256(tx)
		items[i] = h[:]
	}
	return MerkleRoot(items)
}

// Check recomputes the block's own hashes: header hash, data hash and last
// commit hash. It needs no validator set.
func (b *FullBlock) Check() error {
	if got := b.Header.Hash(); !equalBytes(got, b.BlockID.Hash) {
		return fmt.Errorf("height %d: header hashes to %X, but the block claims %X", b.Header.Height, got, b.BlockID.Hash)
	}
	if got := b.DataHash(); !equalBytes(got, b.Header.DataHash) {
		return fmt.Errorf("height %d: transactions hash to %X, header data_hash is %X", b.Header.Height, got, b.Header.DataHash)
	}
	if b.LastCommit != nil && len(b.LastCommit.Signatures) > 0 {
		if got := b.LastCommit.Hash(); !equalBytes(got, b.Header.LastCommitHash) {
			return fmt.Errorf("height %d: last_commit hashes to %X, header last_commit_hash is %X", b.Header.Height, got, b.Header.LastCommitHash)
		}
	}
	return nil
}

// --- JSON parsing -----------------------------------------------------------

type jsonBlockID struct {
	Hash  string `json:"hash"`
	Parts struct {
		Total json.Number `json:"total"`
		Hash  string      `json:"hash"`
	} `json:"parts"`
}

type jsonCommit struct {
	Height     string      `json:"height"`
	Round      json.Number `json:"round"`
	BlockID    jsonBlockID `json:"block_id"`
	Signatures []struct {
		Flag             json.Number `json:"block_id_flag"`
		ValidatorAddress string      `json:"validator_address"`
		Timestamp        string      `json:"timestamp"`
		Signature        *string     `json:"signature"`
	} `json:"signatures"`
}

type jsonHeader struct {
	Version struct {
		Block string `json:"block"`
		App   string `json:"app"`
	} `json:"version"`
	ChainID            string      `json:"chain_id"`
	Height             string      `json:"height"`
	Time               string      `json:"time"`
	LastBlockID        jsonBlockID `json:"last_block_id"`
	LastCommitHash     string      `json:"last_commit_hash"`
	DataHash           string      `json:"data_hash"`
	ValidatorsHash     string      `json:"validators_hash"`
	NextValidatorsHash string      `json:"next_validators_hash"`
	ConsensusHash      string      `json:"consensus_hash"`
	AppHash            string      `json:"app_hash"`
	LastResultsHash    string      `json:"last_results_hash"`
	EvidenceHash       string      `json:"evidence_hash"`
	ProposerAddress    string      `json:"proposer_address"`
}

// ParseFullBlock parses a /block RPC response.
func ParseFullBlock(raw []byte) (*FullBlock, error) {
	var env struct {
		Result struct {
			BlockID jsonBlockID `json:"block_id"`
			Block   struct {
				Header jsonHeader `json:"header"`
				Data   struct {
					Txs []string `json:"txs"`
				} `json:"data"`
				LastCommit *jsonCommit `json:"last_commit"`
			} `json:"block"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("decode block: %w", err)
	}
	r := env.Result
	b := &FullBlock{}
	var err error
	if b.BlockID, err = parseBlockID(r.BlockID); err != nil {
		return nil, fmt.Errorf("block_id: %w", err)
	}
	if b.Header, err = parseHeader(r.Block.Header); err != nil {
		return nil, err
	}
	for i, t := range r.Block.Data.Txs {
		tx, err := base64.StdEncoding.DecodeString(t)
		if err != nil {
			return nil, fmt.Errorf("height %d tx %d: %w", b.Header.Height, i, err)
		}
		b.Txs = append(b.Txs, tx)
	}
	if r.Block.LastCommit != nil {
		if b.LastCommit, err = parseCommit(*r.Block.LastCommit); err != nil {
			return nil, fmt.Errorf("height %d last_commit: %w", b.Header.Height, err)
		}
	}
	return b, nil
}

// ParseSignedHeader parses a /commit RPC response into its header and commit.
func ParseSignedHeader(raw []byte) (*Header, *Commit, error) {
	var env struct {
		Result struct {
			SignedHeader struct {
				Header jsonHeader `json:"header"`
				Commit jsonCommit `json:"commit"`
			} `json:"signed_header"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, nil, fmt.Errorf("decode commit: %w", err)
	}
	h, err := parseHeader(env.Result.SignedHeader.Header)
	if err != nil {
		return nil, nil, err
	}
	c, err := parseCommit(env.Result.SignedHeader.Commit)
	if err != nil {
		return nil, nil, err
	}
	return &h, c, nil
}

// ParseValidators parses a /validators RPC response (all pages merged into
// one "validators" list) into a validator set.
func ParseValidators(raw []byte) (*ValidatorSet, error) {
	var env struct {
		Result struct {
			Validators []struct {
				Address string `json:"address"`
				PubKey  struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				} `json:"pub_key"`
				VotingPower string `json:"voting_power"`
			} `json:"validators"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("decode validators: %w", err)
	}
	var vals []Validator
	for _, v := range env.Result.Validators {
		if v.PubKey.Type != "tendermint/PubKeyEd25519" {
			return nil, fmt.Errorf("validator %s: unsupported key type %q", v.Address, v.PubKey.Type)
		}
		pk, err := base64.StdEncoding.DecodeString(v.PubKey.Value)
		if err != nil || len(pk) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("validator %s: bad ed25519 public key", v.Address)
		}
		power, err := strconv.ParseInt(v.VotingPower, 10, 64)
		if err != nil || power <= 0 {
			return nil, fmt.Errorf("validator %s: bad voting power %q", v.Address, v.VotingPower)
		}
		vals = append(vals, ValidatorFromPubKey(pk, power))
	}
	if len(vals) == 0 {
		return nil, fmt.Errorf("empty validator set")
	}
	return NewValidatorSet(vals), nil
}

// ParseGenesisValidators reads the validators of a CometBFT genesis.json.
func ParseGenesisValidators(raw []byte) (chainID string, vs *ValidatorSet, err error) {
	var g struct {
		ChainID    string `json:"chain_id"`
		Validators []struct {
			PubKey struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"pub_key"`
			Power string `json:"power"`
		} `json:"validators"`
	}
	if err := json.Unmarshal(raw, &g); err != nil {
		return "", nil, fmt.Errorf("decode genesis: %w", err)
	}
	var vals []Validator
	for i, v := range g.Validators {
		if v.PubKey.Type != "tendermint/PubKeyEd25519" {
			return "", nil, fmt.Errorf("genesis validator %d: unsupported key type %q", i, v.PubKey.Type)
		}
		pk, err := base64.StdEncoding.DecodeString(v.PubKey.Value)
		if err != nil || len(pk) != ed25519.PublicKeySize {
			return "", nil, fmt.Errorf("genesis validator %d: bad ed25519 public key", i)
		}
		power, err := strconv.ParseInt(v.Power, 10, 64)
		if err != nil || power <= 0 {
			return "", nil, fmt.Errorf("genesis validator %d: bad power %q", i, v.Power)
		}
		vals = append(vals, ValidatorFromPubKey(pk, power))
	}
	if len(vals) == 0 {
		return "", nil, fmt.Errorf("genesis has no validators")
	}
	return g.ChainID, NewValidatorSet(vals), nil
}

// ValidatorFromPubKey builds a validator; its address is the first 20 bytes
// of SHA-256 of the public key.
func ValidatorFromPubKey(pk []byte, power int64) Validator {
	sum := sha256.Sum256(pk)
	return Validator{Address: sum[:20], PubKey: ed25519.PublicKey(pk), VotingPower: power}
}

func parseHeader(j jsonHeader) (Header, error) {
	var h Header
	var err error
	if h.VersionBlock, err = parseUint(j.Version.Block); err != nil {
		return h, fmt.Errorf("version.block: %w", err)
	}
	if h.VersionApp, err = parseUint(j.Version.App); err != nil {
		return h, fmt.Errorf("version.app: %w", err)
	}
	h.ChainID = j.ChainID
	if h.Height, err = strconv.ParseInt(j.Height, 10, 64); err != nil {
		return h, fmt.Errorf("height %q: %w", j.Height, err)
	}
	if h.Time, err = time.Parse(time.RFC3339Nano, j.Time); err != nil {
		return h, fmt.Errorf("height %d time: %w", h.Height, err)
	}
	if h.LastBlockID, err = parseBlockID(j.LastBlockID); err != nil {
		return h, fmt.Errorf("height %d last_block_id: %w", h.Height, err)
	}
	for _, f := range []struct {
		dst *[]byte
		src string
	}{
		{&h.LastCommitHash, j.LastCommitHash}, {&h.DataHash, j.DataHash},
		{&h.ValidatorsHash, j.ValidatorsHash}, {&h.NextValidatorsHash, j.NextValidatorsHash},
		{&h.ConsensusHash, j.ConsensusHash}, {&h.AppHash, j.AppHash},
		{&h.LastResultsHash, j.LastResultsHash}, {&h.EvidenceHash, j.EvidenceHash},
		{&h.ProposerAddress, j.ProposerAddress},
	} {
		if *f.dst, err = hex.DecodeString(f.src); err != nil {
			return h, fmt.Errorf("height %d: bad hex %q: %w", h.Height, f.src, err)
		}
	}
	return h, nil
}

func parseBlockID(j jsonBlockID) (BlockID, error) {
	var id BlockID
	var err error
	if id.Hash, err = hex.DecodeString(j.Hash); err != nil {
		return id, err
	}
	if id.PartHash, err = hex.DecodeString(j.Parts.Hash); err != nil {
		return id, err
	}
	total, err := parseUint(j.Parts.Total.String())
	if err != nil {
		return id, err
	}
	id.PartTotal = uint32(total)
	return id, nil
}

func parseCommit(j jsonCommit) (*Commit, error) {
	c := &Commit{}
	var err error
	if c.Height, err = strconv.ParseInt(defaultZero(j.Height), 10, 64); err != nil {
		return nil, fmt.Errorf("height %q: %w", j.Height, err)
	}
	round, err := strconv.ParseInt(defaultZero(j.Round.String()), 10, 32)
	if err != nil {
		return nil, fmt.Errorf("round: %w", err)
	}
	c.Round = int32(round)
	if c.BlockID, err = parseBlockID(j.BlockID); err != nil {
		return nil, fmt.Errorf("block_id: %w", err)
	}
	for i, s := range j.Signatures {
		flag, err := strconv.Atoi(s.Flag.String())
		if err != nil {
			return nil, fmt.Errorf("signature %d flag: %w", i, err)
		}
		cs := CommitSig{Flag: flag}
		if cs.ValidatorAddress, err = hex.DecodeString(s.ValidatorAddress); err != nil {
			return nil, fmt.Errorf("signature %d address: %w", i, err)
		}
		if cs.Timestamp, err = time.Parse(time.RFC3339Nano, s.Timestamp); err != nil {
			return nil, fmt.Errorf("signature %d timestamp: %w", i, err)
		}
		if s.Signature != nil && *s.Signature != "" {
			if cs.Signature, err = base64.StdEncoding.DecodeString(*s.Signature); err != nil {
				return nil, fmt.Errorf("signature %d: %w", i, err)
			}
		}
		c.Signatures = append(c.Signatures, cs)
	}
	return c, nil
}

func parseUint(s string) (uint64, error) {
	return strconv.ParseUint(defaultZero(s), 10, 64)
}

func defaultZero(s string) string {
	if s == "" {
		return "0"
	}
	return s
}

func equalBytes(a, b []byte) bool {
	return hex.EncodeToString(a) == hex.EncodeToString(b)
}
