// Copyright 2026 James Isham Williams (SYNTHOS Collective)
// Dual-licensed under MIT or Apache-2.0 at your option.

// Package car implements the IPLD Content Addressable aRchive (CARv1) binary
// format and CIDv1 (SHA2-256 multihash, base32lower multibase) encoding and
// verification for Filecoin storage deals.
package car

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	// CIDVersion1 is the multiformats CIDv1 version prefix.
	CIDVersion1 = 0x01

	// CodecRaw is the multicodec code for raw binary/JSON blocks (0x55).
	CodecRaw = 0x55

	// CodecDagCBOR is the multicodec code for IPLD DAG-CBOR (0x71).
	CodecDagCBOR = 0x71

	// MultihashSHA256Code is the multihash function code for SHA2-256 (0x12).
	MultihashSHA256Code = 0x12

	// MultihashSHA256Len is the byte length of a SHA2-256 digest (32 bytes = 0x20).
	MultihashSHA256Len = 0x20

	// cidV1SHA256ByteLen is the exact byte length of a CIDv1 with a 1-byte
	// codec and a 32-byte SHA2-256 multihash: 1 + 1 + 1 + 1 + 32 = 36 bytes.
	cidV1SHA256ByteLen = 36
)

var base32LowerNoPad = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// CID represents a content identifier (CIDv1 with SHA2-256 multihash).
type CID struct {
	Codec  byte
	Digest [32]byte
}

// NewCID computes a CIDv1 (SHA2-256) over data with the given multicodec.
func NewCID(codec byte, data []byte) CID {
	return CID{
		Codec:  codec,
		Digest: sha256.Sum256(data),
	}
}

// Bytes returns the 36-byte binary representation of the CIDv1.
func (c CID) Bytes() []byte {
	out := make([]byte, cidV1SHA256ByteLen)
	out[0] = CIDVersion1
	out[1] = c.Codec
	out[2] = MultihashSHA256Code
	out[3] = MultihashSHA256Len
	copy(out[4:], c.Digest[:])
	return out
}

// String returns the standard multibase base32lower string representation
// ("b" + base32lower(cid_bytes)), producing "bafkrei..." for CodecRaw and
// "bafyrei..." for CodecDagCBOR.
func (c CID) String() string {
	return "b" + base32LowerNoPad.EncodeToString(c.Bytes())
}

// Verify checks that sha256(data) matches the CID's embedded multihash digest.
func (c CID) Verify(data []byte) bool {
	sum := sha256.Sum256(data)
	return sum == c.Digest
}

// ParseCID parses a multibase base32lower CIDv1 string ("b...").
func ParseCID(s string) (CID, error) {
	s = strings.TrimSpace(s)
	if len(s) < 2 || s[0] != 'b' {
		return CID{}, fmt.Errorf("car: unsupported multibase prefix in CID %q (expected 'b')", s)
	}
	raw, err := base32LowerNoPad.DecodeString(strings.ToLower(s[1:]))
	if err != nil {
		return CID{}, fmt.Errorf("car: base32 decode CID %q: %w", s, err)
	}
	return CIDFromBytes(raw)
}

// CIDFromBytes decodes a 36-byte binary CIDv1 (SHA2-256).
func CIDFromBytes(b []byte) (CID, error) {
	if len(b) != cidV1SHA256ByteLen {
		return CID{}, fmt.Errorf("car: unexpected CID byte length %d (expected %d)", len(b), cidV1SHA256ByteLen)
	}
	if b[0] != CIDVersion1 {
		return CID{}, fmt.Errorf("car: unsupported CID version 0x%02x (expected 0x01)", b[0])
	}
	if b[1] != CodecRaw && b[1] != CodecDagCBOR {
		return CID{}, fmt.Errorf("car: unsupported CID codec 0x%02x", b[1])
	}
	if b[2] != MultihashSHA256Code || b[3] != MultihashSHA256Len {
		return CID{}, fmt.Errorf("car: unsupported multihash header 0x%02x 0x%02x", b[2], b[3])
	}
	var c CID
	c.Codec = b[1]
	copy(c.Digest[:], b[4:])
	return c, nil
}

// Block represents a single IPLD block inside a CARv1 stream.
type Block struct {
	CID  CID
	Data []byte
}

// Header represents the CARv1 DAG-CBOR header.
type Header struct {
	Version uint64
	Roots   []CID
}

// encodeHeaderCBOR encodes a CARv1 header as deterministic DAG-CBOR:
//
//	{ "roots": [ Tag(42, 0x00 || root_cid_bytes) ], "version": 1 }
//
// Per RFC 8949 / DAG-CBOR canonical map key ordering, "roots" (length 5)
// precedes "version" (length 7).
func encodeHeaderCBOR(root CID) []byte {
	var buf bytes.Buffer
	// Map of 2 pairs: 0xa2
	buf.WriteByte(0xa2)

	// Key 1: text string "roots" (length 5 -> 0x65)
	buf.WriteByte(0x65)
	buf.WriteString("roots")

	// Value 1: array of 1 item (0x81)
	buf.WriteByte(0x81)
	// CBOR Tag 42 (IPLD CID link): 0xd8 0x2a
	buf.WriteByte(0xd8)
	buf.WriteByte(0x2a)
	// Byte string of length 37 (0x00 multibase identity prefix + 36-byte CIDv1): 0x58 0x25
	cidBytes := root.Bytes()
	buf.WriteByte(0x58)
	buf.WriteByte(byte(1 + len(cidBytes)))
	buf.WriteByte(0x00)
	buf.Write(cidBytes)

	// Key 2: text string "version" (length 7 -> 0x67)
	buf.WriteByte(0x67)
	buf.WriteString("version")
	// Value 2: unsigned int 1 (0x01)
	buf.WriteByte(0x01)

	return buf.Bytes()
}

// decodeHeaderCBOR decodes the CARv1 DAG-CBOR header written by encodeHeaderCBOR
// (and compatible standard CARv1 encoders with 1 or more CIDv1 SHA-256 roots).
func decodeHeaderCBOR(b []byte) (*Header, error) {
	expectedPrefix := []byte{0xa2, 0x65, 'r', 'o', 'o', 't', 's'}
	if !bytes.HasPrefix(b, expectedPrefix) {
		return nil, errors.New("car: invalid CARv1 DAG-CBOR header prefix")
	}
	pos := len(expectedPrefix)
	if pos >= len(b) {
		return nil, errors.New("car: truncated CARv1 header at roots array")
	}
	arrHeader := b[pos]
	pos++
	if arrHeader < 0x80 || arrHeader > 0x97 {
		return nil, fmt.Errorf("car: unsupported roots array header 0x%02x", arrHeader)
	}
	rootCount := int(arrHeader - 0x80)
	roots := make([]CID, 0, rootCount)
	for i := 0; i < rootCount; i++ {
		if pos+4 > len(b) {
			return nil, errors.New("car: truncated CID tag in CARv1 header")
		}
		if b[pos] != 0xd8 || b[pos+1] != 0x2a {
			return nil, fmt.Errorf("car: expected CBOR tag 42 (0xd82a), got 0x%02x%02x", b[pos], b[pos+1])
		}
		pos += 2
		var byteLen int
		if b[pos] == 0x58 {
			byteLen = int(b[pos+1])
			pos += 2
		} else if b[pos] >= 0x40 && b[pos] <= 0x57 {
			byteLen = int(b[pos] - 0x40)
			pos++
		} else {
			return nil, fmt.Errorf("car: unexpected byte string header 0x%02x", b[pos])
		}
		if pos+byteLen > len(b) || byteLen < 2 {
			return nil, errors.New("car: truncated CID bytes in CARv1 header")
		}
		if b[pos] != 0x00 {
			return nil, fmt.Errorf("car: expected 0x00 identity multibase prefix in tag 42, got 0x%02x", b[pos])
		}
		cid, err := CIDFromBytes(b[pos+1 : pos+byteLen])
		if err != nil {
			return nil, err
		}
		roots = append(roots, cid)
		pos += byteLen
	}
	versionSuffix := []byte{0x67, 'v', 'e', 'r', 's', 'i', 'o', 'n', 0x01}
	if !bytes.Equal(b[pos:], versionSuffix) {
		return nil, errors.New("car: invalid or unsupported CAR version in header (expected version 1)")
	}
	return &Header{
		Version: 1,
		Roots:   roots,
	}, nil
}

// WriteCAR writes a complete IPLD CARv1 stream with the given root CID and
// ordered blocks to w.
func WriteCAR(w io.Writer, root CID, blocks []Block) error {
	headerBytes := encodeHeaderCBOR(root)
	if err := writeSection(w, headerBytes); err != nil {
		return fmt.Errorf("car: write header: %w", err)
	}
	for i, blk := range blocks {
		if !blk.CID.Verify(blk.Data) {
			return fmt.Errorf("car: block %d CID digest mismatch before write", i)
		}
		cidBytes := blk.CID.Bytes()
		section := make([]byte, len(cidBytes)+len(blk.Data))
		copy(section, cidBytes)
		copy(section[len(cidBytes):], blk.Data)
		if err := writeSection(w, section); err != nil {
			return fmt.Errorf("car: write block %d: %w", i, err)
		}
	}
	return nil
}

// ReadCAR reads and cryptographically verifies all blocks in a CARv1 stream.
func ReadCAR(r io.Reader) (*Header, []Block, error) {
	br := &byteReader{r: r}
	headerBytes, err := readSection(br)
	if err != nil {
		return nil, nil, fmt.Errorf("car: read header: %w", err)
	}
	hdr, err := decodeHeaderCBOR(headerBytes)
	if err != nil {
		return nil, nil, err
	}
	var blocks []Block
	for {
		section, err := readSection(br)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("car: read block section %d: %w", len(blocks), err)
		}
		if len(section) < cidV1SHA256ByteLen {
			return nil, nil, fmt.Errorf("car: block section %d shorter than CIDv1 (%d bytes)", len(blocks), len(section))
		}
		cid, err := CIDFromBytes(section[:cidV1SHA256ByteLen])
		if err != nil {
			return nil, nil, fmt.Errorf("car: block %d CID decode: %w", len(blocks), err)
		}
		data := section[cidV1SHA256ByteLen:]
		if !cid.Verify(data) {
			return nil, nil, fmt.Errorf("car: block %d (%s) failed SHA-256 multihash verification", len(blocks), cid.String())
		}
		blocks = append(blocks, Block{
			CID:  cid,
			Data: data,
		})
	}
	return hdr, blocks, nil
}

func writeSection(w io.Writer, body []byte) error {
	var lenBuf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(lenBuf[:], uint64(len(body)))
	if _, err := w.Write(lenBuf[:n]); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

type byteReader struct {
	r   io.Reader
	buf [1]byte
}

func (b *byteReader) ReadByte() (byte, error) {
	_, err := io.ReadFull(b.r, b.buf[:])
	return b.buf[0], err
}

func readSection(br *byteReader) ([]byte, error) {
	length, err := binary.ReadUvarint(br)
	if err != nil {
		return nil, err
	}
	if length == 0 || length > 64*1024*1024 {
		return nil, fmt.Errorf("car: invalid section length %d", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(br.r, buf); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return buf, nil
}
