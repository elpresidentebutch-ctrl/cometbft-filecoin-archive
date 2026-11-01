// Copyright 2026 James Isham Williams (SYNTHOS Collective)
// Dual-licensed under MIT or Apache-2.0 at your option.

package comet

// Minimal, dependency-free encoders for the exact byte formats CometBFT
// v0.38 hashes and signs: protobuf (as emitted by gogoproto) and the
// RFC 6962 Merkle tree from cometbft/crypto/merkle.

import (
	"crypto/sha256"
	"encoding/binary"
	"math/bits"
	"time"
)

const (
	wireVarint  = 0
	wireFixed64 = 1
	wireBytes   = 2
)

type pbuf []byte

func (b pbuf) tag(field int, wire int) pbuf {
	return binary.AppendUvarint(b, uint64(field)<<3|uint64(wire))
}

// uvarint writes a varint field, omitted when zero (proto3 scalar rules).
func (b pbuf) uvarint(field int, v uint64) pbuf {
	if v == 0 {
		return b
	}
	return binary.AppendUvarint(b.tag(field, wireVarint), v)
}

// int64v writes an int64 varint field (two's complement), omitted when zero.
func (b pbuf) int64v(field int, v int64) pbuf {
	return b.uvarint(field, uint64(v))
}

// sfixed64 writes a fixed 8-byte little-endian field, omitted when zero.
func (b pbuf) sfixed64(field int, v int64) pbuf {
	if v == 0 {
		return b
	}
	return binary.LittleEndian.AppendUint64(b.tag(field, wireFixed64), uint64(v))
}

// bytesField writes a length-delimited field, omitted when empty.
func (b pbuf) bytesField(field int, v []byte) pbuf {
	if len(v) == 0 {
		return b
	}
	return b.message(field, v)
}

// message writes an embedded message field even when it is empty, the way
// gogoproto emits non-nullable fields.
func (b pbuf) message(field int, v []byte) pbuf {
	b = binary.AppendUvarint(b.tag(field, wireBytes), uint64(len(v)))
	return append(b, v...)
}

// timestamp encodes google.protobuf.Timestamp as gogoproto's StdTimeMarshal.
func timestamp(t time.Time) []byte {
	var b pbuf
	b = b.int64v(1, t.Unix())
	b = b.int64v(2, int64(t.Nanosecond()))
	return b
}

// delimited prefixes msg with its uvarint length (protoio.MarshalDelimited).
func delimited(msg []byte) []byte {
	out := binary.AppendUvarint(nil, uint64(len(msg)))
	return append(out, msg...)
}

// Wrapper types used by CometBFT's cdcEncode for header fields. Empty values
// encode to nil.
func stringValue(s string) []byte {
	if s == "" {
		return nil
	}
	return pbuf(nil).bytesField(1, []byte(s))
}

func int64Value(v int64) []byte {
	if v == 0 {
		return nil
	}
	return pbuf(nil).int64v(1, v)
}

func bytesValue(v []byte) []byte {
	if len(v) == 0 {
		return nil
	}
	return pbuf(nil).bytesField(1, v)
}

// MerkleRoot is cometbft/crypto/merkle.HashFromByteSlices: an RFC 6962 tree
// with 0x00 leaf and 0x01 inner-node prefixes; the root of no items is
// SHA-256 of nothing.
func MerkleRoot(items [][]byte) []byte {
	switch len(items) {
	case 0:
		h := sha256.Sum256(nil)
		return h[:]
	case 1:
		h := sha256.Sum256(append([]byte{0}, items[0]...))
		return h[:]
	}
	k := splitPoint(len(items))
	left, right := MerkleRoot(items[:k]), MerkleRoot(items[k:])
	h := sha256.Sum256(append(append([]byte{1}, left...), right...))
	return h[:]
}

// splitPoint returns the largest power of two strictly less than n (n >= 2).
func splitPoint(n int) int {
	k := 1 << (bits.Len(uint(n)) - 1)
	if k == n {
		k >>= 1
	}
	return k
}
