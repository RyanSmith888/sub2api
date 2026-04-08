package claude

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/bits"
	"strings"
	"unicode/utf16"
)

const (
	FingerprintSalt = "59cf53e54c78"
	Version         = "2.1.88"

	// CCH 占位符，与真实 Claude Code 一致
	CCHPlaceholder = "00000"

	// xxHash64 常量
	xxhPrime1 uint64 = 0x9E3779B185EBCA87
	xxhPrime2 uint64 = 0xC2B2AE3D27D4EB4F
	xxhPrime3 uint64 = 0x165667B19E3779F9
	xxhPrime4 uint64 = 0x85EBCA77C2B2AE63
	xxhPrime5 uint64 = 0x27D4EB2F165667C5

	// Bun Attestation.zig 中的 seed
	CCHSeed uint64 = 0x6E52736AC806831E

	// CCH 掩码：取低 20 位（结果空间 = 2^20 ≈ 100万）
	CCHMask uint64 = 0xFFFFF
)

// ComputeFingerprint 计算与 Claude Code 完全一致的 3 字符指纹。
func ComputeFingerprint(messageText string) string {
	utf16Units := utf16.Encode([]rune(messageText))
	indices := []int{4, 7, 20}
	var chars []string
	for _, i := range indices {
		if i < len(utf16Units) {
			chars = append(chars, string(rune(utf16Units[i])))
		} else {
			chars = append(chars, "0")
		}
	}
	input := FingerprintSalt + strings.Join(chars, "") + Version
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])[:3]
}

// BuildBillingHeader 构建归属头，cch 使用占位符 00000。
// 真实的 CCH 值需要在完整请求 body 构建后通过 ComputeAndReplaceCCH 计算替换。
func BuildBillingHeader(messageText string) string {
	fp := ComputeFingerprint(messageText)
	return fmt.Sprintf("x-anthropic-billing-header: cc_version=%s.%s; cc_entrypoint=cli; cch=%s;", Version, fp, CCHPlaceholder)
}

// ComputeAndReplaceCCH 在完整的请求 body 上计算真实的 CCH 值并替换占位符。
// 算法：xxHash64(body_with_placeholder, seed=0x6E52736AC806831E) & 0xFFFFF
// 必须在请求 body 完全构建后、发送前调用。
func ComputeAndReplaceCCH(body []byte) []byte {
	placeholder := []byte("cch=" + CCHPlaceholder + ";")
	if !bytes.Contains(body, placeholder) {
		return body
	}
	hash := xxHash64(body, CCHSeed)
	cch := fmt.Sprintf("%05x", hash&CCHMask)
	replacement := []byte("cch=" + cch + ";")
	return bytes.Replace(body, placeholder, replacement, 1)
}

// xxHash64 实现带 seed 的 xxHash64 算法。
// 完全匹配 Bun Attestation.zig 中的实现。
func xxHash64(data []byte, seed uint64) uint64 {
	n := len(data)
	var h uint64

	if n >= 32 {
		v1 := seed + xxhPrime1 + xxhPrime2
		v2 := seed + xxhPrime2
		v3 := seed
		v4 := seed - xxhPrime1

		for len(data) >= 32 {
			v1 = xxh64Round(v1, binary.LittleEndian.Uint64(data[0:8]))
			v2 = xxh64Round(v2, binary.LittleEndian.Uint64(data[8:16]))
			v3 = xxh64Round(v3, binary.LittleEndian.Uint64(data[16:24]))
			v4 = xxh64Round(v4, binary.LittleEndian.Uint64(data[24:32]))
			data = data[32:]
		}

		h = bits.RotateLeft64(v1, 1) + bits.RotateLeft64(v2, 7) +
			bits.RotateLeft64(v3, 12) + bits.RotateLeft64(v4, 18)

		h = xxh64MergeRound(h, v1)
		h = xxh64MergeRound(h, v2)
		h = xxh64MergeRound(h, v3)
		h = xxh64MergeRound(h, v4)
	} else {
		h = seed + xxhPrime5
	}

	h += uint64(n)

	for len(data) >= 8 {
		k := binary.LittleEndian.Uint64(data[0:8])
		k *= xxhPrime2
		k = bits.RotateLeft64(k, 31)
		k *= xxhPrime1
		h ^= k
		h = bits.RotateLeft64(h, 27)*xxhPrime1 + xxhPrime4
		data = data[8:]
	}

	for len(data) >= 4 {
		h ^= uint64(binary.LittleEndian.Uint32(data[0:4])) * xxhPrime1
		h = bits.RotateLeft64(h, 23)*xxhPrime2 + xxhPrime3
		data = data[4:]
	}

	for len(data) > 0 {
		h ^= uint64(data[0]) * xxhPrime5
		h = bits.RotateLeft64(h, 11) * xxhPrime1
		data = data[1:]
	}

	h ^= h >> 33
	h *= xxhPrime2
	h ^= h >> 29
	h *= xxhPrime3
	h ^= h >> 32

	return h
}

func xxh64Round(acc, input uint64) uint64 {
	acc += input * xxhPrime2
	acc = bits.RotateLeft64(acc, 31)
	acc *= xxhPrime1
	return acc
}

func xxh64MergeRound(acc, val uint64) uint64 {
	val = xxh64Round(0, val)
	acc ^= val
	acc = acc*xxhPrime1 + xxhPrime4
	return acc
}
