package claude

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf16"
)

const (
	// FingerprintSalt 与 Claude Code 客户端保持一致的盐值
	FingerprintSalt = "59cf53e54c78"
	// Version 当前模拟的 Claude Code 版本号
	Version = "2.1.88"
)

// ComputeFingerprint 计算与 Claude Code 完全一致的 3 字符指纹。
// 算法: SHA256(SALT + msg[4] + msg[7] + msg[20] + version)[:3]
// 使用 UTF-16 code unit 索引以匹配 JavaScript 的 string[i] 行为。
// 对于 BMP 字符（ASCII、中文等）rune 和 UTF-16 等价；
// 对于 emoji 等非 BMP 字符，JS 返回 surrogate 的一半，这里做同样处理。
func ComputeFingerprint(messageText string) string {
	// 将字符串转为 UTF-16 code unit 序列，与 JS string[i] 行为一致
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

// computeCCH 生成一个基于请求内容的 5 字符伪认证哈希，
// 用于填充 cch 字段。真实 Claude Code 由 Bun 原生 HTTP 栈计算，
// 这里用请求内容的 SHA256 衍生值替代以避免全零或缺失。
func computeCCH(messageText, fingerprint string) string {
	input := fingerprint + messageText + Version + FingerprintSalt
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])[:5]
}

// BuildBillingHeader 构建与 Claude Code 一致的归属头字符串。
// 格式: x-anthropic-billing-header: cc_version={VERSION}.{FINGERPRINT}; cc_entrypoint=cli; cch={HASH};
func BuildBillingHeader(messageText string) string {
	fp := ComputeFingerprint(messageText)
	cch := computeCCH(messageText, fp)
	return fmt.Sprintf("x-anthropic-billing-header: cc_version=%s.%s; cc_entrypoint=cli; cch=%s;", Version, fp, cch)
}
