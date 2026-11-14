package config

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	// DefaultHTTPBufferSizeBytes 默认 HTTP 通道 buffer (16KiB)
	DefaultHTTPBufferSizeBytes = 16 * 1024
	// MinHTTPBufferSizeBytes 最小允许值，避免过小导致过多系统调用
	MinHTTPBufferSizeBytes = 1024
	// MaxHTTPBufferSizeBytes 最大允许值，避免异常配置造成内存压力
	MaxHTTPBufferSizeBytes = 1024 * 1024
)

// ParseByteSize 解析字节大小，支持纯数字（字节）以及 K/M 后缀（如 16K, 1M）
func ParseByteSize(input string) (int, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}

	multiplier := 1
	switch last := s[len(s)-1]; last {
	case 'k', 'K':
		multiplier = 1024
		s = strings.TrimSpace(s[:len(s)-1])
	case 'm', 'M':
		multiplier = 1024 * 1024
		s = strings.TrimSpace(s[:len(s)-1])
	}

	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q: %w", input, err)
	}
	if v <= 0 {
		return 0, fmt.Errorf("size must be positive: %q", input)
	}

	bytes := v * multiplier
	if bytes < MinHTTPBufferSizeBytes || bytes > MaxHTTPBufferSizeBytes {
		return 0, fmt.Errorf("size out of range [%d, %d]: %d", MinHTTPBufferSizeBytes, MaxHTTPBufferSizeBytes, bytes)
	}
	return bytes, nil
}
