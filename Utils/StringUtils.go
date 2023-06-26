package Utils

import (
	"bytes"
	"strings"
)

func FindSubstr(text, prefix, suffix string) string {
	start := strings.Index(text, prefix)
	if start == -1 {
		return ""
	}
	end := strings.LastIndex(text, suffix)
	if end == -1 {
		return ""
	}
	return text[start : end+len(suffix)]
}

func FindSubBytes(src, prefix, suffix []byte) []byte {
	start := bytes.Index(src, prefix)
	if start == -1 {
		return nil
	}
	end := bytes.LastIndex(src, suffix)
	if end == -1 {
		return nil
	}
	return src[start : end+len(suffix)]
}
