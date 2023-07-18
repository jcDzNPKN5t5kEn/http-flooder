package Utils

import (
	"bytes"
	"io/ioutil"
	"strings"
)

func FileToList(file string) []string {
		proxyListBytes, err := ioutil.ReadFile(file)
		if err != nil {
			panic(err)
		}
		return strings.Split(string(proxyListBytes), "\n")
}
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
