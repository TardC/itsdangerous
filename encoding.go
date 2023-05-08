package itsdangerous

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"strings"
)

func base64Encode(bytes []byte) string {
	s := base64.URLEncoding.EncodeToString(bytes)
	return strings.Trim(s, "=")
}

func base64Decode(s string) ([]byte, error) {
	var padLen int

	if l := len(s) % 4; l > 0 {
		padLen = 4 - l
	} else {
		padLen = 1
	}

	b, err := base64.URLEncoding.DecodeString(s + strings.Repeat("=", padLen))
	if err != nil {
		return []byte(""), err
	}
	return b, nil
}

func intToBytes(num int64) []byte {
	numBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(numBytes, uint64(num))
	return bytes.TrimLeft(numBytes, "\x00")
}

func bytesToInt(numBytes []byte) int64 {
	num := binary.BigEndian.Uint64(numBytes)
	return int64(num)
}
