package itsdangerous

import (
	"errors"
	"fmt"
	"hash"
	"strings"
	"time"
)

type TimestampSigner struct {
	MaxAge int64
	*RegularSigner
}

func (s *TimestampSigner) GetTimestamp() int64 {
	return time.Now().Unix()
}

func (s *TimestampSigner) TimestampToDatetime(timestamp int64) time.Time {
	return time.Unix(timestamp, 0)
}

func (s *TimestampSigner) Sign(value string) string {
	timestamp := base64Encode(intToBytes(s.GetTimestamp()))
	value = value + s.Sep + timestamp
	return s.RegularSigner.Sign(value)
}

func (s *TimestampSigner) UnSign(signedValue string) (string, error) {
	result, err := s.RegularSigner.UnSign(signedValue)
	if err != nil {
		return "", err
	}

	index := strings.LastIndex(result, s.Sep)
	if index < 0 {
		return "", errors.New("timestamp missing")
	}
	value, ts := result[:index], result[index+len(s.Sep):]

	tsBytes, err := base64Decode(ts)
	if err != nil {
		return "", err
	}
	tsInt := bytesToInt(tsBytes)

	if s.MaxAge > 0 {
		age := s.GetTimestamp() - tsInt
		if age > s.MaxAge {
			return "", fmt.Errorf("signature age %d > %d seconds", age, s.MaxAge)
		}
	}

	return value, nil
}

func NewTimestampSigner(secretKey, salt, sep, keyDerivation string, digestMethod func() hash.Hash, algorithm SigningAlgorithm, maxAge int64) *TimestampSigner {
	s := NewRegularSigner(secretKey, salt, sep, keyDerivation, digestMethod, algorithm)
	return &TimestampSigner{RegularSigner: s, MaxAge: maxAge}
}
