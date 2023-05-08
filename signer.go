package itsdangerous

import (
	"crypto/hmac"
	"crypto/sha1"
	"errors"
	"fmt"
	"hash"
	"strings"
)

type SigningAlgorithm interface {
	GetSignature(key, value string) string
}

type NoneAlgorithm struct {
}

func (a *NoneAlgorithm) GetSignature(key, value string) string {
	return ""
}

type HMACAlgorithm struct {
	DigestMethod func() hash.Hash
}

func (a *HMACAlgorithm) GetSignature(key, value string) string {
	mac := hmac.New(a.DigestMethod, []byte(key))
	mac.Write([]byte(value))
	sum := mac.Sum(nil)
	return string(sum)
}

func VerifySignature(algorithm SigningAlgorithm, key, value, sig string) bool {
	return hmac.Equal([]byte(sig), []byte(algorithm.GetSignature(key, value)))
}

func NewHMACAlgorithm(digestMethod func() hash.Hash) *HMACAlgorithm {
	if digestMethod == nil {
		digestMethod = sha1.New
	}

	return &HMACAlgorithm{DigestMethod: digestMethod}
}

type Signer interface {
	DeriveKey() string
	GetSignature(value string) string
	Sign(value string) string
	VerifySignature(value, sig string) bool
	UnSign(signedValue string) (string, error)
	Validate(signedValue string) bool
}

type RegularSigner struct {
	SecretKey     string
	Salt          string
	Sep           string
	KeyDerivation string
	DigestMethod  func() hash.Hash
	Algorithm     SigningAlgorithm
}

func (s *RegularSigner) DeriveKey() string {
	var key string

	h := s.DigestMethod()

	switch s.KeyDerivation {
	case "concat":
		h.Write([]byte(s.Salt + s.SecretKey))
		key = string(h.Sum(nil))
	case "django-concat":
		h.Write([]byte(s.Salt + "signer" + s.SecretKey))
		key = string(h.Sum(nil))
	case "hmac":
		h := hmac.New(sha1.New, []byte(s.SecretKey))
		h.Write([]byte(s.Salt))
		key = string(h.Sum(nil))
	case "none":
		key = s.SecretKey
	default:
		panic(errors.New("unknown key derivation method"))
	}

	return key
}

func (s *RegularSigner) GetSignature(value string) string {
	key := s.DeriveKey()

	sig := s.Algorithm.GetSignature(key, value)
	return base64Encode([]byte(sig))
}

func (s *RegularSigner) Sign(value string) string {
	sig := s.GetSignature(value)

	return value + s.Sep + sig
}

func (s *RegularSigner) VerifySignature(value, sig string) bool {
	sigDecoded, err := base64Decode(sig)
	if err != nil {
		return false
	}

	key := s.DeriveKey()
	return VerifySignature(s.Algorithm, string(sigDecoded), key, value)
}

func (s *RegularSigner) UnSign(signedValue string) (string, error) {
	index := strings.LastIndex(signedValue, s.Sep)
	if index < 0 {
		return "", fmt.Errorf("no %s found in value", s.Sep)
	}

	value, sig := signedValue[:index], signedValue[index+len(s.Sep):]
	if s.VerifySignature(value, sig) {
		return value, nil
	}

	return "", fmt.Errorf("signature %s does not match", sig)
}

func (s *RegularSigner) Validate(signedValue string) bool {
	_, err := s.UnSign(signedValue)
	if err != nil {
		return false
	}
	return true
}

func NewRegularSigner(secretKey, salt, sep, keyDerivation string, digestMethod func() hash.Hash, algorithm SigningAlgorithm) *RegularSigner {
	if salt == "" {
		salt = "itsdangerous.RegularSigner"
	}

	if sep == "" {
		sep = "."
	}

	if keyDerivation == "" {
		keyDerivation = "django-concat"
	}

	if digestMethod == nil {
		digestMethod = sha1.New
	}

	if algorithm == nil {
		algorithm = NewHMACAlgorithm(digestMethod)
	}

	return &RegularSigner{
		SecretKey:     secretKey,
		Salt:          salt,
		Sep:           sep,
		KeyDerivation: keyDerivation,
		DigestMethod:  digestMethod,
		Algorithm:     algorithm,
	}
}
