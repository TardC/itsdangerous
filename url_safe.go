package itsdangerous

import (
	"bytes"
	"compress/zlib"
)

type URLSafeSerializer struct {
	*RegularSerializer
}

func (s *URLSafeSerializer) dumpPayload(obj any) ([]byte, error) {
	payload, err := s.RegularSerializer.dumpPayload(obj)
	if err != nil {
		return nil, err
	}

	isCompressed := false
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	_, err = w.Write(payload)
	if err != nil {
		return nil, err
	}
	err = w.Close()
	if err != nil {
		return nil, err
	}

	if len(b.Bytes()) < len(payload)-1 {
		payload = b.Bytes()
		isCompressed = true
	}

	base64d := base64Encode(payload)
	if isCompressed {
		base64d = "." + base64d
	}

	return []byte(base64d), nil
}

func (s *URLSafeSerializer) Dumps(obj any) (string, error) {
	payload, err := s.dumpPayload(obj)
	if err != nil {
		return "", err
	}

	rv := s.Signer.Sign(string(payload))
	return rv, nil
}
