package itsdangerous

import (
	"encoding/json"
)

type Marshaller interface {
	Marshal(v any) ([]byte, error)
}

type JSONMarshaller struct {
}

func (m *JSONMarshaller) Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

type RegularSerializer struct {
	Marshaller Marshaller
	Signer     Signer
}

func (s *RegularSerializer) dumpPayload(obj any) ([]byte, error) {
	return s.Marshaller.Marshal(obj)
}

func (s *RegularSerializer) Dumps(obj any) (string, error) {
	payload, err := s.dumpPayload(obj)
	if err != nil {
		return "", err
	}

	rv := s.Signer.Sign(string(payload))
	return rv, nil
}
