package storage

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"strings"
)

type Data struct {
	Data     []byte
	PassHash []byte
	Attach   bool
}

type Storage interface {
	Post(data Data, expires int64) (string, error)
	Get(id string) (Data, error)
	Delete(id string) error
}

type IdGenerationError struct{ error }
type DataError struct{ error }
type NotFound struct{ error }
type IoError struct{ error }

func GenerateRandomId() (string, error) {
	key := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", IdGenerationError{err}
	}
	return strings.Replace(base64.URLEncoding.EncodeToString(key), "=", "", -1), nil
}
