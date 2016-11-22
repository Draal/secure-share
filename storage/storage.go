package storage

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"strings"
)

type Storage interface {
	Post(data interface{}, expire int64) (string, error)
	Get(id string, data interface{}) error
	Delete(id string) error
}

type IdGenerationError struct{ error }
type DataError struct{ error }
type NotFound struct{ error }

func GenerateRandomId() (string, error) {
	key := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", IdGenerationError{err}
	}
	return strings.Replace(base64.URLEncoding.EncodeToString(key), "=", "", -1), nil
}
