package injection

import (
	"crypto/rand"
	"encoding/base32"
)


func GenerateRandomBytes(len int) ([]byte, error) {
	b := make([]byte, len)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func GenerateRandomStringURLSafe(len int) (string, error) {
	b, err := GenerateRandomBytes(len)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), err
}

