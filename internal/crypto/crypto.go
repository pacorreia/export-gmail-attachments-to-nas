package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"sync"
)

var (
	mu        sync.RWMutex
	secretKey []byte
)

// Init derives and stores the AES-GCM encryption key from key.
// Must be called before Encrypt or Decrypt. Returns an error if key is empty.
func Init(key string) error {
	if key == "" {
		return errors.New("encryption key must not be empty")
	}
	h := sha256.Sum256([]byte(key))
	mu.Lock()
	secretKey = h[:]
	mu.Unlock()
	return nil
}

func activeKey() ([]byte, error) {
	mu.RLock()
	k := secretKey
	mu.RUnlock()
	if k == nil {
		return nil, errors.New("crypto not initialised: call crypto.Init first")
	}
	return k, nil
}

// Encrypt AES-GCM encrypts plaintext and returns a base64-encoded ciphertext.
func Encrypt(plaintext string) (string, error) {
	k, err := activeKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt AES-GCM decrypts a base64-encoded ciphertext produced by Encrypt.
func Decrypt(ciphertext string) (string, error) {
	k, err := activeKey()
	if err != nil {
		return "", err
	}
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	nonce, data := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
