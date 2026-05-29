// Package crypto provides AES-256-GCM encryption for sensitive data at rest.
// Used to encrypt VPN tunnel passwords stored in PostgreSQL.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// KeySize is the required key size in bytes for AES-256 (32 bytes).
const KeySize = 32

// Encrypt encrypts plaintext using AES-256-GCM with the given key.
// Returns a base64-encoded string containing: nonce (12 bytes) + ciphertext + tag.
// The key must be exactly 32 bytes (AES-256).
func Encrypt(key, plaintext []byte) (string, error) {
	if len(key) != KeySize {
		return "", fmt.Errorf("encryption key must be %d bytes, got %d", KeySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	// Seal appends ciphertext+tag to nonce
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a base64-encoded ciphertext produced by Encrypt.
// Extracts the nonce from the first 12 bytes, then decrypts.
func Decrypt(key []byte, encoded string) (string, error) {
	if len(key) != KeySize {
		return "", fmt.Errorf("encryption key must be %d bytes, got %d", KeySize, len(key))
	}

	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode base64: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short: %d bytes (need at least %d)", len(data), nonceSize)
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}

	return string(plaintext), nil
}

// GenerateKey creates a random 32-byte AES-256 key, encoded as base64.
// Useful for generating the ENCRYPTION_KEY env var on first run.
func GenerateKey() (string, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("generate key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// DecodeKey decodes a base64-encoded key string into raw bytes.
// Returns an error if the decoded key is not exactly 32 bytes.
func DecodeKey(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("decoded key must be %d bytes, got %d", KeySize, len(key))
	}
	return key, nil
}
