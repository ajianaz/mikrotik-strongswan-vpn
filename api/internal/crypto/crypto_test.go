package crypto

import (
	"encoding/base64"
	"strings"
	"testing"
)

// helperKey generates a valid 32-byte key for tests using GenerateKey/DecodeKey.
func helperKey(t *testing.T) []byte {
	t.Helper()
	keyStr, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	key, err := DecodeKey(keyStr)
	if err != nil {
		t.Fatalf("DecodeKey(%q) failed: %v", err, keyStr)
	}
	return key
}

func TestEncrypt_ValidBase64(t *testing.T) {
	key := helperKey(t)
	encoded, err := Encrypt(key, []byte("hello world"))
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}
	// Must be valid base64
	_, err = base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("Encrypt() result is not valid base64: %v", err)
	}
}

func TestEncrypt_DifferentEachTime(t *testing.T) {
	key := helperKey(t)
	encoded1, err := Encrypt(key, []byte("same plaintext"))
	if err != nil {
		t.Fatalf("Encrypt() call 1 error: %v", err)
	}
	encoded2, err := Encrypt(key, []byte("same plaintext"))
	if err != nil {
		t.Fatalf("Encrypt() call 2 error: %v", err)
	}
	if encoded1 == encoded2 {
		t.Error("Encrypt() produced identical output for same plaintext (nonce should differ)")
	}
}

func TestDecrypt_Roundtrip(t *testing.T) {
	key := helperKey(t)
	plaintext := "my secret VPN password!@#$%"
	encoded, err := Encrypt(key, []byte(plaintext))
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}
	decoded, err := Decrypt(key, encoded)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}
	if decoded != plaintext {
		t.Errorf("Decrypt() = %q, want %q", decoded, plaintext)
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	key1 := helperKey(t)
	key2 := helperKey(t)

	encoded, err := Encrypt(key1, []byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	_, err = Decrypt(key2, encoded)
	if err == nil {
		t.Error("Decrypt() with wrong key should return error, got nil")
	}
}

func TestDecrypt_CorruptedBase64(t *testing.T) {
	key := helperKey(t)
	_, err := Decrypt(key, "not-valid-base64!!!")
	if err == nil {
		t.Error("Decrypt() with corrupted base64 should return error, got nil")
	}
}

func TestEncryptDecrypt_EmptyPlaintext(t *testing.T) {
	key := helperKey(t)
	encoded, err := Encrypt(key, []byte(""))
	if err != nil {
		t.Fatalf("Encrypt(empty) error: %v", err)
	}
	decoded, err := Decrypt(key, encoded)
	if err != nil {
		t.Fatalf("Decrypt(empty) error: %v", err)
	}
	if decoded != "" {
		t.Errorf("Decrypt(empty) = %q, want empty string", decoded)
	}
}

func TestGenerateKey_Length(t *testing.T) {
	keyStr, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}
	// 32 bytes base64-encoded = 44 characters (with padding)
	if len(keyStr) != 44 {
		t.Errorf("GenerateKey() length = %d, want 44", len(keyStr))
	}
	// Must be valid base64
	_, err = base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		t.Fatalf("GenerateKey() result is not valid base64: %v", err)
	}
}

func TestDecodeKey_Valid(t *testing.T) {
	keyStr, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}
	key, err := DecodeKey(keyStr)
	if err != nil {
		t.Fatalf("DecodeKey() error: %v", err)
	}
	if len(key) != KeySize {
		t.Errorf("DecodeKey() key length = %d, want %d", len(key), KeySize)
	}
}

func TestDecodeKey_InvalidBase64(t *testing.T) {
	_, err := DecodeKey("not-valid-base64!!!")
	if err == nil {
		t.Error("DecodeKey(invalid base64) should return error, got nil")
	}
}

func TestDecodeKey_WrongLength(t *testing.T) {
	// Create a valid base64 string that decodes to 16 bytes (too short for AES-256)
	shortKey := base64.StdEncoding.EncodeToString(make([]byte, 16))
	_, err := DecodeKey(shortKey)
	if err == nil {
		t.Error("DecodeKey(16-byte key) should return error, got nil")
	}
}

func TestEncrypt_WrongKeySize(t *testing.T) {
	key := helperKey(t)
	_, err := Encrypt(key[:16], []byte("test"))
	if err == nil {
		t.Error("Encrypt() with 16-byte key should return error, got nil")
	}
}

func TestDecrypt_WrongKeySize(t *testing.T) {
	key := helperKey(t)
	_, err := Decrypt(key[:16], "somebase64string")
	if err == nil {
		t.Error("Decrypt() with 16-byte key should return error, got nil")
	}
}

func TestEncryptDecrypt_BinaryPlaintext(t *testing.T) {
	key := helperKey(t)
	// Test with binary data (all byte values)
	plaintext := make([]byte, 256)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}
	encoded, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt(binary) error: %v", err)
	}
	decoded, err := Decrypt(key, encoded)
	if err != nil {
		t.Fatalf("Decrypt(binary) error: %v", err)
	}
	if len(decoded) != len(plaintext) {
		t.Fatalf("Decrypt() length = %d, want %d", len(decoded), len(plaintext))
	}
	if decoded != string(plaintext) {
		t.Error("Decrypt() binary roundtrip mismatch")
	}
}

func TestDecrypt_ShortCiphertext(t *testing.T) {
	key := helperKey(t)
	// Valid base64 but too short to contain nonce
	shortData := base64.StdEncoding.EncodeToString(make([]byte, 4))
	_, err := Decrypt(key, shortData)
	if err == nil {
		t.Error("Decrypt() with too-short ciphertext should return error, got nil")
	}
	// Also test completely empty string
	_, err = Decrypt(key, "")
	if err == nil {
		t.Error("Decrypt() with empty string should return error, got nil")
	}
}

func TestGenerateKey_Unique(t *testing.T) {
	keys := make(map[string]bool)
	for i := 0; i < 100; i++ {
		keyStr, err := GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey() iteration %d error: %v", i, err)
		}
		if keys[keyStr] {
			t.Errorf("GenerateKey() produced duplicate key at iteration %d", i)
		}
		keys[keyStr] = true
	}
}

func TestEncryptDecrypt_LongPlaintext(t *testing.T) {
	key := helperKey(t)
	// Test with a long string
	plaintext := strings.Repeat("abcdefgh", 1000) // 8000 bytes
	encoded, err := Encrypt(key, []byte(plaintext))
	if err != nil {
		t.Fatalf("Encrypt(long) error: %v", err)
	}
	decoded, err := Decrypt(key, encoded)
	if err != nil {
		t.Fatalf("Decrypt(long) error: %v", err)
	}
	if decoded != plaintext {
		t.Error("Decrypt() long plaintext roundtrip mismatch")
	}
}
