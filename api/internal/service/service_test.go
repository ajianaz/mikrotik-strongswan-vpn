package service

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// --- validateName tests ---

func TestValidateName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"empty string", "", true},
		{"single char", "a", false},
		{"max length 128", strings.Repeat("a", 128), false},
		{"too long 129", strings.Repeat("a", 129), true},
		{"mixed valid", "My Tunnel-01", false},
		{"has slash", "has/slash", true},
		{"has backslash", "has\\backslash", true},
		{"has dollar sign", "has$sign", true},
		{"has backtick", "has`backtick", true},
		{"has dots path traversal", "has..dots", true},
		{"has tab", "has\ttab", true},
		{"has null byte", "has\x00null", true},
		{"has space", "has space", false},
		{"has underscore", "has_underscore", false},
		{"has hyphen", "has-hyphen", false},
		{"has plus", "has+plus", true},
		{"has at", "has@at", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateName(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if err != nil && tt.wantErr {
				if !errors.Is(err, ErrInvalidName) {
					t.Errorf("validateName(%q) error = %v, should wrap ErrInvalidName", tt.input, err)
				}
			}
		})
	}
}

// --- generatePassword tests ---

func TestGeneratePassword_Length(t *testing.T) {
	pw, err := generatePassword()
	if err != nil {
		t.Fatalf("generatePassword() error: %v", err)
	}
	// 24 bytes → 32 base64 chars (with padding)
	if len(pw) != 32 {
		t.Errorf("generatePassword() length = %d, want 32", len(pw))
	}
}

func TestGeneratePassword_Unique(t *testing.T) {
	pw1, err := generatePassword()
	if err != nil {
		t.Fatalf("generatePassword() call 1 error: %v", err)
	}
	pw2, err := generatePassword()
	if err != nil {
		t.Fatalf("generatePassword() call 2 error: %v", err)
	}
	if pw1 == pw2 {
		t.Error("generatePassword() produced identical passwords on successive calls")
	}
}

// --- generatePSK tests ---

func TestGeneratePSK_Length(t *testing.T) {
	psk, err := generatePSK()
	if err != nil {
		t.Fatalf("generatePSK() error: %v", err)
	}
	if len(psk) != 32 {
		t.Errorf("generatePSK() length = %d, want 32", len(psk))
	}
	// Must be hex
	matched := regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(psk)
	if !matched {
		t.Errorf("generatePSK() = %q, want 32-char hex string", psk)
	}
}

// --- generateUsername tests ---

func TestGenerateUsername_Format(t *testing.T) {
	username := generateUsername("Test")
	matched := regexp.MustCompile(`^[a-z0-9-]+-[a-f0-9]{8}$`).MatchString(username)
	if !matched {
		t.Errorf("generateUsername(\"Test\") = %q, does not match pattern ^[a-z0-9-]+-[a-f0-9]{8}$", username)
	}
}

func TestGenerateUsername_MaxLength(t *testing.T) {
	username := generateUsername("Test")
	if len(username) > 36 {
		t.Errorf("generateUsername(\"Test\") length = %d, want <= 36", len(username))
	}
}

// --- hashPassword tests ---

func TestHashPassword_Format(t *testing.T) {
	hash, err := hashPassword("test123")
	if err != nil {
		t.Fatalf("hashPassword() error: %v", err)
	}
	if !strings.HasPrefix(hash, "$2") {
		t.Errorf("hashPassword() = %q, want bcrypt hash starting with $2", hash)
	}
}

func TestHashPassword_Verify(t *testing.T) {
	password := "test123"
	hash, err := hashPassword(password)
	if err != nil {
		t.Fatalf("hashPassword() error: %v", err)
	}
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		t.Errorf("bcrypt.CompareHashAndPassword() failed: %v", err)
	}
}

func TestHashPassword_WrongPassword(t *testing.T) {
	hash, err := hashPassword("correct-password")
	if err != nil {
		t.Fatalf("hashPassword() error: %v", err)
	}
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte("wrong-password"))
	if err == nil {
		t.Error("bcrypt should reject wrong password")
	}
}

// --- ErrInvalidName error wrapping ---

func TestErrInvalidName_ErrorWrapping(t *testing.T) {
	err := validateName("")
	if err == nil {
		t.Fatal("validateName(\"\") should return error")
	}
	if !errors.Is(err, ErrInvalidName) {
		t.Errorf("error = %v, should be unwrap-compatible with ErrInvalidName via errors.Is", err)
	}
}
