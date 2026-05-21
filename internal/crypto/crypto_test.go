package crypto

import (
	"strings"
	"testing"
)

func TestInit_EmptyKey(t *testing.T) {
	secretKey = nil
	err := Init("")
	if err == nil {
		t.Fatal("expected error for empty key, got nil")
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	secretKey = nil
	if err := Init("test-secret-key"); err != nil {
		t.Fatalf("Init: %v", err)
	}

	cases := []string{"hello", "", "unicode: 日本語", strings.Repeat("x", 10000)}
	for _, plain := range cases {
		enc, err := Encrypt(plain)
		if err != nil {
			t.Fatalf("Encrypt(%q): %v", plain, err)
		}
		got, err := Decrypt(enc)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if got != plain {
			t.Errorf("round-trip mismatch: got %q, want %q", got, plain)
		}
	}
}

func TestEncrypt_ProducesUniqueCiphertexts(t *testing.T) {
	secretKey = nil
	if err := Init("test-secret-key"); err != nil {
		t.Fatalf("Init: %v", err)
	}
	c1, _ := Encrypt("same")
	c2, _ := Encrypt("same")
	if c1 == c2 {
		t.Error("two encryptions of the same plaintext should produce different ciphertexts (random nonce)")
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	secretKey = nil
	if err := Init("key-a"); err != nil {
		t.Fatalf("Init: %v", err)
	}
	enc, err := Encrypt("secret")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Re-init with a different key — decryption must fail.
	secretKey = nil
	if err := Init("key-b"); err != nil {
		t.Fatalf("Init: %v", err)
	}
	_, err = Decrypt(enc)
	if err == nil {
		t.Error("expected decryption to fail with wrong key")
	}
}

func TestDecrypt_InvalidBase64(t *testing.T) {
	secretKey = nil
	if err := Init("test-key"); err != nil {
		t.Fatalf("Init: %v", err)
	}
	_, err := Decrypt("not-valid-base64!!!")
	if err == nil {
		t.Error("expected error for invalid base64 input")
	}
}

func TestEncryptDecrypt_NotInitialised(t *testing.T) {
	secretKey = nil
	_, err := Encrypt("hello")
	if err == nil {
		t.Error("Encrypt should return error when not initialised")
	}
	_, err = Decrypt("anything")
	if err == nil {
		t.Error("Decrypt should return error when not initialised")
	}
}
