package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/scrypt"
)

// scrypt parameters for passwords and client secrets at rest.
const (
	scryptN      = 16384
	scryptR      = 8
	scryptP      = 1
	scryptKeyLen = 32
	saltLen      = 16
)

// HashSecret hashes a password or client secret with scrypt. The encoded form
// is "scrypt$<salt-b64>$<hash-b64>".
func HashSecret(plain string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk, err := scrypt.Key([]byte(plain), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("scrypt$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(dk)), nil
}

// VerifySecret checks a plaintext against an encoded scrypt hash.
func VerifySecret(plain, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 3 || parts[0] != "scrypt" {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	got, err := scrypt.Key([]byte(plain), salt, scryptN, scryptR, scryptP, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// HashToken hashes opaque token material (refresh tokens, auth codes, device
// codes) with SHA-256 so plaintext values never sit in the store.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
