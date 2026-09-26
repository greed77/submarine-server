// Package secret generates tokens and hashes passwords.
package secret

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

// NewToken returns n random bytes, hex encoded.
func NewToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return hex.EncodeToString(b)
}

// Hash is how every token is stored: only its SHA-256 lives in the database.
func Hash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// Argon2id parameters: OWASP's minimum recommendation (19 MiB, 2 passes),
// chosen to stay fast on a Raspberry Pi.
const (
	argonMemory  = 19 * 1024
	argonTime    = 2
	argonThreads = 1
	argonKeyLen  = 32
)

var b64 = base64.RawStdEncoding

// HashPassword returns a PHC-format argon2id hash.
func HashPassword(pw string) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, b64.EncodeToString(salt), b64.EncodeToString(key))
}

// VerifyPassword checks pw against a hash from HashPassword. Hashes made with
// older parameters still verify, since the parameters are read from the hash.
func VerifyPassword(encoded, pw string) bool {
	m, t, p, salt, key, err := parseHash(encoded)
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(key)))
	return subtle.ConstantTimeCompare(got, key) == 1
}

var (
	dummyOnce sync.Once
	dummyHash string
)

// BurnPasswordCheck costs the same as a real VerifyPassword, so unknown
// emails can't be told apart from wrong passwords by timing.
func BurnPasswordCheck(pw string) {
	dummyOnce.Do(func() { dummyHash = HashPassword("dummy password") })
	VerifyPassword(dummyHash, pw)
}

func parseHash(s string) (m, t uint32, p uint8, salt, key []byte, err error) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		err = errors.New("unsupported hash")
		return
	}
	var v int
	if _, err = fmt.Sscanf(parts[2], "v=%d", &v); err != nil {
		return
	}
	if v != argon2.Version {
		err = errors.New("unsupported argon2 version")
		return
	}
	if _, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return
	}
	if salt, err = b64.DecodeString(parts[4]); err != nil {
		return
	}
	key, err = b64.DecodeString(parts[5])
	return
}
