package identity

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

type PasswordParameters struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

func DefaultPasswordParameters() PasswordParameters {
	return PasswordParameters{Memory: 64 * 1024, Iterations: 3, Parallelism: 2, SaltLength: 16, KeyLength: 32}
}

type PasswordHasher struct{ parameters PasswordParameters }

func NewPasswordHasher(parameters PasswordParameters) (*PasswordHasher, error) {
	if parameters.Memory < 8*1024 || parameters.Iterations == 0 || parameters.Parallelism == 0 || parameters.SaltLength < 16 || parameters.KeyLength < 16 {
		return nil, errors.New("unsafe Argon2id parameters")
	}
	return &PasswordHasher{parameters: parameters}, nil
}

func (h *PasswordHasher) Hash(password string) (string, error) {
	if err := validatePassword(password); err != nil {
		return "", err
	}
	salt := make([]byte, h.parameters.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, h.parameters.Iterations, h.parameters.Memory, h.parameters.Parallelism, h.parameters.KeyLength)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, h.parameters.Memory, h.parameters.Iterations, h.parameters.Parallelism, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

func (h *PasswordHasher) Verify(password, encoded string) (valid, needsRehash bool, err error) {
	parameters, salt, expected, err := parsePasswordHash(encoded)
	if err != nil {
		return false, false, err
	}
	actual := argon2.IDKey([]byte(password), salt, parameters.Iterations, parameters.Memory, parameters.Parallelism, uint32(len(expected)))
	valid = subtle.ConstantTimeCompare(actual, expected) == 1
	needsRehash = valid && parameters != h.parameters
	return valid, needsRehash, nil
}

func validatePassword(password string) error {
	if len(password) < 12 || len(password) > 1024 {
		return errors.New("password must contain between 12 and 1024 bytes")
	}
	return nil
}

func parsePasswordHash(encoded string) (PasswordParameters, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return PasswordParameters{}, nil, nil, errors.New("invalid Argon2id hash format")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return PasswordParameters{}, nil, nil, errors.New("unsupported Argon2id version")
	}
	var parameters PasswordParameters
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &parameters.Memory, &parameters.Iterations, &parameters.Parallelism); err != nil {
		return PasswordParameters{}, nil, nil, errors.New("invalid Argon2id parameters")
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil {
		return PasswordParameters{}, nil, nil, errors.New("invalid Argon2id salt")
	}
	key, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil {
		return PasswordParameters{}, nil, nil, errors.New("invalid Argon2id key")
	}
	parameters.SaltLength = uint32(len(salt))
	parameters.KeyLength = uint32(len(key))
	if _, err := NewPasswordHasher(parameters); err != nil {
		return PasswordParameters{}, nil, nil, err
	}
	return parameters, salt, key, nil
}
