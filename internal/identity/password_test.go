package identity

import (
	"strings"
	"testing"
)

func TestPasswordHasherRoundTrip(t *testing.T) {
	t.Parallel()
	hasher, err := NewPasswordHasher(PasswordParameters{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 16})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := hasher.Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	valid, needsRehash, err := hasher.Verify("correct horse battery staple", encoded)
	if err != nil || !valid || needsRehash {
		t.Fatalf("Verify() = %v, %v, %v", valid, needsRehash, err)
	}
	valid, _, err = hasher.Verify("wrong password", encoded)
	if err != nil || valid {
		t.Fatalf("wrong password Verify() = %v, %v", valid, err)
	}
}

func TestPasswordHasherRejectsMalformedHash(t *testing.T) {
	t.Parallel()
	hasher, _ := NewPasswordHasher(DefaultPasswordParameters())
	for _, encoded := range []string{"", "$argon2i$v=19$m=65536,t=3,p=2$x$y", "$argon2id$v=18$m=65536,t=3,p=2$x$y"} {
		if _, _, err := hasher.Verify("correct horse battery staple", encoded); err == nil {
			t.Fatalf("Verify(%q) error = nil", encoded)
		}
	}
}

func TestPasswordHasherDetectsRehash(t *testing.T) {
	t.Parallel()
	oldHasher, _ := NewPasswordHasher(PasswordParameters{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 16})
	currentHasher, _ := NewPasswordHasher(PasswordParameters{Memory: 8 * 1024, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 16})
	encoded, _ := oldHasher.Hash(strings.Repeat("a", 12))
	valid, needsRehash, err := currentHasher.Verify(strings.Repeat("a", 12), encoded)
	if err != nil || !valid || !needsRehash {
		t.Fatalf("Verify() = %v, %v, %v", valid, needsRehash, err)
	}
}

func TestPasswordHasherRejectsShortPassword(t *testing.T) {
	t.Parallel()
	hasher, _ := NewPasswordHasher(DefaultPasswordParameters())
	if _, err := hasher.Hash("too-short"); err == nil {
		t.Fatal("Hash() error = nil")
	}
}
