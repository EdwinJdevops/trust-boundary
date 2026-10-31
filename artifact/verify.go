// Package artifact measures exact artifact bytes. This is integrity verification,
// not publisher authentication, provenance verification or a malware verdict.
package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
)

// Measure hashes bytes read through a trusted input, with a strict size bound.
func Measure(r io.Reader, limit int64) (string, error) {
	if limit <= 0 || limit > 64<<20 {
		return "", errors.New("invalid artifact size limit")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(r, limit+1))
	if err != nil {
		return "", err
	}
	if n == 0 || n > limit {
		return "", errors.New("artifact size denied")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
