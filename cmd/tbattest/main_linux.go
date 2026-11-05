// tbattest issues an attestation from an operator's reviewed validation bundle.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"github.com/EdwinJdevops/trust-boundary/evidence"
	"github.com/EdwinJdevops/trust-boundary/internal/evidencefiles"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "DENIED:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	f := flag.NewFlagSet("tbattest", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	policy := f.String("policy", "", "trusted policy JSON")
	id := f.String("validator", "", "enrolled validator identity")
	keyPath := f.String("key", "", "private Ed25519 PKCS#8 DER file")
	statement := f.String("statement", "", "reviewed unsigned statement")
	source := f.String("source", "", "source archive")
	artifact := f.String("artifact", "", "artifact file")
	suite := f.String("suite", "", "suite manifest")
	logs := f.String("logs", "", "fixed-name log directory")
	if err := f.Parse(args); err != nil || f.NArg() != 0 {
		return errors.New("invalid issuance arguments")
	}
	for _, value := range []*string{policy, id, keyPath, statement, source, artifact, suite, logs} {
		if *value == "" {
			return errors.New("required flags: --policy --validator --key --statement --source --artifact --suite --logs")
		}
	}
	p, err := evidencefiles.Policy(*policy)
	if err != nil {
		return err
	}
	pub, ok := p.Keys[*id]
	if !ok {
		return errors.New("validator is absent from trusted policy")
	}
	s, err := evidencefiles.Statement(*statement)
	if err != nil {
		return err
	}
	if err = p.CheckStatement(s, time.Now()); err != nil {
		return err
	}
	if err = evidencefiles.CheckBundle(s, *source, *artifact, *suite, *logs); err != nil {
		return err
	}
	key, err := readKey(*keyPath)
	if err != nil {
		return err
	}
	defer clear(key)
	if !bytes.Equal(key.Public().(ed25519.PublicKey), pub) {
		return errors.New("private key does not match enrolled validator")
	}
	if err = p.CheckStatement(s, time.Now()); err != nil {
		return err
	}
	a, err := evidence.Sign(s, *id, key)
	if err != nil {
		return err
	}
	encoded, err := evidence.Canonical(a)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(encoded))
	return err
}

func readKey(path string) (ed25519.PrivateKey, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("cannot open validator key")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, errors.New("cannot inspect validator key")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	mode := info.Mode().Perm()
	if !info.Mode().IsRegular() || !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || (mode != 0400 && mode != 0600) {
		return nil, errors.New("validator key must be a private regular file owned by the signer")
	}
	const maxKey = 4096
	raw, err := io.ReadAll(io.LimitReader(f, maxKey+1))
	defer clear(raw)
	if err != nil || len(raw) > maxKey {
		return nil, errors.New("cannot read bounded validator key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(raw)
	key, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok {
		return nil, errors.New("validator key must be Ed25519 PKCS#8 DER")
	}
	return key, nil
}
