// tbverify records unsigned evidence, checks bundle integrity, and verifies
// externally signed validator quorums. It never generates or loads private keys.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/EdwinJdevops/trust-boundary/evidence"
)

type stringsFlag []string

func (s *stringsFlag) String() string     { return strings.Join(*s, ",") }
func (s *stringsFlag) Set(v string) error { *s = append(*s, v); return nil }

type diskPolicy struct {
	Commit         string            `json:"commit"`
	SourceSHA256   string            `json:"source_sha256"`
	ArtifactSHA256 string            `json:"artifact_sha256"`
	SuiteSHA256    string            `json:"suite_sha256"`
	Keys           map[string]string `json:"keys"`
	Minimum        int               `json:"minimum"`
	MaxAgeSeconds  int64             `json:"max_age_seconds"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "DENIED:", err)
		os.Exit(1)
	}
}
func read(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("regular input file required")
	}
	b, err := io.ReadAll(io.LimitReader(f, evidence.MaxDocument+1))
	if err != nil {
		return nil, err
	}
	if len(b) > evidence.MaxDocument {
		return nil, errors.New("input too large")
	}
	return b, nil
}
func emit(w io.Writer, v any) error {
	b, err := evidence.Canonical(v)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(b))
	return err
}
func statement(path string) (evidence.Statement, error) {
	var s evidence.Statement
	b, err := read(path)
	if err != nil {
		return s, err
	}
	if err = evidence.Decode(b, &s); err != nil {
		return s, err
	}
	return s, s.Validate()
}
func sameFileHash(path, expected string) error {
	hash, err := evidence.HashFile(path, 128<<20)
	if err != nil {
		return err
	}
	if hash != expected {
		return errors.New("file differs from recorded digest")
	}
	return nil
}
func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: tbverify record|inspect|verify (no keys are generated)")
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	switch args[0] {
	case "record":
		commit := f.String("commit", "", "full Git commit")
		source := f.String("source", "", "git archive file")
		artifact := f.String("artifact", "", "built artifact")
		suite := f.String("suite", "", "trusted suite manifest")
		logs := f.String("logs", "", "fixed-name log directory")
		gov := f.String("go-version", "", "Go version")
		start := f.Int64("started-at", 0, "Unix start")
		finish := f.Int64("finished-at", 0, "Unix finish")
		var checks stringsFlag
		f.Var(&checks, "check", "check-name=exit-code, in required order")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return errors.New("unexpected arguments")
		}
		s := evidence.Statement{Version: 1, Commit: *commit, GoVersion: *gov, Platform: "linux/amd64", StartedAt: *start, FinishedAt: *finish}
		var err error
		s.SourceSHA256, err = evidence.HashFile(*source, 128<<20)
		if err != nil {
			return err
		}
		s.ArtifactSHA256, err = evidence.HashFile(*artifact, 128<<20)
		if err != nil {
			return err
		}
		s.SuiteSHA256, err = evidence.HashFile(*suite, 128<<20)
		if err != nil {
			return err
		}
		s.EnvironmentSHA256, err = evidence.HashFile(filepath.Join(*logs, "environment.log"), evidence.MaxLog)
		if err != nil {
			return err
		}
		required := evidence.RequiredChecks()
		if len(checks) != len(required) {
			return errors.New("all required checks must execute")
		}
		for i, c := range checks {
			parts := strings.Split(c, "=")
			if len(parts) != 2 || parts[0] != required[i] {
				return errors.New("unexpected check or order")
			}
			exit, err := strconv.Atoi(parts[1])
			if err != nil {
				return err
			}
			hash, err := evidence.HashFile(filepath.Join(*logs, required[i]+".log"), evidence.MaxLog)
			if err != nil {
				return err
			}
			s.Checks = append(s.Checks, evidence.Check{Name: parts[0], ExitCode: exit, LogSHA256: hash})
		}
		if err = s.Validate(); err != nil {
			return err
		}
		return emit(out, s)
	case "inspect":
		path := f.String("statement", "", "canonical unsigned statement")
		logs := f.String("logs", "", "fixed-name log directory")
		source := f.String("source", "", "source archive")
		artifact := f.String("artifact", "", "artifact file")
		suite := f.String("suite", "", "suite manifest")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return errors.New("unexpected arguments")
		}
		s, err := statement(*path)
		if err != nil {
			return err
		}
		if err = evidence.CheckLogs(s, *logs); err != nil {
			return err
		}
		for _, item := range [][2]string{{*source, s.SourceSHA256}, {*artifact, s.ArtifactSHA256}, {*suite, s.SuiteSHA256}} {
			if err = sameFileHash(item[0], item[1]); err != nil {
				return err
			}
		}
		return emit(out, map[string]any{"integrity": "passed", "authentication": "not-verified", "commit": s.Commit, "statement_sha256": hashStatement(s)})
	case "verify":
		policy := f.String("policy", "", "independently installed trusted JSON policy")
		var inputs stringsFlag
		f.Var(&inputs, "attestation", "canonical signed attestation, repeat for quorum")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return errors.New("unexpected arguments")
		}
		b, err := read(*policy)
		if err != nil {
			return err
		}
		var raw diskPolicy
		// Policy must also use canonical JSON. It is installed independently,
		// never populated from values or keys supplied by an untrusted bundle.
		if err = evidence.Decode(b, &raw); err != nil {
			return err
		}
		p := evidence.Policy{Commit: raw.Commit, SourceSHA256: raw.SourceSHA256, ArtifactSHA256: raw.ArtifactSHA256, SuiteSHA256: raw.SuiteSHA256, Minimum: raw.Minimum, Keys: map[string]ed25519.PublicKey{}}
		if raw.MaxAgeSeconds < 1 || raw.MaxAgeSeconds > 86400 {
			return errors.New("invalid freshness policy")
		}
		p.MaxAge = time.Duration(raw.MaxAgeSeconds) * time.Second
		for id, s := range raw.Keys {
			key, err := hex.DecodeString(s)
			if err != nil {
				return err
			}
			p.Keys[id] = key
		}
		if err = p.Validate(); err != nil {
			return err
		}
		if len(inputs) > 16 {
			return errors.New("too many attestations")
		}
		var attestations []evidence.Attestation
		for _, path := range inputs {
			b, err := read(path)
			if err != nil {
				return err
			}
			var a evidence.Attestation
			if err = evidence.Decode(b, &a); err != nil {
				return err
			}
			attestations = append(attestations, a)
		}
		if err = evidence.VerifyQuorum(attestations, p, time.Now()); err != nil {
			return err
		}
		return emit(out, map[string]any{"authentication": "passed", "validators": len(attestations), "commit": p.Commit})
	default:
		return errors.New("unknown operation")
	}
}
func hashStatement(s evidence.Statement) string { b, _ := json.Marshal(s); return evidence.Hash(b) }
