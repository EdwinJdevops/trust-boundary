// tbverify records unsigned evidence, checks bundle integrity, and verifies
// externally signed validator quorums. It never generates or loads private keys.
package main

import (
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
	"github.com/EdwinJdevops/trust-boundary/internal/evidencefiles"
)

type stringsFlag []string

func (s *stringsFlag) String() string     { return strings.Join(*s, ",") }
func (s *stringsFlag) Set(v string) error { *s = append(*s, v); return nil }

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "DENIED:", err)
		os.Exit(1)
	}
}
func emit(w io.Writer, v any) error {
	b, err := evidence.Canonical(v)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(b))
	return err
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
		s, err := evidencefiles.Statement(*path)
		if err != nil {
			return err
		}
		if err = evidencefiles.CheckBundle(s, *source, *artifact, *suite, *logs); err != nil {
			return err
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
		p, err := evidencefiles.Policy(*policy)
		if err != nil {
			return err
		}
		if len(inputs) > 16 {
			return errors.New("too many attestations")
		}
		var attestations []evidence.Attestation
		for _, path := range inputs {
			b, err := evidencefiles.Read(path)
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
