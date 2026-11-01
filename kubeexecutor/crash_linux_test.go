package kubeexecutor

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/EdwinJdevops/trust-boundary/gate"
)

type crashFixture struct {
	Config   Config
	Envelope gate.Envelope
	Manifest []byte
}

// Invoked only as a child of TestKilledExecutorNeverRepeatsUncertainCreate.
// The fixture has an ephemeral synthetic API token and no signing private key.
func TestExecutorCrashHelper(t *testing.T) {
	path := os.Getenv("TB_CRASH_FIXTURE")
	if path == "" {
		t.Skip("subprocess helper")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f crashFixture
	if err = json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	e, err := New(f.Config)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Execute(context.Background(), f.Envelope, f.Manifest, imageHash)
	t.Fatalf("helper returned instead of being killed while awaiting create response: %v", err)
}

func TestKilledExecutorNeverRepeatsUncertainCreate(t *testing.T) {
	for _, persisted := range []bool{false, true} {
		label := "request-not-persisted"
		if persisted {
			label = "persisted-response-lost"
		}
		t.Run(label, func(t *testing.T) {
			doc := document()
			env, pub := signed(t, doc)
			arrived := make(chan struct{}, 1)
			var posts, gets atomic.Int32
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer synthetic-token" {
					t.Error("helper did not authenticate with fixture credential")
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				switch r.Method {
				case http.MethodPost:
					posts.Add(1)
					body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
					if err != nil || !bytes.Equal(body, doc) {
						t.Error("helper sent a different create request")
					}
					arrived <- struct{}{}
					// Model a received request whose acknowledgement never reaches
					// the executor. The GET below independently models either result.
					<-r.Context().Done()
				case http.MethodGet:
					gets.Add(1)
					if !persisted {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					_, _ = w.Write(observed(doc))
				default:
					t.Error("unexpected mutation method")
					w.WriteHeader(http.StatusForbidden)
				}
			}))
			defer s.Close()
			c := config(t, s, pub)
			fixture, err := json.Marshal(crashFixture{c, env, doc})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "fixture.json")
			if err = os.WriteFile(path, fixture, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestExecutorCrashHelper$")
			cmd.Env = []string{"TB_CRASH_FIXTURE=" + path}
			var output bytes.Buffer
			cmd.Stdout, cmd.Stderr = &output, &output
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if cmd.ProcessState == nil {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				}
			}()
			select {
			case <-arrived:
			case <-ctx.Done():
				t.Fatal("helper never reached the uncertain create window")
			}
			// Before killing, require the actual durable request record to exist
			// and contain the signed request. This is not a power-loss proof.
			journal, err := os.ReadFile(filepath.Join(c.JournalDir, env.Intent.Nonce))
			if err != nil {
				t.Fatal(err)
			}
			var record Record
			if json.Unmarshal(journal, &record) != nil || record.Version != 2 || record.Envelope != env || !bytes.Equal(record.Manifest, doc) {
				t.Fatal("create reached API without a complete signed journal")
			}
			if err = cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			if err = cmd.Wait(); err == nil {
				t.Fatal("helper exited successfully instead of receiving SIGKILL")
			}
			status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatalf("wrong helper termination: %v; output: %s", cmd.ProcessState, output.String())
			}
			restarted, err := New(c)
			if err != nil {
				t.Fatal(err)
			}
			o, err := restarted.Recover(context.Background(), env.Intent.Nonce)
			if persisted && (err != nil || o.UID != "uid-1") {
				t.Fatalf("persisted state was not observed: %+v %v", o, err)
			}
			if !persisted && err == nil {
				t.Fatal("missing state reported as recovered")
			}
			if _, err = restarted.Execute(context.Background(), env, doc, imageHash); err == nil {
				t.Fatal("killed operation allowed another create")
			}
			after, err := os.ReadFile(filepath.Join(c.JournalDir, env.Intent.Nonce))
			if err != nil || !bytes.Equal(journal, after) {
				t.Fatal("recovery changed or removed the consumed request record")
			}
			if posts.Load() != 1 || gets.Load() != 1 {
				t.Fatalf("unexpected API calls after process death: POST=%d GET=%d", posts.Load(), gets.Load())
			}
			t.Log("SIGKILL confirmed; consumed journal unchanged; recovery GET only; replay denied")
		})
	}
}
