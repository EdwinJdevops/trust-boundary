package deploycheck

import (
	"bytes"
	"strings"
	"testing"
)

func TestAmbiguousJSONDenied(t *testing.T) {
	m := valid()
	delete(pod(m), "runAsUser")
	b := render(m)
	cases := map[string][]byte{
		"duplicate root key":     append([]byte(`{"kind":"Other",`), b[1:]...),
		"case alias":             bytes.Replace(b, []byte(`"kind"`), []byte(`"Kind"`), 1),
		"case aliased duplicate": append([]byte(`{"Kind":"Other",`), b[1:]...),
		"duplicate nested key":   bytes.Replace(b, []byte(`"namespace":"staging"`), []byte(`"namespace":"production","namespace":"staging"`), 1),
		"second document":        append(append([]byte{}, b...), b...),
		"oversized document":     []byte(strings.Repeat(" ", 1<<20+1)),
		"malformed document":     []byte(`{"kind":`),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if err := Check(doc, "staging", hash); err == nil {
				t.Fatal("ambiguous JSON accepted")
			}
		})
	}
}

func TestImageRefAttackStringsDenied(t *testing.T) {
	images := []string{
		"example.com/app:latest@sha256:" + hash,
		"example.com/app@@sha256:" + hash,
		"example.com/app\ninvalid@sha256:" + hash,
		"example.com/app?query@sha256:" + hash,
	}
	for _, name := range images {
		t.Run(name, func(t *testing.T) {
			m := valid()
			delete(pod(m), "runAsUser")
			pod(m)["containers"].([]any)[0].(map[string]any)["image"] = name
			if Check(render(m), "staging", hash) == nil {
				t.Fatal("invalid image reference accepted")
			}
		})
	}
}
