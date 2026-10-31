package artifact

import (
	"strings"
	"testing"
)

func TestMeasurement(t *testing.T) {
	a, e := Measure(strings.NewReader("abc"), 3)
	if e != nil || a != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("%s %v", a, e)
	}
	b, e := Measure(strings.NewReader("abd"), 3)
	if e != nil || a == b {
		t.Fatal("tampering not distinguished")
	}
	for _, s := range []string{"", "abcd"} {
		if _, e := Measure(strings.NewReader(s), 3); e == nil {
			t.Fatal("size not enforced")
		}
	}
}
