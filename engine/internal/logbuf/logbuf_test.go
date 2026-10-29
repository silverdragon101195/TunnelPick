package logbuf

import (
	"strings"
	"testing"
)

func TestRedactRemovesKeyMaterial(t *testing.T) {
	const key = "YAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
	cases := []string{
		"PrivateKey = " + key,
		"private_key=" + key,
		"handshake with peer " + key + " failed",
		"PresharedKey: " + key,
	}
	for _, c := range cases {
		got := Redact(c)
		if strings.Contains(got, key) || strings.Contains(got, "YAnz5TF") {
			t.Errorf("key leaked: %q -> %q", c, got)
		}
	}
}

func TestRingKeepsOnlyTheLastLines(t *testing.T) {
	b := New(3)
	for i := 0; i < 5; i++ {
		b.Printf("line %d", i)
	}
	got := b.Tail(0)
	if len(got) != 3 || !strings.HasSuffix(got[0], "line 2") || !strings.HasSuffix(got[2], "line 4") {
		t.Fatalf("unexpected tail %v", got)
	}
}
