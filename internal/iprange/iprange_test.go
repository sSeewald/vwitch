package iprange

import (
	"net/netip"
	"slices"
	"testing"
)

func r(a, b string) Range { return Range{netip.MustParseAddr(a), netip.MustParseAddr(b)} }

func TestFromPrefix(t *testing.T) {
	for p, want := range map[string]Range{
		"10.0.0.0/8":    r("10.0.0.0", "10.255.255.255"),
		"1.2.3.4/32":    r("1.2.3.4", "1.2.3.4"),
		"2001:db8::/32": r("2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"),
	} {
		if got := FromPrefix(netip.MustParsePrefix(p)); got != want {
			t.Errorf("%s: %v", p, got)
		}
	}
}

func TestMergeSubtract(t *testing.T) {
	got := Merge([]Range{r("10.0.0.5", "10.0.0.9"), r("2001:db8::", "2001:db8::1"), r("10.0.0.0", "10.0.0.4"), r("10.0.0.8", "10.0.1.0"), r("11.0.0.0", "11.0.0.1")})
	want := []Range{r("10.0.0.0", "10.0.1.0"), r("11.0.0.0", "11.0.0.1"), r("2001:db8::", "2001:db8::1")}
	if !slices.Equal(got, want) {
		t.Fatalf("merge %v", got)
	}
	got = Subtract([]Range{r("10.0.0.0", "10.0.0.255")}, []Range{r("10.0.0.10", "10.0.0.19"), r("10.0.0.250", "10.0.1.5"), r("2001:db8::", "2001:db8::1")})
	want = []Range{r("10.0.0.0", "10.0.0.9"), r("10.0.0.20", "10.0.0.249")}
	if !slices.Equal(got, want) {
		t.Fatalf("subtract %v", got)
	}
	if got := Subtract([]Range{r("10.0.0.1", "10.0.0.2")}, []Range{r("10.0.0.0", "10.0.0.255")}); len(got) != 0 {
		t.Fatalf("fully cut %v", got)
	}
}
