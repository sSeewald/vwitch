package geo

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sseewald/vwitch/internal/iprange"
)

const sample = `2.3|ripencc|1700000000|3|19830705|20261105|+0100
ripencc|*|ipv4|*|2|summary
ripencc|RU|ipv4|5.8.0.0|1024|20100101|allocated|x
ripencc|RU|ipv4|5.8.4.0|512|20100101|assigned|x
ripencc|DE|ipv4|2.160.0.0|1048576|20100101|allocated|x
ripencc|RU|ipv4|9.9.9.0|256|20100101|available|x
ripencc|ZZ|ipv4|9.9.8.0|256|20100101|allocated|x
ripencc|RU|ipv6|2a00:1000::/32|0|20100101|allocated|x
ripencc|RU|ipv6|2a00:1000::|32|20100101|allocated|x
ripencc|BY|ipv4|5.8.6.0|300|20100101|allocated|x
`

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestParseLookup(t *testing.T) {
	db, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	for a, want := range map[string]string{
		"5.8.0.1": "RU", "5.8.5.255": "RU", "2.175.255.255": "DE", "5.8.7.43": "BY", "5.8.7.44": "",
		"9.9.9.1": "", "9.9.8.1": "", "2a00:1000:ffff::1": "RU", "1.1.1.1": "",
	} {
		if got := db.Country(addr(a)); got != want {
			t.Errorf("Country(%s) = %q, want %q", a, got, want)
		}
	}
	got := db.Ranges([]string{"RU"})
	want := []iprange.Range{{From: addr("5.8.0.0"), To: addr("5.8.5.255")}, {From: addr("2a00:1000::"), To: addr("2a00:1000:ffff:ffff:ffff:ffff:ffff:ffff")}}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("ranges %v", got)
	}
}

func TestSaveLoad(t *testing.T) {
	db, _ := Parse(strings.NewReader(sample))
	db.Updated = time.Unix(1_700_000_000, 0)
	var buf bytes.Buffer
	if err := db.Save(&buf); err != nil {
		t.Fatal(err)
	}
	db2, err := Load(&buf)
	if err != nil || db2.Len() != db.Len() || !db2.Updated.Equal(db.Updated) || db2.Country(addr("5.8.7.43")) != "BY" ||
		db2.Country(addr("2a00:1000::5")) != "RU" {
		t.Fatalf("load: %v %d", err, db2.Len())
	}
}

func TestFetch(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(sample)) }))
	defer ok.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "x", 500) }))
	defer bad.Close()
	db, err := Fetch(context.Background(), ok.Client(), []string{ok.URL, ok.URL}, "test", time.Now())
	if err != nil || db.Country(addr("5.8.0.1")) != "RU" {
		t.Fatal(err)
	}
	if _, err := Fetch(context.Background(), ok.Client(), []string{ok.URL, bad.URL}, "test", time.Now()); err == nil {
		t.Fatal("a failed registry must fail the update")
	}
}
