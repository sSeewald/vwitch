// Package geo maps addresses to countries using the delegation statistics
// of the five regional internet registries. They are public, need no
// license key and name the country an address range is registered to (not
// where a server stands). Parsing and lookups are pure; Fetch downloads.
package geo

import (
	"bufio"
	"cmp"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sseewald/vwitch/internal/iprange"
)

// Sources are the registries' daily delegation files.
var Sources = []string{
	"https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
	"https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
	"https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
	"https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
	"https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
}

// DB holds the registered ranges, sorted and non-overlapping per family.
type DB struct {
	Updated time.Time
	recs    []rec
}

type rec struct {
	r  iprange.Range
	cc string
}

// Len is the number of ranges.
func (db *DB) Len() int {
	if db == nil {
		return 0
	}
	return len(db.recs)
}

// Country returns the country code a is registered to, or "".
func (db *DB) Country(a netip.Addr) string {
	if db == nil {
		return ""
	}
	a = a.Unmap()
	i, _ := slices.BinarySearchFunc(db.recs, a, func(x rec, a netip.Addr) int { return x.r.From.Compare(a) })
	// i is the first range starting after a (or at a)
	for _, j := range []int{i, i - 1} {
		if j >= 0 && j < len(db.recs) && db.recs[j].r.Contains(a) {
			return db.recs[j].cc
		}
	}
	return ""
}

// Ranges returns the merged ranges of the given countries.
func (db *DB) Ranges(countries []string) []iprange.Range {
	if db == nil {
		return nil
	}
	var out []iprange.Range
	for _, r := range db.recs {
		if slices.Contains(countries, r.cc) {
			out = append(out, r.r)
		}
	}
	return iprange.Merge(out)
}

// Parse reads registry delegation files (or a saved database, which uses
// the same line format) and keeps allocated and assigned ranges.
func Parse(r io.Reader) (*DB, error) {
	db := &DB{}
	if err := db.add(r); err != nil {
		return nil, err
	}
	db.sort()
	return db, nil
}

func (db *DB) add(r io.Reader) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		if rr, ok := parseLine(sc.Text()); ok {
			db.recs = append(db.recs, rr)
		}
	}
	return sc.Err()
}

func (db *DB) sort() {
	slices.SortFunc(db.recs, func(a, b rec) int { return cmp.Or(a.r.From.Compare(b.r.From), a.r.To.Compare(b.r.To)) })
}

// parseLine reads "registry|cc|type|start|value|date|status[|...]".
func parseLine(line string) (rec, bool) {
	f := strings.Split(line, "|")
	if len(f) < 7 || len(f[1]) != 2 || f[1] == "ZZ" {
		return rec{}, false
	}
	if f[6] != "allocated" && f[6] != "assigned" {
		return rec{}, false
	}
	start, err := netip.ParseAddr(f[3])
	if err != nil {
		return rec{}, false
	}
	n, err := strconv.ParseUint(f[4], 10, 64)
	if err != nil || n == 0 {
		return rec{}, false
	}
	cc := strings.ToUpper(f[1])
	switch f[2] {
	case "ipv4":
		if !start.Is4() || n > 1<<32 {
			return rec{}, false
		}
		end := new(big.Int).Add(new(big.Int).SetBytes(start.AsSlice()), big.NewInt(int64(n-1)))
		if end.BitLen() > 32 {
			return rec{}, false
		}
		var b [4]byte
		end.FillBytes(b[:])
		return rec{iprange.Range{From: start, To: netip.AddrFrom4(b)}, cc}, true
	case "ipv6":
		if !start.Is6() || n > 128 {
			return rec{}, false
		}
		p, err := start.Prefix(int(n))
		if err != nil {
			return rec{}, false
		}
		return rec{iprange.FromPrefix(p), cc}, true
	}
	return rec{}, false
}

// Save writes the database compactly (gzip, registry line format), so a
// restart does not need the network.
func (db *DB) Save(w io.Writer) error {
	z := gzip.NewWriter(w)
	bw := bufio.NewWriter(z)
	fmt.Fprintf(bw, "#updated|%d\n", db.Updated.Unix())
	for _, r := range db.recs {
		if r.r.From.Is4() {
			n := new(big.Int).Sub(new(big.Int).SetBytes(r.r.To.AsSlice()), new(big.Int).SetBytes(r.r.From.AsSlice()))
			fmt.Fprintf(bw, "x|%s|ipv4|%s|%s|0|allocated\n", r.cc, r.r.From, n.Add(n, big.NewInt(1)))
		} else {
			bits := 128
			for p := 0; p <= 128; p++ {
				if pp, err := r.r.From.Prefix(p); err == nil && iprange.FromPrefix(pp) == r.r {
					bits = p
					break
				}
			}
			fmt.Fprintf(bw, "x|%s|ipv6|%s|%d|0|allocated\n", r.cc, r.r.From, bits)
		}
	}
	if err := bw.Flush(); err != nil {
		return err
	}
	return z.Close()
}

// Load reads a database written by Save.
func Load(r io.Reader) (*DB, error) {
	z, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	defer func() { _ = z.Close() }()
	br := bufio.NewReader(z)
	head, err := br.ReadString('\n')
	if err != nil || !strings.HasPrefix(head, "#updated|") {
		return nil, errors.New("geo: not a saved database")
	}
	sec, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(head, "#updated|")), 10, 64)
	if err != nil {
		return nil, errors.New("geo: bad header")
	}
	db, err := Parse(br)
	if err != nil {
		return nil, err
	}
	db.Updated = time.Unix(sec, 0)
	return db, nil
}

// Fetch downloads all sources. It fails unless every registry answered,
// so a partial download never replaces a complete database.
func Fetch(ctx context.Context, c *http.Client, sources []string, userAgent string, now time.Time) (*DB, error) {
	db := &DB{Updated: now}
	for _, u := range sources {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", userAgent)
		resp, err := c.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("%s: %s", u, resp.Status)
		}
		before := len(db.recs)
		err = db.add(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", u, err)
		}
		if len(db.recs) == before {
			return nil, fmt.Errorf("%s: no ranges", u)
		}
	}
	db.sort()
	return db, nil
}
