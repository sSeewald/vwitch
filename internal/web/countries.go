package web

import (
	"slices"
	"sync"

	"golang.org/x/text/collate"
	"golang.org/x/text/language"
	"golang.org/x/text/language/display"
)

// Country is one entry of the country picker.
type Country struct {
	Code, Name, Flag string
}

var (
	codesOnce sync.Once
	codes     []string
)

// notAssigned are region codes CLDR knows that are no ISO 3166-1 country
// (exceptionally or user reserved); the registries never use them.
var notAssigned = map[string]bool{"AC": true, "CP": true, "DG": true, "EA": true, "EZ": true, "IC": true,
	"TA": true, "UK": true, "UN": true, "XK": true}

// countryCodes are all assigned ISO 3166-1 alpha-2 country codes: the
// current (canonical) codes that have a name.
func countryCodes() []string {
	codesOnce.Do(func() {
		en := display.Regions(language.English)
		for a := 'A'; a <= 'Z'; a++ {
			for b := 'A'; b <= 'Z'; b++ {
				s := string([]rune{a, b})
				r, err := language.ParseRegion(s)
				if err != nil || !r.IsCountry() || r.Canonicalize().String() != s || notAssigned[s] {
					continue
				}
				if n := en.Name(r); n != "" && n != s {
					codes = append(codes, s)
				}
			}
		}
	})
	return codes
}

// country names a code in the UI language and adds its flag.
func country(lang, code string) Country {
	c := Country{Code: code, Name: code, Flag: flag(code)}
	if r, err := language.ParseRegion(code); err == nil {
		if n := display.Regions(language.Make(lang)).Name(r); n != "" {
			c.Name = n
		}
	}
	return c
}

// countries are all countries sorted by their name in the UI language.
func countries(lang string) []Country {
	out := make([]Country, 0, len(countryCodes()))
	for _, code := range countryCodes() {
		out = append(out, country(lang, code))
	}
	col := collate.New(language.Make(lang))
	slices.SortFunc(out, func(a, b Country) int { return col.CompareString(a.Name, b.Name) })
	return out
}

// flag is the emoji flag of a country code (regional indicator symbols).
func flag(code string) string {
	if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
		return ""
	}
	const base = 0x1F1E6 - 'A'
	return string([]rune{rune(code[0]) + base, rune(code[1]) + base})
}
