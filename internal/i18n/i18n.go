// Package i18n translates UI texts. Catalogs are embedded JSON files, one
// per language; the language is taken from a cookie, then Accept-Language,
// then the configured default.
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"slices"
	"strings"
)

//go:embed locales/*.json
var files embed.FS

// Cookie stores an explicit language choice.
const Cookie = "lang"

var catalogs = map[string]map[string]string{}

// Languages lists available languages, sorted.
var Languages []string

func init() {
	entries, err := files.ReadDir("locales")
	if err != nil {
		panic(err)
	}
	for _, e := range entries {
		data, err := files.ReadFile("locales/" + e.Name())
		if err != nil {
			panic(err)
		}
		m := map[string]string{}
		if err := json.Unmarshal(data, &m); err != nil {
			panic(fmt.Sprintf("i18n %s: %v", e.Name(), err))
		}
		lang := strings.TrimSuffix(e.Name(), path.Ext(e.Name()))
		catalogs[lang] = m
		Languages = append(Languages, lang)
	}
	slices.Sort(Languages)
}

// T translates key; args are applied with fmt.Sprintf. Missing keys fall
// back to English, then to the key itself.
// Msg formats key with string arguments; arguments starting with "@" are
// translated keys (e.g. "@exit.block"). Used for logged events.
func Msg(lang, key string, args []string) string {
	a := make([]any, len(args))
	for i, v := range args {
		if k, ok := strings.CutPrefix(v, "@"); ok {
			v = T(lang, k)
		}
		a[i] = v
	}
	return T(lang, key, a...)
}

func T(lang, key string, args ...any) string {
	s, ok := catalogs[lang][key]
	if !ok {
		if s, ok = catalogs["en"][key]; !ok {
			s = key
		}
	}
	if len(args) > 0 && strings.Contains(s, "%") {
		return fmt.Sprintf(s, args...)
	}
	return s
}

// Supported reports whether lang has a catalog.
func Supported(lang string) bool { _, ok := catalogs[lang]; return ok }

// Pick chooses the language for a request.
func Pick(r *http.Request, fallback string) string {
	if c, err := r.Cookie(Cookie); err == nil && Supported(c.Value) {
		return c.Value
	}
	for _, part := range strings.Split(r.Header.Get("Accept-Language"), ",") {
		tag, _, _ := strings.Cut(strings.TrimSpace(part), ";")
		base, _, _ := strings.Cut(strings.ToLower(tag), "-")
		if Supported(base) {
			return base
		}
	}
	if Supported(fallback) {
		return fallback
	}
	return "en"
}
