package i18n

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestCatalogsComplete(t *testing.T) {
	for _, lang := range Languages {
		for k := range catalogs["en"] {
			if _, ok := catalogs[lang][k]; !ok {
				t.Errorf("%s: missing key %q", lang, k)
			}
		}
		for k := range catalogs[lang] {
			if _, ok := catalogs["en"][k]; !ok {
				t.Errorf("%s: key %q not in en", lang, k)
			}
		}
	}
	if !slices.Contains(Languages, "de") || !slices.Contains(Languages, "en") {
		t.Fatal(Languages)
	}
}

func TestPick(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept-Language", "fr-FR,de-DE;q=0.8,en;q=0.5")
	if got := Pick(r, "en"); got != "de" {
		t.Fatalf("got %s", got)
	}
	r.AddCookie(&http.Cookie{Name: Cookie, Value: "en"})
	if got := Pick(r, "de"); got != "en" {
		t.Fatalf("cookie ignored: %s", got)
	}
}
