package main

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/Draal/secure-share/config"
	"github.com/Draal/secure-share/storage"
)

// spyStorage wraps the memory storage and counts calls, to prove that page
// GETs never touch the storage.
type spyStorage struct {
	storage.Storage
	mu         sync.Mutex
	calls      int
	failDelete bool // Delete fails and leaves the secret in place
}

func (s *spyStorage) count() int { s.mu.Lock(); defer s.mu.Unlock(); return s.calls }
func (s *spyStorage) inc()       { s.mu.Lock(); s.calls++; s.mu.Unlock() }

func (s *spyStorage) Post(d storage.Data, e int64) (string, error) {
	s.inc()
	return s.Storage.Post(d, e)
}
func (s *spyStorage) Get(id, h string) (storage.Data, error) { s.inc(); return s.Storage.Get(id, h) }
func (s *spyStorage) Delete(id string) error {
	s.inc()
	if s.failDelete {
		return errors.New("disk error")
	}
	return s.Storage.Delete(id)
}

const testID = "AbCdEfGhIjKlMnOpQrStUv"

var testConfig struct {
	once sync.Once
	cfg  *config.Config
	err  error
}

func newTestHandler(t *testing.T) (http.Handler, *spyStorage) {
	t.Helper()
	testConfig.once.Do(func() {
		t.Setenv("USE_HASHING", "1")
		testConfig.cfg, testConfig.err = config.OpenFromEnv()
	})
	if testConfig.err != nil {
		t.Fatal(testConfig.err)
	}
	spy := &spyStorage{Storage: storage.OpenMemoryStorage()}
	h, err := newHandler(testConfig.cfg, spy, handlerOptions{SiteURL: "https://encrypt.one", ManageSecret: []byte("test-manage-secret-0123456789abcdef")})
	if err != nil {
		t.Fatal(err)
	}
	return h, spy
}

type req struct {
	method, path string
	headers      map[string]string
}

func do(t *testing.T, h http.Handler, r req) *httptest.ResponseRecorder {
	t.Helper()
	if r.method == "" {
		r.method = http.MethodGet
	}
	rq := httptest.NewRequest(r.method, r.path, nil)
	for k, v := range r.headers {
		rq.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, rq)
	return rec
}

func TestOldLangParamRedirects(t *testing.T) {
	h, _ := newTestHandler(t)
	cases := map[string]string{
		"/?lang=ru":                    "/ru/",
		"/?lang=uk":                    "/uk/",
		"/ru/?lang=en":                 "/",
		"/how-it-works/?lang=uk":       "/uk/how-it-works/",
		"/ru/privacy/?lang=en":         "/privacy/",
		"/?lang=ru&utm=x":              "/ru/?utm=x",
		"/s/" + testID + "?lang=ru":    "/s/" + testID,
		"/password-generator/?lang=ru": "/ru/password-generator/",
	}
	for path, want := range cases {
		rec := do(t, h, req{path: path})
		if rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != want {
			t.Errorf("%s: got %d %q, want 301 %q", path, rec.Code, rec.Header().Get("Location"), want)
		}
		if !strings.Contains(rec.Header().Get("Set-Cookie"), "lang=") {
			t.Errorf("%s: language choice is not saved to the cookie", path)
		}
	}
}

func TestRootLanguageDetection(t *testing.T) {
	h, _ := newTestHandler(t)
	cases := []struct {
		accept, cookie string
		status         int
		location       string
	}{
		{"ru-RU,ru;q=0.9,en;q=0.8", "", http.StatusFound, "/ru/"},
		{"uk,en;q=0.5", "", http.StatusFound, "/uk/"},
		{"en-US,en;q=0.9", "", http.StatusOK, ""},
		{"", "", http.StatusOK, ""},
		{"de-DE,ru;q=0.9", "", http.StatusOK, ""},
		{"ru-RU", "en-us", http.StatusOK, ""},
		{"en-US", "uk-uk", http.StatusFound, "/uk/"},
	}
	for _, c := range cases {
		headers := map[string]string{}
		if c.accept != "" {
			headers["Accept-Language"] = c.accept
		}
		if c.cookie != "" {
			headers["Cookie"] = "lang=" + c.cookie
		}
		rec := do(t, h, req{path: "/", headers: headers})
		if rec.Code != c.status || rec.Header().Get("Location") != c.location {
			t.Errorf("accept %q cookie %q: got %d %q, want %d %q", c.accept, c.cookie, rec.Code, rec.Header().Get("Location"), c.status, c.location)
		}
		if !strings.Contains(strings.Join(rec.Header().Values("Vary"), ","), "Accept-Language") {
			t.Errorf("accept %q: no Vary: Accept-Language", c.accept)
		}
	}
}

func TestThreeLetterLanguageSelection(t *testing.T) {
	h := &Handler{config: &config.Config{Languages: []config.Language{
		{Code: "en-us", Short: "en"},
		{Code: "fi-fi", Short: "fi"},
		{Code: "fil-ph", Short: "fil"},
	}}}
	for _, tc := range []struct {
		name, header, value, want string
	}{
		{"cookie with region", "Cookie", "lang=fil-ph", "fil"},
		{"cookie primary", "Cookie", "lang=fil", "fil"},
		{"Finnish cookie", "Cookie", "lang=fi-fi", "fi"},
		{"browser with region", "Accept-Language", "fil-PH,fi;q=0.8", "fil"},
		{"Finnish browser", "Accept-Language", "fi-FI,fil;q=0.8", "fi"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/s/example", nil)
			r.Header.Set(tc.header, tc.value)
			if got := h.langForUnprefixedPage(r).Short; got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLanguagePagesNeverRedirect(t *testing.T) {
	h, _ := newTestHandler(t)
	for _, path := range []string{"/ru/", "/uk/", "/how-it-works/", "/ru/password-generator/", "/uk/privacy/"} {
		rec := do(t, h, req{path: path, headers: map[string]string{"Accept-Language": "uk", "Cookie": "lang=ru-ru"}})
		if rec.Code != http.StatusOK {
			t.Errorf("%s: got %d, want 200", path, rec.Code)
		}
	}
}

func TestTrailingSlashRedirects(t *testing.T) {
	h, _ := newTestHandler(t)
	cases := map[string]string{
		"/ru":                     "/ru/",
		"/uk":                     "/uk/",
		"/how-it-works":           "/how-it-works/",
		"/ru/privacy":             "/ru/privacy/",
		"/password-generator?x=1": "/password-generator/?x=1",
		"/s/" + testID + "/":      "/s/" + testID,
		"/m/" + testID + "/":      "/m/" + testID,
	}
	for path, want := range cases {
		rec := do(t, h, req{path: path})
		if rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != want {
			t.Errorf("%s: got %d %q, want 301 %q", path, rec.Code, rec.Header().Get("Location"), want)
		}
	}
}

var (
	canonicalRe = regexp.MustCompile(`<link rel="canonical" href="([^"]+)">`)
	hreflangRe  = regexp.MustCompile(`<link rel="alternate" hreflang="([^"]+)" href="([^"]+)">`)
	htmlLangRe  = regexp.MustCompile(`<html lang="([a-z]+)">`)
)

func TestCanonicalAndHreflangOnEveryPage(t *testing.T) {
	h, _ := newTestHandler(t)
	for _, p := range pageDefs {
		for _, prefix := range []string{"", "/ru", "/uk"} {
			path := prefix + "/" + p.Slug
			rec := do(t, h, req{path: path})
			if rec.Code != http.StatusOK {
				t.Fatalf("%s: status %d", path, rec.Code)
			}
			body := rec.Body.String()
			m := canonicalRe.FindStringSubmatch(body)
			if m == nil || m[1] != "https://encrypt.one"+path {
				t.Errorf("%s: canonical %v", path, m)
			}
			got := map[string]string{}
			for _, a := range hreflangRe.FindAllStringSubmatch(body, -1) {
				got[a[1]] = a[2]
			}
			want := map[string]string{
				"en":        "https://encrypt.one/" + p.Slug,
				"ru":        "https://encrypt.one/ru/" + p.Slug,
				"uk":        "https://encrypt.one/uk/" + p.Slug,
				"x-default": "https://encrypt.one/" + p.Slug,
			}
			for k, v := range want {
				if got[k] != v {
					t.Errorf("%s: hreflang %s = %q, want %q", path, k, got[k], v)
				}
			}
			if rec.Header().Get("X-Robots-Tag") != "" {
				t.Errorf("%s: indexable page has X-Robots-Tag", path)
			}
		}
	}
}

func TestSecretPagesAreNoindexAndDoNotTouchStorage(t *testing.T) {
	h, spy := newTestHandler(t)
	for _, path := range []string{"/s/" + testID, "/m/" + testID} {
		rec := do(t, h, req{path: path, headers: map[string]string{"User-Agent": "TelegramBot (like TwitterBot)"}})
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", path, rec.Code)
		}
		if !strings.Contains(rec.Header().Get("X-Robots-Tag"), "noindex") {
			t.Errorf("%s: no X-Robots-Tag noindex", path)
		}
		if canonicalRe.MatchString(rec.Body.String()) {
			t.Errorf("%s: noindex page has a canonical link", path)
		}
	}
	if n := spy.count(); n != 0 {
		t.Errorf("page GETs touched the storage %d times", n)
	}
}

func TestSecretPageLanguage(t *testing.T) {
	h, _ := newTestHandler(t)
	cases := []struct{ accept, cookie, want string }{
		{"", "", "en"},
		{"uk-UA,uk;q=0.9", "", "uk"},
		{"de,ru;q=0.8", "", "de"},
		{"uk", "ru-ru", "ru"},
		{"ru", "en", "en"},
	}
	for _, c := range cases {
		headers := map[string]string{}
		if c.accept != "" {
			headers["Accept-Language"] = c.accept
		}
		if c.cookie != "" {
			headers["Cookie"] = "lang=" + c.cookie
		}
		rec := do(t, h, req{path: "/s/" + testID, headers: headers})
		if m := htmlLangRe.FindStringSubmatch(rec.Body.String()); m == nil || m[1] != c.want {
			t.Errorf("accept %q cookie %q: lang %v, want %s", c.accept, c.cookie, m, c.want)
		}
	}
}

func TestNotFound(t *testing.T) {
	h, _ := newTestHandler(t)
	cases := map[string]string{
		"/nope/":             "en",
		"/ru/nope/":          "ru",
		"/uk/use-cases/x/":   "uk",
		"/s/short":           "en",
		"/s/" + testID + "x": "en",
	}
	for path, lang := range cases {
		rec := do(t, h, req{path: path})
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: got %d, want 404", path, rec.Code)
		}
		if m := htmlLangRe.FindStringSubmatch(rec.Body.String()); m == nil || m[1] != lang {
			t.Errorf("%s: lang %v, want %s", path, m, lang)
		}
	}
}

func TestPagesRejectOtherMethods(t *testing.T) {
	h, _ := newTestHandler(t)
	for _, path := range []string{"/", "/ru/how-it-works/", "/s/" + testID} {
		rec := do(t, h, req{method: http.MethodPost, path: path})
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s: got %d, want 405", path, rec.Code)
		}
	}
}

func TestAssets(t *testing.T) {
	h, _ := newTestHandler(t)
	cssURL := testConfig.cfg.GetAssetUrl("css/site.css")
	if !regexp.MustCompile(`^/assets/css/site\.[0-9a-f]+\.css$`).MatchString(cssURL) {
		t.Fatalf("css url %q is not hashed", cssURL)
	}
	for path, wantType := range map[string]string{
		cssURL:                            "text/css; charset=utf-8",
		"/assets/css/site.css":            "text/css; charset=utf-8",
		"/assets/fonts/onest-latin.woff2": "font/woff2",
		"/favicon.ico":                    "",
		"/assets/js/app.js":               "text/javascript; charset=utf-8",
	} {
		rec := do(t, h, req{path: path})
		if rec.Code != http.StatusOK || (wantType != "" && rec.Header().Get("Content-Type") != wantType) {
			t.Errorf("%s: %d %q", path, rec.Code, rec.Header().Get("Content-Type"))
		}
	}
	for _, path := range []string{"/assets/", "/assets/js/", "/assets/js/missing.js", "/assets/../go.mod"} {
		if rec := do(t, h, req{path: path}); rec.Code == http.StatusOK {
			t.Errorf("%s: got 200", path)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	h, _ := newTestHandler(t)
	rec := do(t, h, req{path: "/"})
	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"script-src 'self'", "style-src 'self'", "connect-src 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP lacks %q", want)
		}
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Errorf("CSP allows unsafe-inline")
	}
	for k, v := range map[string]string{
		"Referrer-Policy":        "no-referrer",
		"X-Content-Type-Options": "nosniff",
	} {
		if rec.Header().Get(k) != v {
			t.Errorf("%s = %q, want %q", k, rec.Header().Get(k), v)
		}
	}
	for _, k := range []string{"Strict-Transport-Security", "Permissions-Policy"} {
		if rec.Header().Get(k) == "" {
			t.Errorf("no %s", k)
		}
	}
}

func TestRobotsSitemapAndVerification(t *testing.T) {
	h, _ := newTestHandler(t)
	robots := do(t, h, req{path: "/robots.txt"}).Body.String()
	if !strings.Contains(robots, "Sitemap: https://encrypt.one/sitemap.xml") || strings.Contains(robots, "Disallow: /s/") {
		t.Errorf("robots.txt:\n%s", robots)
	}
	sitemap := do(t, h, req{path: "/sitemap.xml"}).Body.String()
	if n := strings.Count(sitemap, "<loc>"); n != len(pageDefs)*len(testConfig.cfg.Languages) {
		t.Errorf("sitemap has %d urls, want %d", n, len(pageDefs)*len(testConfig.cfg.Languages))
	}
	for _, want := range []string{"<loc>https://encrypt.one/uk/privacy/</loc>", `hreflang="x-default" href="https://encrypt.one/privacy/"`} {
		if !strings.Contains(sitemap, want) {
			t.Errorf("sitemap lacks %s", want)
		}
	}
	rec := do(t, h, req{path: "/googleed203f16e9c1b9a9.html"})
	body, _ := io.ReadAll(rec.Body)
	if string(body) != "google-site-verification: googleed203f16e9c1b9a9.html\n" {
		t.Errorf("google verification: %q", body)
	}
}

// A missing translation is rendered as its key ("home.hero.title"), and a
// value html/template refused to insert becomes "ZgotmplZ".
var untranslatedRe = regexp.MustCompile(`>\s*(common|form|home|created|secret|generator|how|privacy|notFound|useCase)\.[A-Za-z0-9.]+\s*<|"(common|form|home|created|secret|generator|how|privacy|notFound|useCase)\.[A-Za-z0-9.]+"|ZgotmplZ`)

func TestPagesAreFullyTranslated(t *testing.T) {
	h, _ := newTestHandler(t)
	ogRe := regexp.MustCompile(`<meta property="og:image" content="https://encrypt\.one/assets/img/og-([a-z]+)\.[0-9a-f]+\.png">`)
	for _, lang := range []struct{ short, code, prefix string }{{"en", "en-us", ""}, {"ru", "ru-ru", "/ru"}, {"uk", "uk-uk", "/uk"}} {
		paths := []string{lang.prefix + "/nope/", "/s/" + testID, "/m/" + testID}
		for _, p := range pageDefs {
			paths = append(paths, lang.prefix+"/"+p.Slug)
		}
		for _, path := range paths {
			body := do(t, h, req{path: path, headers: map[string]string{"Cookie": "lang=" + lang.code}}).Body.String()
			if m := untranslatedRe.FindString(body); m != "" {
				t.Errorf("%s (%s): untranslated %q", path, lang.short, m)
			}
			if m := htmlLangRe.FindStringSubmatch(body); m == nil || m[1] != lang.short {
				t.Errorf("%s: html lang %v, want %s", path, m, lang.short)
			}
			if m := ogRe.FindStringSubmatch(body); m == nil || m[1] != lang.short {
				t.Errorf("%s: og:image %v, want og-%s", path, m, lang.short)
			}
		}
	}
}

func TestSecretPagesHaveAllViews(t *testing.T) {
	h, _ := newTestHandler(t)
	views := map[string][]string{
		"/s/" + testID: {"intro", "password", "revealed", "gone", "error"},
		"/m/" + testID: {"alive", "expired", "destroyed"},
	}
	for path, want := range views {
		body := do(t, h, req{path: path}).Body.String()
		for _, v := range want {
			if !strings.Contains(body, `data-view="`+v+`"`) {
				t.Errorf("%s: no %s view", path, v)
			}
		}
	}
}

func TestHomeShareBlock(t *testing.T) {
	h, _ := newTestHandler(t)
	titles := map[string]string{
		"/":    "What Can You Share with a One-Time Link?",
		"/ru/": "Что можно передать по одноразовой ссылке?",
		"/uk/": "Що можна передати одноразовим посиланням?",
	}
	cardRe := regexp.MustCompile(`(?s)<li class="share-card">.*?</li>`)
	for path, title := range titles {
		body := do(t, h, req{path: path}).Body.String()
		if !strings.Contains(body, `<h2 class="h2" id="share-title">`+title+`</h2>`) {
			t.Errorf("%s: no h2 %q", path, title)
		}
		cards := cardRe.FindAllString(body, -1)
		if len(cards) != 4 {
			t.Fatalf("%s: %d cards, want 4", path, len(cards))
		}
		for _, c := range cards {
			if !strings.Contains(c, `<h3 class="share-card__title">`) || strings.Contains(c, "<a ") {
				t.Errorf("%s: card without h3 or with a link: %s", path, c)
			}
		}
		// How it works, then this block, then the encryption block, then FAQ.
		order := []string{`id="how"`, `id="what-to-share"`, `id="why-title"`, `id="faq"`}
		last := -1
		for _, marker := range order {
			i := strings.Index(body, marker)
			if i <= last {
				t.Errorf("%s: %s is out of order", path, marker)
			}
			last = i
		}
		if strings.Contains(body, "use-cases/") {
			t.Errorf("%s: still links to use-case pages", path)
		}
	}
	for _, path := range []string{"/use-cases/wifi/", "/ru/use-cases/api-key/", "/uk/use-cases/new-employee/"} {
		if rec := do(t, h, req{path: path}); rec.Code != http.StatusNotFound {
			t.Errorf("%s: got %d, want 404", path, rec.Code)
		}
	}
}

func TestPagesReferenceExistingAssets(t *testing.T) {
	h, _ := newTestHandler(t)
	assetRe := regexp.MustCompile(`"(/assets/[^"]+)"`)
	for _, path := range []string{"/", "/ru/password-generator/", "/how-it-works/", "/s/" + testID, "/m/" + testID} {
		body := do(t, h, req{path: path}).Body.String()
		if !strings.Contains(body, `<script type="module" src="/assets/js/app.`) {
			t.Errorf("%s: app module is not loaded", path)
		}
		for _, m := range assetRe.FindAllStringSubmatch(body, -1) {
			if rec := do(t, h, req{path: m[1]}); rec.Code != http.StatusOK {
				t.Errorf("%s: %s -> %d", path, m[1], rec.Code)
			}
		}
	}
}

func TestArabicPageDirectionAndTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/ar/"}).Body.String()
	for _, want := range []string{`<html lang="ar" dir="rtl">`, "شارك كلمات المرور", `hreflang="ar"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Arabic page lacks %q", want)
		}
	}
}

func TestHebrewPageDirectionAndTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/he/"}).Body.String()
	for _, want := range []string{`<html lang="he" dir="rtl">`, "שיתוף סיסמאות", `hreflang="he"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Hebrew page lacks %q", want)
		}
	}
}

func TestGermanPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/de/"}).Body.String()
	for _, want := range []string{`<html lang="de">`, "Passwörter sicher", `hreflang="de"`} {
		if !strings.Contains(body, want) {
			t.Errorf("German page lacks %q", want)
		}
	}
}

func TestFrenchPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/fr/"}).Body.String()
	for _, want := range []string{`<html lang="fr">`, "Partagez vos mots de passe", `hreflang="fr"`} {
		if !strings.Contains(body, want) {
			t.Errorf("French page lacks %q", want)
		}
	}
}

func TestSpanishPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/es/"}).Body.String()
	for _, want := range []string{`<html lang="es">`, "Comparte contraseñas", `hreflang="es"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Spanish page lacks %q", want)
		}
	}
}

func TestPortuguesePageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/pt/"}).Body.String()
	for _, want := range []string{`<html lang="pt">`, "Compartilhe senhas", `hreflang="pt"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Portuguese page lacks %q", want)
		}
	}
}

func TestItalianPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/it/"}).Body.String()
	for _, want := range []string{`<html lang="it">`, "Condividi password", `hreflang="it"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Italian page lacks %q", want)
		}
	}
}

func TestDutchPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/nl/"}).Body.String()
	for _, want := range []string{`<html lang="nl">`, "Deel wachtwoorden", `hreflang="nl"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Dutch page lacks %q", want)
		}
	}
}

func TestPolishPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/pl/"}).Body.String()
	for _, want := range []string{`<html lang="pl">`, "Bezpiecznie udostępniaj hasła", `hreflang="pl"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Polish page lacks %q", want)
		}
	}
}

func TestTurkishPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/tr/"}).Body.String()
	for _, want := range []string{`<html lang="tr">`, "Parolaları tek kullanımlık", `hreflang="tr"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Turkish page lacks %q", want)
		}
	}
}

func TestCzechPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/cs/"}).Body.String()
	for _, want := range []string{`<html lang="cs">`, "Sdílejte hesla bezpečně", `hreflang="cs"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Czech page lacks %q", want)
		}
	}
}

func TestRomanianPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/ro/"}).Body.String()
	for _, want := range []string{`<html lang="ro">`, "Partajează parole", `hreflang="ro"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Romanian page lacks %q", want)
		}
	}
}

func TestBulgarianPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/bg/"}).Body.String()
	for _, want := range []string{`<html lang="bg">`, "Споделяйте пароли", `hreflang="bg"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Bulgarian page lacks %q", want)
		}
	}
}

func TestSlovakPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/sk/"}).Body.String()
	for _, want := range []string{`<html lang="sk">`, "Zdieľajte heslá bezpečne", `hreflang="sk"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Slovak page lacks %q", want)
		}
	}
}

func TestSwedishPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/sv/"}).Body.String()
	for _, want := range []string{`<html lang="sv">`, "Dela lösenord säkert", `hreflang="sv"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Swedish page lacks %q", want)
		}
	}
}

func TestDanishPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/da/"}).Body.String()
	for _, want := range []string{`<html lang="da">`, "Del adgangskoder sikkert", `hreflang="da"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Danish page lacks %q", want)
		}
	}
}

func TestNorwegianPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/no/"}).Body.String()
	for _, want := range []string{`<html lang="no">`, "Del passord sikkert", `hreflang="no"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Norwegian page lacks %q", want)
		}
	}
}

func TestCroatianPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/hr/"}).Body.String()
	for _, want := range []string{`<html lang="hr">`, "Sigurno dijelite lozinke", `hreflang="hr"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Croatian page lacks %q", want)
		}
	}
}

func TestSerbianPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/sr/"}).Body.String()
	for _, want := range []string{`<html lang="sr">`, "Bezbedno delite lozinke", `hreflang="sr"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Serbian page lacks %q", want)
		}
	}
}

func TestIndonesianPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/id/"}).Body.String()
	for _, want := range []string{`<html lang="id">`, "Bagikan kata sandi", `hreflang="id"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Indonesian page lacks %q", want)
		}
	}
}

func TestMalayPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/ms/"}).Body.String()
	for _, want := range []string{`<html lang="ms">`, "Kongsi kata laluan", `hreflang="ms"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Malay page lacks %q", want)
		}
	}
}

func TestBelarusianPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/be/"}).Body.String()
	for _, want := range []string{`<html lang="be">`, "Бяспечна перадавайце паролі", `hreflang="be"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Belarusian page lacks %q", want)
		}
	}
}

func TestGreekPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/el/"}).Body.String()
	for _, want := range []string{`<html lang="el">`, "Μοιραστείτε κωδικούς", `hreflang="el"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Greek page lacks %q", want)
		}
	}
}

func TestSlovenianPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/sl/"}).Body.String()
	for _, want := range []string{`<html lang="sl">`, "Varno delite gesla", `hreflang="sl"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Slovenian page lacks %q", want)
		}
	}
}

func TestMacedonianPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/mk/"}).Body.String()
	for _, want := range []string{`<html lang="mk">`, "Споделувајте лозинки безбедно", `hreflang="mk"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Macedonian page lacks %q", want)
		}
	}
}

func TestFinnishPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/fi/"}).Body.String()
	for _, want := range []string{`<html lang="fi">`, "Jaa salasanat turvallisesti", `hreflang="fi"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Finnish page lacks %q", want)
		}
	}
}

func TestJapanesePageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/ja/"}).Body.String()
	for _, want := range []string{`<html lang="ja">`, "パスワードを安全に共有", `hreflang="ja"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Japanese page lacks %q", want)
		}
	}
}

func TestKoreanPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/ko/"}).Body.String()
	for _, want := range []string{`<html lang="ko">`, "비밀번호를 안전하게 공유", `hreflang="ko"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Korean page lacks %q", want)
		}
	}
}

func TestHindiPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	paths := []string{"/hi/", "/hi/how-it-works/", "/hi/privacy/", "/hi/password-generator/", "/hi/nope/", "/s/" + testID, "/m/" + testID}
	for _, path := range paths {
		body := do(t, h, req{path: path, headers: map[string]string{"Cookie": "lang=hi-in"}}).Body.String()
		if !strings.Contains(body, `<html lang="hi">`) {
			t.Errorf("%s: missing Hindi language", path)
		}
		if m := untranslatedRe.FindString(body); m != "" {
			t.Errorf("%s: untranslated %q", path, m)
		}
	}
}

func TestVietnamesePageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	paths := []string{"/vi/", "/vi/how-it-works/", "/vi/privacy/", "/vi/password-generator/", "/vi/nope/", "/s/" + testID, "/m/" + testID}
	for _, path := range paths {
		body := do(t, h, req{path: path, headers: map[string]string{"Cookie": "lang=vi-vn"}}).Body.String()
		if !strings.Contains(body, `<html lang="vi">`) {
			t.Errorf("%s: missing Vietnamese language", path)
		}
		if m := untranslatedRe.FindString(body); m != "" {
			t.Errorf("%s: untranslated %q", path, m)
		}
	}
}

func TestBengaliPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	paths := []string{"/bn/", "/bn/how-it-works/", "/bn/privacy/", "/bn/password-generator/", "/bn/nope/", "/s/" + testID, "/m/" + testID}
	for _, path := range paths {
		body := do(t, h, req{path: path, headers: map[string]string{"Cookie": "lang=bn-bd"}}).Body.String()
		if !strings.Contains(body, `<html lang="bn">`) {
			t.Errorf("%s: missing Bengali language", path)
		}
		if m := untranslatedRe.FindString(body); m != "" {
			t.Errorf("%s: untranslated %q", path, m)
		}
	}
}

func TestPersianPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	paths := []string{"/fa/", "/fa/how-it-works/", "/fa/privacy/", "/fa/password-generator/", "/fa/nope/", "/s/" + testID, "/m/" + testID}
	for _, path := range paths {
		body := do(t, h, req{path: path, headers: map[string]string{"Cookie": "lang=fa-ir"}}).Body.String()
		if !strings.Contains(body, `<html lang="fa" dir="rtl">`) {
			t.Errorf("%s: missing Persian language or RTL direction", path)
		}
		if m := untranslatedRe.FindString(body); m != "" {
			t.Errorf("%s: untranslated %q", path, m)
		}
	}
}

func TestUrduPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	paths := []string{"/ur/", "/ur/how-it-works/", "/ur/privacy/", "/ur/password-generator/", "/ur/nope/", "/s/" + testID, "/m/" + testID}
	for _, path := range paths {
		body := do(t, h, req{path: path, headers: map[string]string{"Cookie": "lang=ur-pk"}}).Body.String()
		if !strings.Contains(body, `<html lang="ur" dir="rtl">`) {
			t.Errorf("%s: missing Urdu language or RTL direction", path)
		}
		if m := untranslatedRe.FindString(body); m != "" {
			t.Errorf("%s: untranslated %q", path, m)
		}
	}
}

func TestFilipinoPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	paths := []string{"/fil/", "/fil/how-it-works/", "/fil/privacy/", "/fil/password-generator/", "/fil/nope/", "/s/" + testID, "/m/" + testID}
	for _, path := range paths {
		body := do(t, h, req{path: path, headers: map[string]string{"Cookie": "lang=fil-ph"}}).Body.String()
		if !strings.Contains(body, `<html lang="fil">`) {
			t.Errorf("%s: missing Filipino language", path)
		}
		if m := untranslatedRe.FindString(body); m != "" {
			t.Errorf("%s: untranslated %q", path, m)
		}
	}
	for _, headers := range []map[string]string{{"Cookie": "lang=fil-ph"}, {"Accept-Language": "fil-PH,fi;q=0.8"}} {
		body := do(t, h, req{path: "/s/" + testID, headers: headers}).Body.String()
		if !strings.Contains(body, `<html lang="fil">`) {
			t.Errorf("language selection failed for %v", headers)
		}
	}
}

func TestUzbekPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	paths := []string{"/uz/", "/uz/how-it-works/", "/uz/privacy/", "/uz/password-generator/", "/uz/nope/", "/s/" + testID, "/m/" + testID}
	for _, path := range paths {
		body := do(t, h, req{path: path, headers: map[string]string{"Cookie": "lang=uz-uz"}}).Body.String()
		if !strings.Contains(body, `<html lang="uz">`) {
			t.Errorf("%s: missing Uzbek language", path)
		}
		if m := untranslatedRe.FindString(body); m != "" {
			t.Errorf("%s: untranslated %q", path, m)
		}
	}
}

func TestKazakhPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	paths := []string{"/kk/", "/kk/how-it-works/", "/kk/privacy/", "/kk/password-generator/", "/kk/nope/", "/s/" + testID, "/m/" + testID}
	for _, path := range paths {
		body := do(t, h, req{path: path, headers: map[string]string{"Cookie": "lang=kk-kz"}}).Body.String()
		if !strings.Contains(body, `<html lang="kk">`) {
			t.Errorf("%s: missing Kazakh language", path)
		}
		if m := untranslatedRe.FindString(body); m != "" {
			t.Errorf("%s: untranslated %q", path, m)
		}
	}
}

func TestGeorgianPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	paths := []string{"/ka/", "/ka/how-it-works/", "/ka/privacy/", "/ka/password-generator/", "/ka/nope/", "/s/" + testID, "/m/" + testID}
	for _, path := range paths {
		body := do(t, h, req{path: path, headers: map[string]string{"Cookie": "lang=ka-ge"}}).Body.String()
		if !strings.Contains(body, `<html lang="ka">`) {
			t.Errorf("%s: missing Georgian language", path)
		}
		if m := untranslatedRe.FindString(body); m != "" {
			t.Errorf("%s: untranslated %q", path, m)
		}
	}
}

func TestHungarianPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/hu/"}).Body.String()
	for _, want := range []string{`<html lang="hu">`, "Osszon meg jelszavakat biztonságosan", `hreflang="hu"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Hungarian page lacks %q", want)
		}
	}
}

func TestAzerbaijaniPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/az/"}).Body.String()
	for _, want := range []string{`<html lang="az">`, "Parolları birdəfəlik", `hreflang="az"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Azerbaijani page lacks %q", want)
		}
	}
}

func TestAlbanianPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/sq/"}).Body.String()
	for _, want := range []string{`<html lang="sq">`, "Ndani fjalëkalime", `hreflang="sq"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Albanian page lacks %q", want)
		}
	}
}

func TestEstonianPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/et/"}).Body.String()
	for _, want := range []string{`<html lang="et">`, "Jagage paroole turvaliselt", `hreflang="et"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Estonian page lacks %q", want)
		}
	}
}

func TestLatvianPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/lv/"}).Body.String()
	for _, want := range []string{`<html lang="lv">`, "Droši kopīgojiet paroles", `hreflang="lv"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Latvian page lacks %q", want)
		}
	}
}

func TestLithuanianPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/lt/"}).Body.String()
	for _, want := range []string{`<html lang="lt">`, "Saugiai dalykitės slaptažodžiais", `hreflang="lt"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Lithuanian page lacks %q", want)
		}
	}
}

func TestThaiPageTranslation(t *testing.T) {
	h, _ := newTestHandler(t)
	body := do(t, h, req{path: "/th/"}).Body.String()
	for _, want := range []string{`<html lang="th">`, "แชร์รหัสผ่านอย่างปลอดภัย", `hreflang="th"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Thai page lacks %q", want)
		}
	}
}
