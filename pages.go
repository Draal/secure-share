package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/Draal/secure-share/config"
)

// pageDef describes an indexable page available in every language.
type pageDef struct {
	Slug     string // path after the language prefix, always with a trailing slash ("" for home)
	Template string
	Meta     string // translation key prefix for title and description
}

var pageDefs = []pageDef{
	{Slug: "", Template: "home", Meta: "home.meta"},
	{Slug: "password-generator/", Template: "generator", Meta: "generator.meta"},
	{Slug: "how-it-works/", Template: "how", Meta: "how.meta"},
	{Slug: "privacy/", Template: "privacy", Meta: "privacy.meta"},
}

// chrome tells which header and footer a page template uses.
var chrome = map[string]struct {
	compactHeader bool
	footer        string // "full", "compact" or "" for none
}{
	"secret":    {true, ""},
	"generator": {false, "compact"},
	"manage":    {false, "compact"},
}

func findPage(slug string) (pageDef, bool) {
	for _, p := range pageDefs {
		if p.Slug == slug {
			return p, true
		}
	}
	return pageDef{}, false
}

type alternate struct {
	Hreflang string
	URL      string
}

// PageData is passed to every template.
type PageData struct {
	Lang         config.Language
	Languages    []config.Language
	Page         pageDef
	Indexable    bool
	Canonical    string            // absolute URL, empty for noindex pages
	Alternates   []alternate       // hreflang links, empty for noindex pages
	LangURLs     map[string]string // language switcher targets by short code
	SiteURL      string
	MaxFileBytes int64 // upload limit for the client-side check

	CompactHeader bool
	Footer        string
	JSONLD        template.JS // structured data of the home page
}

// pageURL builds the path of a page in a language: "/ru/how-it-works/".
func pageURL(l config.Language, slug string) string {
	return l.Prefix + "/" + slug
}

func (h *Handler) newPageData(l config.Language, p pageDef, indexable bool) *PageData {
	languages := append([]config.Language(nil), h.config.Languages...)
	sort.SliceStable(languages, func(i, j int) bool {
		return languages[i].Short < languages[j].Short
	})
	d := &PageData{
		Lang:         l,
		Languages:    languages,
		Page:         p,
		Indexable:    indexable,
		LangURLs:     make(map[string]string),
		SiteURL:      h.siteURL,
		MaxFileBytes: h.config.MaxFileSize,
		Footer:       "full",
	}
	if c, ok := chrome[p.Template]; ok {
		d.CompactHeader, d.Footer = c.compactHeader, c.footer
	}
	if p.Template == "home" {
		d.JSONLD = h.homeJSONLD(l)
	}
	for _, other := range h.config.Languages {
		d.LangURLs[other.Short] = pageURL(other, p.Slug)
	}
	if indexable {
		d.Canonical = h.siteURL + pageURL(l, p.Slug)
		for _, other := range h.config.Languages {
			d.Alternates = append(d.Alternates, alternate{other.Short, h.siteURL + pageURL(other, p.Slug)})
		}
		d.Alternates = append(d.Alternates, alternate{"x-default", h.siteURL + pageURL(h.config.Languages[0], p.Slug)})
	}
	return d
}

func (h *Handler) render(w http.ResponseWriter, status int, d *PageData) {
	t := h.templates.get(d.Lang.Code, d.Page.Template)
	if t == nil {
		http.Error(w, "template not found", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", d); err != nil {
		log.Printf("template %s: %v", d.Page.Template, err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

// servePage handles language-prefixed and English pages, the root
// language redirect, trailing slashes and the localized 404.
func (h *Handler) servePage(w http.ResponseWriter, r *http.Request) {
	l, rest := h.splitLangPrefix(r.URL.Path)
	if rest == "" { // "/ru" -> "/ru/"
		redirectKeepQuery(w, r, l.Prefix+"/", http.StatusMovedPermanently)
		return
	}
	slug := strings.TrimPrefix(rest, "/")

	if r.URL.Path == "/" {
		w.Header().Add("Vary", "Accept-Language")
		w.Header().Add("Vary", "Cookie")
		if target, ok := h.rootRedirect(r); ok {
			redirectKeepQuery(w, r, target, http.StatusFound)
			return
		}
	}

	if p, ok := findPage(slug); ok {
		if !allowRead(w, r) {
			return
		}
		h.render(w, http.StatusOK, h.newPageData(l, p, true))
		return
	}
	if !strings.HasSuffix(slug, "/") {
		if _, ok := findPage(slug + "/"); ok {
			redirectKeepQuery(w, r, pageURL(l, slug+"/"), http.StatusMovedPermanently)
			return
		}
	}
	h.notFound(w, r, l)
}

// rootRedirect decides where "/" should go. A saved choice wins; without
// one, Accept-Language starting with ru or uk sends the visitor to that
// language. English visitors and requests without the header stay on "/".
func (h *Handler) rootRedirect(r *http.Request) (string, bool) {
	if l, ok := h.langFromCookie(r); ok {
		if l.Prefix != "" {
			return l.Prefix + "/", true
		}
		return "", false
	}
	if l, ok := h.primaryAcceptLanguage(r); ok {
		return l.Prefix + "/", true
	}
	return "", false
}

func (h *Handler) notFound(w http.ResponseWriter, r *http.Request, l config.Language) {
	d := h.newPageData(l, pageDef{Template: "not-found", Meta: "notFound.meta"}, false)
	for _, other := range h.config.Languages {
		d.LangURLs[other.Short] = pageURL(other, "")
	}
	w.Header().Set("X-Robots-Tag", "noindex")
	h.render(w, http.StatusNotFound, d)
}

// Secret ids are 16 random bytes in unpadded base64url. Checking the format
// before touching the storage also keeps ids out of disk paths.
var secretIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)

// serveSecretPages renders /s/<id> (recipient) and /m/<id> (sender). Neither
// GET touches the storage: link preview bots must not consume secrets.
func (h *Handler) serveSecretPages(w http.ResponseWriter, r *http.Request) {
	kind, id := r.URL.Path[1:2], r.URL.Path[3:]
	if strings.HasSuffix(id, "/") && secretIDRe.MatchString(strings.TrimSuffix(id, "/")) {
		redirectKeepQuery(w, r, strings.TrimSuffix(r.URL.Path, "/"), http.StatusMovedPermanently)
		return
	}
	l := h.langForUnprefixedPage(r)
	w.Header().Add("Vary", "Accept-Language")
	w.Header().Add("Vary", "Cookie")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	if !secretIDRe.MatchString(id) {
		h.notFound(w, r, l)
		return
	}
	if !allowRead(w, r) {
		return
	}
	p := pageDef{Template: "secret", Meta: "secret.meta"}
	if kind == "m" {
		p = pageDef{Template: "manage", Meta: "created.meta"}
	}
	d := h.newPageData(l, p, false)
	for _, other := range h.config.Languages {
		d.LangURLs[other.Short] = r.URL.Path
	}
	h.render(w, http.StatusOK, d)
}

func allowRead(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	w.Header().Set("Allow", "GET, HEAD")
	http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	return false
}

func redirectKeepQuery(w http.ResponseWriter, r *http.Request, target string, status int) {
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, target, status)
}

// homeJSONLD builds WebApplication and FAQPage structured data from the
// translations. json.Marshal escapes <, > and &, so the result is safe
// inside <script type="application/ld+json">.
func (h *Handler) homeJSONLD(l config.Language) template.JS {
	t := h.config.T(l.Code)
	url := h.siteURL + pageURL(l, "")
	type answer struct {
		Type string `json:"@type"`
		Text string `json:"text"`
	}
	type question struct {
		Type   string `json:"@type"`
		Name   string `json:"name"`
		Answer answer `json:"acceptedAnswer"`
	}
	var faq []question
	for i := 1; i <= 5; i++ {
		faq = append(faq, question{"Question", t(fmt.Sprintf("home.faq.q%d", i)), answer{"Answer", t(fmt.Sprintf("home.faq.a%d", i))}})
	}
	doc := map[string]interface{}{
		"@context": "https://schema.org",
		"@graph": []interface{}{
			map[string]interface{}{
				"@type":               "WebApplication",
				"@id":                 h.siteURL + "/#app",
				"name":                "Encrypt.One",
				"url":                 url,
				"inLanguage":          l.Short,
				"applicationCategory": "SecurityApplication",
				"operatingSystem":     "Any",
				"browserRequirements": "Requires JavaScript and Web Crypto API",
				"description":         t("home.meta.description"),
				"isAccessibleForFree": true,
				"offers":              map[string]interface{}{"@type": "Offer", "price": "0", "priceCurrency": "USD"},
			},
			map[string]interface{}{
				"@type":      "FAQPage",
				"@id":        url + "#faq",
				"inLanguage": l.Short,
				"mainEntity": faq,
			},
		},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return ""
	}
	return template.JS(b)
}
