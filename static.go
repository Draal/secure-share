package main

import (
	"encoding/xml"
	"mime"
	"net/http"
	"os"
	"path"
	"regexp"
)

func init() {
	mime.AddExtensionType(".woff2", "font/woff2")
}

// hashRe strips the content hash from asset URLs: site.1a2b3c4d.css -> site.css.
// In production nginx serves public/ with the same rewrite, so Go serves
// these files only when run locally.
var hashRe = regexp.MustCompile(`\.[0-9a-f]+(\.[a-z]+)$`)

func (h *Handler) serveStatic(w http.ResponseWriter, r *http.Request, urlPath string) {
	if !allowRead(w, r) {
		return
	}
	file := path.Join(h.config.Root, hashRe.ReplaceAllString(urlPath, "$1"))
	if info, err := os.Stat(file); err != nil || info.IsDir() {
		h.notFound(w, r, h.langForUnprefixedPage(r))
		return
	}
	http.ServeFile(w, r, file)
}

func (h *Handler) serveRobots(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	// /s/ and /m/ stay crawlable on purpose: they answer with
	// X-Robots-Tag: noindex, which a crawler can only see if allowed in.
	w.Write([]byte("User-agent: *\nAllow: /\nDisallow: /api/\n\nSitemap: " + h.siteURL + "/sitemap.xml\n"))
}

type sitemapLink struct {
	Rel      string `xml:"rel,attr"`
	Hreflang string `xml:"hreflang,attr"`
	Href     string `xml:"href,attr"`
}

type sitemapURL struct {
	Loc   string        `xml:"loc"`
	Links []sitemapLink `xml:"xhtml:link"`
}

type sitemapSet struct {
	XMLName xml.Name     `xml:"urlset"`
	NS      string       `xml:"xmlns,attr"`
	XHTML   string       `xml:"xmlns:xhtml,attr"`
	URLs    []sitemapURL `xml:"url"`
}

func (h *Handler) serveSitemap(w http.ResponseWriter, r *http.Request) {
	set := sitemapSet{
		NS:    "http://www.sitemaps.org/schemas/sitemap/0.9",
		XHTML: "http://www.w3.org/1999/xhtml",
	}
	for _, p := range pageDefs {
		for _, l := range h.config.Languages {
			d := h.newPageData(l, p, true)
			u := sitemapURL{Loc: d.Canonical}
			for _, a := range d.Alternates {
				u.Links = append(u.Links, sitemapLink{Rel: "alternate", Hreflang: a.Hreflang, Href: a.URL})
			}
			set.URLs = append(set.URLs, u)
		}
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Write([]byte(xml.Header))
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	enc.Encode(set)
}

func (h *Handler) serveGoogleVerification(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte("google-site-verification: googleed203f16e9c1b9a9.html\n"))
}
