package main

import (
	"net/http"
	"strings"
	"time"

	"github.com/Draal/secure-share/config"
)

const langCookie = "lang"

// langFromCookie returns the saved language choice. Old cookies hold the
// go-i18n tag ("ru-ru"), new ones may hold the short code ("ru" or "fil").
func (h *Handler) langFromCookie(r *http.Request) (config.Language, bool) {
	c, err := r.Cookie(langCookie)
	if err != nil || len(c.Value) < 2 {
		return config.Language{}, false
	}
	return h.config.LanguageByShort(strings.ToLower(strings.SplitN(c.Value, "-", 2)[0]))
}

// langFromAcceptLanguage picks the first supported language from the header.
func (h *Handler) langFromAcceptLanguage(r *http.Request) (config.Language, bool) {
	for _, part := range strings.Split(r.Header.Get("Accept-Language"), ",") {
		tag := strings.ToLower(strings.TrimSpace(strings.SplitN(part, ";", 2)[0]))
		if len(tag) < 2 {
			continue
		}
		if l, ok := h.config.LanguageByShort(strings.SplitN(tag, "-", 2)[0]); ok {
			return l, true
		}
	}
	return config.Language{}, false
}

// primaryAcceptLanguage returns the first language of Accept-Language
// when it is Russian or Ukrainian. Used only for the first visit to "/".
func (h *Handler) primaryAcceptLanguage(r *http.Request) (config.Language, bool) {
	first := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Accept-Language"), ",")[0]))
	for _, short := range []string{"ru", "uk"} {
		if strings.HasPrefix(first, short) {
			return h.config.LanguageByShort(short)
		}
	}
	return config.Language{}, false
}

// langForUnprefixedPage resolves the language of /s/ and /m/ pages:
// saved choice first, then Accept-Language, then English.
func (h *Handler) langForUnprefixedPage(r *http.Request) config.Language {
	if l, ok := h.langFromCookie(r); ok {
		return l
	}
	if l, ok := h.langFromAcceptLanguage(r); ok {
		return l
	}
	return h.config.Languages[0]
}

// splitLangPrefix separates "/ru/how-it-works/" into the language and the
// rest of the path ("/how-it-works/"). English pages have no prefix.
func (h *Handler) splitLangPrefix(p string) (config.Language, string) {
	for _, l := range h.config.Languages {
		if l.Prefix != "" && (p == l.Prefix || strings.HasPrefix(p, l.Prefix+"/")) {
			return l, strings.TrimPrefix(p, l.Prefix)
		}
	}
	return h.config.Languages[0], p
}

func (h *Handler) saveLanguageToCookie(w http.ResponseWriter, r *http.Request, l config.Language) {
	http.SetCookie(w, &http.Cookie{
		Name:     langCookie,
		Value:    l.Code,
		Path:     "/",
		Expires:  time.Now().AddDate(5, 0, 0),
		SameSite: http.SameSiteLaxMode,
		Secure:   isHTTPS(r),
	})
}

func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// redirectOldLangParam handles old "?lang=ru" links: saves the choice like
// the old site did and answers 301 to the language address of the same path.
func (h *Handler) redirectOldLangParam(w http.ResponseWriter, r *http.Request) bool {
	q := r.URL.Query()
	short := q.Get("lang")
	if short == "" {
		return false
	}
	l, ok := h.config.LanguageByShort(strings.ToLower(short))
	if !ok {
		l = h.config.Languages[0]
	}
	h.saveLanguageToCookie(w, r, l)
	q.Del("lang")

	target := r.URL.Path
	if !isUnprefixedPage(target) {
		_, rest := h.splitLangPrefix(target)
		target = l.Prefix + rest
		if target == "" {
			target = "/"
		}
	}
	if enc := q.Encode(); enc != "" {
		target += "?" + enc
	}
	http.Redirect(w, r, target, http.StatusMovedPermanently)
	return true
}

func isUnprefixedPage(p string) bool {
	return strings.HasPrefix(p, "/s/") || strings.HasPrefix(p, "/m/")
}
