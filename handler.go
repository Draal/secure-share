package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/Draal/secure-share/config"
	"github.com/Draal/secure-share/storage"
)

type Handler struct {
	config    *config.Config
	storage   storage.Storage
	templates *templateSet
	siteURL   string // absolute site URL without a trailing slash, for canonical links

	manageSecret []byte // key of the sender page tokens, from MANAGE_TOKEN_SECRET
	limits       *rateLimiter
	attempts     *passwordAttempts
	idLocks      idLocks
}

type handlerOptions struct {
	SiteURL      string
	ManageSecret []byte
}

// ServeHTTP is the single entry point: static files, pages and the API.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w.Header())

	p := r.URL.Path
	switch {
	case strings.HasPrefix(p, "/assets/"):
		h.serveStatic(w, r, p)
	case p == "/favicon.ico":
		h.serveStatic(w, r, "/assets/img/favicon.ico")
	case p == "/robots.txt":
		h.serveRobots(w, r)
	case p == "/sitemap.xml":
		h.serveSitemap(w, r)
	case p == "/googleed203f16e9c1b9a9.html":
		h.serveGoogleVerification(w, r)
	case strings.HasPrefix(p, "/api/"):
		h.serveAPI(w, r)
	case h.redirectOldLangParam(w, r):
	case isUnprefixedPage(p):
		h.serveSecretPages(w, r)
	default:
		h.servePage(w, r)
	}
}

// setSecurityHeaders adds the headers shared by every response.
func setSecurityHeaders(hdr http.Header) {
	const csp = "default-src 'none'; " +
		"script-src 'self'; " +
		"style-src 'self'; " +
		"img-src 'self' data:; " +
		"font-src 'self'; " +
		"connect-src 'self'; " +
		"manifest-src 'self'; " +
		"form-action 'self'; " +
		"base-uri 'none'; " +
		"frame-ancestors 'none'"
	hdr.Set("Content-Security-Policy", csp)
	hdr.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	hdr.Set("Referrer-Policy", "no-referrer")
	hdr.Set("X-Content-Type-Options", "nosniff")
	hdr.Set("X-Frame-Options", "DENY")
	hdr.Set("Cross-Origin-Opener-Policy", "same-origin")
	hdr.Set("Cross-Origin-Resource-Policy", "same-origin")
	hdr.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
}

func newHandler(c *config.Config, st storage.Storage, opts handlerOptions) (*Handler, error) {
	templates, err := loadTemplates(c)
	if err != nil {
		return nil, fmt.Errorf("Couldn't load templates: %s", err.Error())
	}
	if len(opts.ManageSecret) < 32 {
		return nil, fmt.Errorf("manage token secret must be at least 32 bytes")
	}
	return &Handler{
		config:       c,
		storage:      st,
		templates:    templates,
		siteURL:      strings.TrimSuffix(opts.SiteURL, "/"),
		manageSecret: opts.ManageSecret,
		limits:       newRateLimiter(defaultRateRules),
		attempts:     newPasswordAttempts(),
	}, nil
}

func OpenHandlerFromEnv() (*Handler, error) {
	config, err := config.OpenFromEnv()
	if err != nil {
		return nil, err
	}
	var st storage.Storage
	switch os.Getenv("STORAGE_TYPE") {
	case "disk":
		if err := checkDiskPaths(os.Getenv("DISK_STORAGE_PATHS")); err != nil {
			return nil, err
		}
		st, err = storage.OpenDiskStorageFromEnv()
		if err != nil {
			return nil, fmt.Errorf("Coudn't open disk storage: %s", err.Error())
		}
	default:
		st = storage.OpenMemoryStorage()
	}
	opts := handlerOptions{
		SiteURL:      os.Getenv("SITE_URL"),
		ManageSecret: []byte(os.Getenv("MANAGE_TOKEN_SECRET")),
	}
	if opts.SiteURL == "" {
		opts.SiteURL = "https://encrypt.one"
	}
	if len(opts.ManageSecret) == 0 {
		panic("MANAGE_TOKEN_SECRET is not set: using a random key, sender page links stop working after a restart")
	}
	return newHandler(config, st, opts)
}

// checkDiskPaths rejects an empty DISK_STORAGE_PATHS or entries that are not
// existing directories. The storage package itself accepts "" and would
// write from the filesystem root.
func checkDiskPaths(paths string) error {
	for _, p := range strings.Split(paths, ":") {
		if p == "" {
			return fmt.Errorf("DISK_STORAGE_PATHS must list storage directories separated by \":\"")
		}
		if info, err := os.Stat(p); err != nil || !info.IsDir() {
			return fmt.Errorf("DISK_STORAGE_PATHS: %s is not a directory", p)
		}
	}
	return nil
}
