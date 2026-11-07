package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Draal/secure-share/config"
	"github.com/Draal/secure-share/storage"
)

// Storage times the sender can choose. Anything else is rejected.
var allowedTTL = map[string]int64{
	"1h": 3600,
	"1d": 24 * 3600,
	"3d": 3 * 24 * 3600,
	"7d": 7 * 24 * 3600,
}

const (
	maxWrongPasswordTries = 3
	passHashBytes         = 32      // v2 HKDF output and old HmacSHA256 are both 32 bytes
	textAllowance         = 1 << 20 // room for the text and the package header next to the file
)

type apiError struct {
	status     int
	code       string
	messageKey string
	count      int
}

func (h *Handler) apiFail(w http.ResponseWriter, r *http.Request, l config.Language, e apiError) {
	body := map[string]any{"code": e.code}
	if e.messageKey != "" {
		if e.count > 0 {
			body["message"] = h.config.T(l.Code)(e.messageKey, e.count, map[string]any{"Count": e.count})
			body["attemptsLeft"] = e.count
		} else {
			body["message"] = h.config.T(l.Code)(e.messageKey)
		}
	}
	writeJSON(w, e.status, map[string]any{"error": body})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// apiLang picks the language of error messages: the page language sent by
// the client, then the saved choice and Accept-Language.
func (h *Handler) apiLang(r *http.Request, short string) config.Language {
	if l, ok := h.config.LanguageByShort(short); ok {
		return l
	}
	return h.langForUnprefixedPage(r)
}

// readJSON accepts only POST with a JSON body of a bounded size. Requiring
// application/json keeps plain HTML forms and link previews out.
func readJSON(w http.ResponseWriter, r *http.Request, limit int64, v any) error {
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct != "application/json" {
		return errors.New("content type")
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

// serveAPI routes /api/secrets and /api/secrets/<id>/<action>.
func (h *Handler) serveAPI(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 || parts[0] != "api" || parts[1] != "secrets" || len(parts) > 4 || len(parts) == 3 {
		h.apiFail(w, r, h.langForUnprefixedPage(r), apiError{status: http.StatusNotFound, code: "not_found"})
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		h.apiFail(w, r, h.langForUnprefixedPage(r), apiError{status: http.StatusMethodNotAllowed, code: "method_not_allowed"})
		return
	}
	if len(parts) == 2 {
		h.createSecret(w, r)
		return
	}
	id, action := parts[2], parts[3]
	if !secretIDRe.MatchString(id) {
		h.apiFail(w, r, h.langForUnprefixedPage(r), apiError{status: http.StatusNotFound, code: "not_found", messageKey: "api.error.notFound"})
		return
	}
	switch action {
	case "reveal":
		h.revealSecret(w, r, id)
	case "destroy":
		h.destroySecret(w, r, id)
	default:
		h.apiFail(w, r, h.langForUnprefixedPage(r), apiError{status: http.StatusNotFound, code: "not_found"})
	}
}

type createRequest struct {
	Data     string `json:"data"`
	PassHash string `json:"passHash"`
	Attach   bool   `json:"attach"`
	TTL      string `json:"ttl"`
	Lang     string `json:"lang"`
}

func (h *Handler) maxDataSize() int64 {
	return h.config.MaxFileSize + textAllowance
}

func (h *Handler) createSecret(w http.ResponseWriter, r *http.Request) {
	l := h.apiLang(r, "")
	if !h.limits.allow("create", clientIP(r)) {
		h.rateLimited(w, r, l)
		return
	}
	var req createRequest
	if err := readJSON(w, r, h.maxDataSize()*4/3+4096, &req); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			h.apiFail(w, r, l, apiError{status: http.StatusRequestEntityTooLarge, code: "too_large", messageKey: "api.error.tooLarge"})
			return
		}
		h.apiFail(w, r, l, apiError{status: http.StatusBadRequest, code: "bad_request", messageKey: "api.error.badRequest"})
		return
	}
	l = h.apiLang(r, req.Lang)
	ttl, ok := allowedTTL[req.TTL]
	if !ok {
		h.apiFail(w, r, l, apiError{status: http.StatusBadRequest, code: "invalid_ttl", messageKey: "api.error.badRequest"})
		return
	}
	data, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil || len(data) == 0 {
		h.apiFail(w, r, l, apiError{status: http.StatusBadRequest, code: "bad_request", messageKey: "api.error.badRequest"})
		return
	}
	if int64(len(data)) > h.maxDataSize() {
		h.apiFail(w, r, l, apiError{status: http.StatusRequestEntityTooLarge, code: "too_large", messageKey: "api.error.tooLarge"})
		return
	}
	var passHash []byte
	if req.PassHash != "" {
		if passHash, err = base64.StdEncoding.DecodeString(req.PassHash); err != nil || len(passHash) != passHashBytes {
			h.apiFail(w, r, l, apiError{status: http.StatusBadRequest, code: "bad_request", messageKey: "api.error.badRequest"})
			return
		}
	}
	expires := time.Now().Unix() + ttl
	id, err := h.storage.Post(storage.Data{Data: data, PassHash: passHash, Attach: req.Attach}, expires)
	if err != nil {
		h.apiFail(w, r, l, apiError{status: http.StatusInternalServerError, code: "server_error", messageKey: "api.error.server"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":      id,
		"expires": expires,
		"token":   h.manageToken(id),
	})
}

type revealRequest struct {
	PassHash string `json:"passHash"`
	Lang     string `json:"lang"`
}

// revealSecret hands out the ciphertext once and deletes it. A wrong
// password does not consume the secret; the third wrong one deletes it.
func (h *Handler) revealSecret(w http.ResponseWriter, r *http.Request, id string) {
	l := h.apiLang(r, "")
	if !h.limits.allow("reveal", clientIP(r)) {
		h.rateLimited(w, r, l)
		return
	}
	var req revealRequest
	if err := readJSON(w, r, 4096, &req); err != nil {
		h.apiFail(w, r, l, apiError{status: http.StatusBadRequest, code: "bad_request", messageKey: "api.error.badRequest"})
		return
	}
	l = h.apiLang(r, req.Lang)

	// One reveal at a time per id, so two parallel requests cannot both get
	// the data before it is deleted.
	unlock := h.idLocks.lock(id)
	defer unlock()

	data, err := h.storage.Get(id, "")
	if err != nil {
		if _, ok := err.(storage.NotFound); ok {
			h.apiFail(w, r, l, apiError{status: http.StatusNotFound, code: "not_found", messageKey: "api.error.notFound"})
			return
		}
		h.apiFail(w, r, l, apiError{status: http.StatusInternalServerError, code: "server_error", messageKey: "api.error.server"})
		return
	}
	if len(data.PassHash) > 0 {
		if req.PassHash == "" {
			h.apiFail(w, r, l, apiError{status: http.StatusUnauthorized, code: "password_required", messageKey: "api.error.passwordRequired"})
			return
		}
		given, err := base64.StdEncoding.DecodeString(req.PassHash)
		if err != nil || subtle.ConstantTimeCompare(given, data.PassHash) != 1 {
			left := h.attempts.fail(id, maxWrongPasswordTries)
			if left <= 0 {
				if err := h.deleteSecret(id); err != nil {
					h.apiFail(w, r, l, apiError{status: http.StatusInternalServerError, code: "server_error", messageKey: "api.error.server"})
					return
				}
				h.apiFail(w, r, l, apiError{status: http.StatusNotFound, code: "too_many_attempts", messageKey: "api.error.tooManyAttempts"})
				return
			}
			h.apiFail(w, r, l, apiError{status: http.StatusForbidden, code: "wrong_password", messageKey: "api.error.wrongPassword", count: left})
			return
		}
	}
	// Do not hand out data that might stay readable
	if err := h.deleteSecret(id); err != nil {
		h.apiFail(w, r, l, apiError{status: http.StatusInternalServerError, code: "server_error", messageKey: "api.error.server"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"data":   base64.StdEncoding.EncodeToString(data.Data),
		"attach": data.Attach,
	})
}

type destroyRequest struct {
	Token string `json:"token"`
	Lang  string `json:"lang"`
}

func (h *Handler) destroySecret(w http.ResponseWriter, r *http.Request, id string) {
	l := h.apiLang(r, "")
	if !h.limits.allow("destroy", clientIP(r)) {
		h.rateLimited(w, r, l)
		return
	}
	var req destroyRequest
	if err := readJSON(w, r, 4096, &req); err != nil {
		h.apiFail(w, r, l, apiError{status: http.StatusBadRequest, code: "bad_request", messageKey: "api.error.badRequest"})
		return
	}
	l = h.apiLang(r, req.Lang)
	if !h.validManageToken(id, req.Token) {
		h.apiFail(w, r, l, apiError{status: http.StatusForbidden, code: "forbidden", messageKey: "api.error.forbidden"})
		return
	}
	if err := h.deleteSecret(id); err != nil {
		h.apiFail(w, r, l, apiError{status: http.StatusInternalServerError, code: "server_error", messageKey: "api.error.server"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"destroyed": true})
}

// deleteSecret removes a secret and reports an error only when it may still
// be readable. A secret that is already gone counts as deleted.
func (h *Handler) deleteSecret(id string) error {
	if err := h.storage.Delete(id); err != nil {
		if _, getErr := h.storage.Get(id, ""); getErr == nil {
			return err
		} else if _, gone := getErr.(storage.NotFound); !gone {
			return getErr
		}
	}
	h.attempts.forget(id)
	return nil
}

func (h *Handler) rateLimited(w http.ResponseWriter, r *http.Request, l config.Language) {
	w.Header().Set("Retry-After", "60")
	h.apiFail(w, r, l, apiError{status: http.StatusTooManyRequests, code: "rate_limited", messageKey: "api.error.rateLimited"})
}

// manageToken is HMAC-SHA256(server secret, id). It is returned once on
// creation, stored nowhere and recomputed to check the sender page.
func (h *Handler) manageToken(id string) string {
	mac := hmac.New(sha256.New, h.manageSecret)
	mac.Write([]byte(id))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (h *Handler) validManageToken(id, token string) bool {
	return subtle.ConstantTimeCompare([]byte(h.manageToken(id)), []byte(token)) == 1
}

// idLocks serializes operations on one secret id.
type idLocks struct {
	mu    sync.Mutex
	locks map[string]*idLock
}

type idLock struct {
	mu   sync.Mutex
	refs int
}

func (l *idLocks) lock(id string) func() {
	l.mu.Lock()
	if l.locks == nil {
		l.locks = make(map[string]*idLock)
	}
	lk := l.locks[id]
	if lk == nil {
		lk = &idLock{}
		l.locks[id] = lk
	}
	lk.refs++
	l.mu.Unlock()
	lk.mu.Lock()
	return func() {
		lk.mu.Unlock()
		l.mu.Lock()
		if lk.refs--; lk.refs == 0 {
			delete(l.locks, id)
		}
		l.mu.Unlock()
	}
}
