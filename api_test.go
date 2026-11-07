package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Draal/secure-share/storage"
)

type apiResp struct {
	code int
	body map[string]interface{}
	hdr  http.Header
}

func (a apiResp) errCode() string {
	if e, ok := a.body["error"].(map[string]interface{}); ok {
		s, _ := e["code"].(string)
		return s
	}
	return ""
}

func (a apiResp) errField(name string) interface{} {
	if e, ok := a.body["error"].(map[string]interface{}); ok {
		return e[name]
	}
	return nil
}

func callAPI(t *testing.T, h http.Handler, method, path string, body interface{}) apiResp {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	r := httptest.NewRequest(method, path, &buf)
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	out := apiResp{code: rec.Code, hdr: rec.Header()}
	json.Unmarshal(rec.Body.Bytes(), &out.body)
	return out
}

var b64 = base64.StdEncoding.EncodeToString

func passHashOf(s string) string {
	h := make([]byte, 32)
	copy(h, s)
	return b64(h)
}

func create(t *testing.T, h http.Handler, req map[string]interface{}) (id, token string, expires int64) {
	t.Helper()
	res := callAPI(t, h, http.MethodPost, "/api/secrets", req)
	if res.code != http.StatusOK {
		t.Fatalf("create: %d %v", res.code, res.body)
	}
	return res.body["id"].(string), res.body["token"].(string), int64(res.body["expires"].(float64))
}

func TestCreateWithEveryTTL(t *testing.T) {
	h, _ := newTestHandler(t)
	for ttl, seconds := range allowedTTL {
		before := time.Now().Unix()
		id, token, expires := create(t, h, map[string]interface{}{"data": b64([]byte{2, 1, 2, 3}), "ttl": ttl})
		if !secretIDRe.MatchString(id) {
			t.Errorf("%s: id %q", ttl, id)
		}
		if expires < before+seconds || expires > time.Now().Unix()+seconds {
			t.Errorf("%s: expires %d, want now+%d", ttl, expires, seconds)
		}
		if len(token) != 43 {
			t.Errorf("%s: token %q", ttl, token)
		}
	}
}

func TestCreateRejectsBadInput(t *testing.T) {
	h, _ := newTestHandler(t)
	data := b64([]byte("ciphertext"))
	cases := map[string]map[string]interface{}{
		"no ttl":         {"data": data},
		"unknown ttl":    {"data": data, "ttl": "2d"},
		"ttl case":       {"data": data, "ttl": "1H"},
		"ttl seconds":    {"data": data, "ttl": "3600"},
		"no data":        {"ttl": "1d"},
		"bad base64":     {"data": "%%%", "ttl": "1d"},
		"short passHash": {"data": data, "ttl": "1d", "passHash": b64([]byte("short"))},
		"bad passHash":   {"data": data, "ttl": "1d", "passHash": "%%%"},
	}
	for name, body := range cases {
		if res := callAPI(t, h, http.MethodPost, "/api/secrets", body); res.code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", name, res.code)
		}
	}

	r := httptest.NewRequest(http.MethodPost, "/api/secrets", strings.NewReader("data="+data+"&ttl=1d"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("form body: got %d, want 400", rec.Code)
	}

	big := make([]byte, testConfig.cfg.MaxFileSize+textAllowance+1)
	if res := callAPI(t, h, http.MethodPost, "/api/secrets", map[string]interface{}{"data": b64(big), "ttl": "1d"}); res.code != http.StatusRequestEntityTooLarge {
		t.Errorf("too large: got %d, want 413", res.code)
	}
}

func TestAPIOnlyAcceptsPOST(t *testing.T) {
	h, _ := newTestHandler(t)
	id, _, _ := create(t, h, map[string]interface{}{"data": b64([]byte("x")), "ttl": "1h"})
	for _, path := range []string{"/api/secrets", "/api/secrets/" + id + "/reveal", "/api/secrets/" + id + "/destroy"} {
		for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodDelete} {
			if res := callAPI(t, h, m, path, nil); res.code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s: got %d, want 405", m, path, res.code)
			}
		}
	}
	// The GETs above must not have consumed the secret.
	if res := callAPI(t, h, http.MethodPost, "/api/secrets/"+id+"/reveal", map[string]interface{}{}); res.code != http.StatusOK {
		t.Errorf("reveal after GETs: %d", res.code)
	}
}

func TestRevealDeletesAfterDelivery(t *testing.T) {
	h, _ := newTestHandler(t)
	payload := []byte{2, 9, 8, 7, 6}
	id, _, _ := create(t, h, map[string]interface{}{"data": b64(payload), "ttl": "1d", "attach": true})
	res := callAPI(t, h, http.MethodPost, "/api/secrets/"+id+"/reveal", map[string]interface{}{})
	if res.code != http.StatusOK || res.body["data"] != b64(payload) || res.body["attach"] != true {
		t.Fatalf("reveal: %d %v", res.code, res.body)
	}
	if res.hdr.Get("Cache-Control") != "no-store" {
		t.Errorf("reveal response is cacheable")
	}
	if res := callAPI(t, h, http.MethodPost, "/api/secrets/"+id+"/reveal", map[string]interface{}{}); res.code != http.StatusNotFound || res.errCode() != "not_found" {
		t.Errorf("second reveal: %d %v", res.code, res.body)
	}
}

func TestWrongPasswords(t *testing.T) {
	h, _ := newTestHandler(t)
	right, wrong := passHashOf("right"), passHashOf("wrong")
	id, _, _ := create(t, h, map[string]interface{}{"data": b64([]byte("x")), "ttl": "1d", "passHash": right})

	if res := callAPI(t, h, http.MethodPost, "/api/secrets/"+id+"/reveal", map[string]interface{}{}); res.code != http.StatusUnauthorized || res.errCode() != "password_required" {
		t.Errorf("no password: %d %v", res.code, res.body)
	}
	for _, left := range []float64{2, 1} {
		res := callAPI(t, h, http.MethodPost, "/api/secrets/"+id+"/reveal", map[string]interface{}{"passHash": wrong})
		if res.code != http.StatusForbidden || res.errCode() != "wrong_password" || res.errField("attemptsLeft") != left {
			t.Errorf("wrong password, %v left: %d %v", left, res.code, res.body)
		}
	}
	// A wrong password does not consume the secret, a missing one is not an attempt.
	if res := callAPI(t, h, http.MethodPost, "/api/secrets/"+id+"/reveal", map[string]interface{}{"passHash": right}); res.code != http.StatusOK {
		t.Fatalf("right password after two wrong: %d %v", res.code, res.body)
	}

	id, _, _ = create(t, h, map[string]interface{}{"data": b64([]byte("x")), "ttl": "1d", "passHash": right})
	for i := 0; i < 2; i++ {
		callAPI(t, h, http.MethodPost, "/api/secrets/"+id+"/reveal", map[string]interface{}{"passHash": wrong})
	}
	if res := callAPI(t, h, http.MethodPost, "/api/secrets/"+id+"/reveal", map[string]interface{}{"passHash": wrong}); res.code != http.StatusNotFound || res.errCode() != "too_many_attempts" {
		t.Errorf("third wrong password: %d %v", res.code, res.body)
	}
	if res := callAPI(t, h, http.MethodPost, "/api/secrets/"+id+"/reveal", map[string]interface{}{"passHash": right}); res.code != http.StatusNotFound {
		t.Errorf("right password after deletion: %d", res.code)
	}
}

func TestDestroyNeedsTheToken(t *testing.T) {
	h, _ := newTestHandler(t)
	id, token, _ := create(t, h, map[string]interface{}{"data": b64([]byte("x")), "ttl": "1d"})
	other, otherToken, _ := create(t, h, map[string]interface{}{"data": b64([]byte("y")), "ttl": "1d"})
	for _, bad := range []string{"", "x", otherToken, strings.ToUpper(token)} {
		if res := callAPI(t, h, http.MethodPost, "/api/secrets/"+id+"/destroy", map[string]interface{}{"token": bad}); res.code != http.StatusForbidden {
			t.Errorf("token %q: got %d, want 403", bad, res.code)
		}
	}
	if res := callAPI(t, h, http.MethodPost, "/api/secrets/"+id+"/destroy", map[string]interface{}{"token": token}); res.code != http.StatusOK {
		t.Fatalf("destroy: %d %v", res.code, res.body)
	}
	if res := callAPI(t, h, http.MethodPost, "/api/secrets/"+id+"/reveal", map[string]interface{}{}); res.code != http.StatusNotFound {
		t.Errorf("reveal after destroy: %d", res.code)
	}
	if res := callAPI(t, h, http.MethodPost, "/api/secrets/"+other+"/reveal", map[string]interface{}{}); res.code != http.StatusOK {
		t.Errorf("other secret was affected: %d", res.code)
	}
}

func TestOldFormatSecretsCanBeRevealed(t *testing.T) {
	// Secrets stored by the old server: raw CryptoJS ciphertext and, with a
	// password, the base64 HmacSHA256 the old share.js computed.
	h, spy := newTestHandler(t)
	oldHash := make([]byte, 32)
	for i := range oldHash {
		oldHash[i] = byte(i * 7)
	}
	id, err := spy.Post(storage.Data{Data: []byte("U2FsdGVk-old"), PassHash: oldHash}, time.Now().Unix()+3600)
	if err != nil {
		t.Fatal(err)
	}
	res := callAPI(t, h, http.MethodPost, "/api/secrets/"+id+"/reveal", map[string]interface{}{"passHash": b64(oldHash)})
	if res.code != http.StatusOK || res.body["data"] != b64([]byte("U2FsdGVk-old")) {
		t.Errorf("old secret: %d %v", res.code, res.body)
	}
}

func TestParallelRevealsGiveTheSecretOnce(t *testing.T) {
	h, _ := newTestHandler(t)
	id, _, _ := create(t, h, map[string]interface{}{"data": b64([]byte("x")), "ttl": "1d"})
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if res := callAPI(t, h, http.MethodPost, "/api/secrets/"+id+"/reveal", map[string]interface{}{}); res.code == http.StatusOK {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Errorf("secret was given out %d times", ok)
	}
}

func TestErrorsInTheRequestedLanguage(t *testing.T) {
	h, _ := newTestHandler(t)
	res := callAPI(t, h, http.MethodPost, "/api/secrets/"+testID+"/reveal", map[string]interface{}{"lang": "ru"})
	if msg, _ := res.errField("message").(string); !strings.Contains(msg, "Секрет не найден") {
		t.Errorf("message %q is not Russian", msg)
	}
}

func TestRateLimits(t *testing.T) {
	newTestHandler(t) // loads the shared config
	spy := &spyStorage{Storage: storage.OpenMemoryStorage()}
	h, err := newHandler(testConfig.cfg, spy, handlerOptions{
		SiteURL:      "https://encrypt.one",
		ManageSecret: []byte("test-manage-secret-0123456789abcdef"),
	})
	if err != nil {
		t.Fatal(err)
	}
	h.limits = newRateLimiter(map[string]rateRule{"create": {burst: 2, interval: time.Hour}, "reveal": {burst: 3, interval: time.Hour}})
	body := map[string]interface{}{"data": b64([]byte("x")), "ttl": "1h"}
	callAPI(t, h, http.MethodPost, "/api/secrets", body)
	callAPI(t, h, http.MethodPost, "/api/secrets", body)
	res := callAPI(t, h, http.MethodPost, "/api/secrets", body)
	if res.code != http.StatusTooManyRequests || res.hdr.Get("Retry-After") == "" || res.errCode() != "rate_limited" {
		t.Errorf("third create: %d %v", res.code, res.body)
	}
	for i := 0; i < 3; i++ {
		callAPI(t, h, http.MethodPost, "/api/secrets/"+testID+"/reveal", map[string]interface{}{})
	}
	if res := callAPI(t, h, http.MethodPost, "/api/secrets/"+testID+"/reveal", map[string]interface{}{}); res.code != http.StatusTooManyRequests {
		t.Errorf("fourth reveal: %d", res.code)
	}
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:5555"
	if ip := clientIP(r); ip != "10.0.0.1" {
		t.Errorf("no header: %s", ip)
	}
	r.Header.Set("X-Real-IP", "3.3.3.3")
	if ip := clientIP(r); ip != "3.3.3.3" {
		t.Errorf("X-Real-IP: %s", ip)
	}
}

func TestFailedDeleteIsNotReportedAsSuccess(t *testing.T) {
	h, spy := newTestHandler(t)
	id, token, _ := create(t, h, map[string]interface{}{"data": b64([]byte("x")), "ttl": "1h", "passHash": passHashOf("p")})
	spy.failDelete = true
	if res := callAPI(t, h, http.MethodPost, "/api/secrets/"+id+"/destroy", map[string]interface{}{"token": token}); res.code != http.StatusInternalServerError {
		t.Errorf("destroy: got %d, want 500", res.code)
	}
	for i := 0; i < maxWrongPasswordTries; i++ {
		callAPI(t, h, http.MethodPost, "/api/secrets/"+id+"/reveal", map[string]interface{}{"passHash": passHashOf("wrong")})
	}
	if res := callAPI(t, h, http.MethodPost, "/api/secrets/"+id+"/reveal", map[string]interface{}{"passHash": passHashOf("p")}); res.code != http.StatusInternalServerError || res.body["data"] != nil {
		t.Errorf("reveal with a failing delete: %d %v", res.code, res.body)
	}
	spy.failDelete = false
	if res := callAPI(t, h, http.MethodPost, "/api/secrets/"+id+"/destroy", map[string]interface{}{"token": token}); res.code != http.StatusOK {
		t.Errorf("destroy: got %d, want 200", res.code)
	}
}

func TestCheckDiskPaths(t *testing.T) {
	dir := t.TempDir()
	for paths, ok := range map[string]bool{"": false, dir: true, dir + ":" + dir: true, dir + ":": false, dir + "/missing": false} {
		if err := checkDiskPaths(paths); (err == nil) != ok {
			t.Errorf("checkDiskPaths(%q): %v", paths, err)
		}
	}
}
