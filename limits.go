package main

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// rateRule allows burst requests at once and refills one every interval.
type rateRule struct {
	burst    float64
	interval time.Duration
}

// Limits per client IP. Generous for people, tight for scripts.
var defaultRateRules = map[string]rateRule{
	"create":  {burst: 20, interval: 30 * time.Second}, // ~120 per hour
	"reveal":  {burst: 30, interval: 10 * time.Second}, // ~360 per hour
	"destroy": {burst: 20, interval: 30 * time.Second},
}

type bucket struct {
	tokens float64
	last   time.Time
}

// rateLimiter is an in-memory token bucket per action and IP. IPs live only
// in this map and are never logged.
type rateLimiter struct {
	mu      sync.Mutex
	rules   map[string]rateRule
	buckets map[string]*bucket
	now     func() time.Time
}

func newRateLimiter(rules map[string]rateRule) *rateLimiter {
	rl := &rateLimiter{rules: rules, buckets: make(map[string]*bucket), now: time.Now}
	go func() {
		for range time.Tick(10 * time.Minute) {
			rl.cleanup()
		}
	}()
	return rl
}

func (rl *rateLimiter) allow(action, ip string) bool {
	rule, ok := rl.rules[action]
	if !ok {
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := rl.now()
	key := action + "|" + ip
	b := rl.buckets[key]
	if b == nil {
		b = &bucket{tokens: rule.burst, last: now}
		rl.buckets[key] = b
	}
	b.tokens += float64(now.Sub(b.last)) / float64(rule.interval)
	if b.tokens > rule.burst {
		b.tokens = rule.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// cleanup drops buckets that are full again.
func (rl *rateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := rl.now()
	for key, b := range rl.buckets {
		rule := rl.rules[key[:strings.IndexByte(key, '|')]]
		if b.tokens+float64(now.Sub(b.last))/float64(rule.interval) >= rule.burst {
			delete(rl.buckets, key)
		}
	}
}

// clientIP is the address used for rate limits: X-Real-IP set by the proxy,
// or the connection address when the header is missing.
func clientIP(r *http.Request) string {
	if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// passwordAttempts counts wrong passwords per secret id. It lives in memory
// like the counter of the old server: the storage interface has no place
// for it, so the count starts over after a restart.
type passwordAttempts struct {
	mu    sync.Mutex
	count map[string]attempt
}

type attempt struct {
	n    int
	last time.Time
}

func newPasswordAttempts() *passwordAttempts {
	pa := &passwordAttempts{count: make(map[string]attempt)}
	go func() {
		for range time.Tick(time.Hour) {
			pa.cleanup(time.Now().Add(-8 * 24 * time.Hour))
		}
	}()
	return pa
}

// fail records a wrong password and returns how many attempts are left.
func (pa *passwordAttempts) fail(id string, max int) int {
	pa.mu.Lock()
	defer pa.mu.Unlock()
	a := pa.count[id]
	a.n++
	a.last = time.Now()
	pa.count[id] = a
	return max - a.n
}

func (pa *passwordAttempts) forget(id string) {
	pa.mu.Lock()
	delete(pa.count, id)
	pa.mu.Unlock()
}

// cleanup drops counters older than the longest storage time.
func (pa *passwordAttempts) cleanup(before time.Time) {
	pa.mu.Lock()
	defer pa.mu.Unlock()
	for id, a := range pa.count {
		if a.last.Before(before) {
			delete(pa.count, id)
		}
	}
}
