package api

import (
	"math"
	"strings"
	"sync"
	"time"
)

// limiter is an in-memory token bucket per key. State is lost on restart,
// which is fine for abuse throttling.
type limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	buckets map[string]*bucket
	now     func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(perSecond float64, burst int) *limiter {
	return &limiter{rate: perSecond, burst: float64(burst), buckets: map[string]*bucket{}, now: time.Now}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = math.Min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *limiter) prune(idle time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := l.now().Add(-idle)
	for k, b := range l.buckets {
		if b.last.Before(cutoff) {
			delete(l.buckets, k)
		}
	}
}

// backoff throttles failed password logins per (email, IP). After
// freeAttempts failures, each further failure doubles the wait, capped at
// maxDelay. Keying on the IP too means a stranger can't lock the real owner
// out; there is deliberately no hard account lockout.
type backoff struct {
	mu    sync.Mutex
	fails map[string]*failState
	now   func() time.Time
}

type failState struct {
	count int
	until time.Time
	last  time.Time
}

const (
	freeAttempts = 5
	maxDelay     = 15 * time.Minute
)

func newBackoff() *backoff {
	return &backoff{fails: map[string]*failState{}, now: time.Now}
}

func backoffKey(email, ip string) string { return email + "\x00" + ip }

// wait returns how long the key must wait before another attempt.
func (b *backoff) wait(email, ip string) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	if f, ok := b.fails[backoffKey(email, ip)]; ok {
		if d := f.until.Sub(b.now()); d > 0 {
			return d
		}
	}
	return 0
}

func (b *backoff) fail(email, ip string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	k := backoffKey(email, ip)
	f, ok := b.fails[k]
	if !ok {
		f = &failState{}
		b.fails[k] = f
	}
	now := b.now()
	f.count++
	f.last = now
	if f.count >= freeAttempts {
		d := time.Duration(1<<min(f.count-freeAttempts, 20)) * time.Second
		f.until = now.Add(min(d, maxDelay))
	}
}

func (b *backoff) succeed(email, ip string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.fails, backoffKey(email, ip))
}

// clearEmail forgets every failure for an email (after a password reset).
func (b *backoff) clearEmail(email string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	prefix := email + "\x00"
	for k := range b.fails {
		if strings.HasPrefix(k, prefix) {
			delete(b.fails, k)
		}
	}
}

func (b *backoff) prune(idle time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	cutoff := b.now().Add(-idle)
	for k, f := range b.fails {
		if f.last.Before(cutoff) {
			delete(b.fails, k)
		}
	}
}
