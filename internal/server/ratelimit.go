package server

import (
	"sync"
	"time"
)

// rateLimiter is the fixed-window per-sender budget from
// app-src/lib/core/host/rate_limiter.dart. The bucket table is capped so a
// flood of fresh sender keys cannot grow memory without bound.
type rateLimiter struct {
	mu         sync.Mutex
	limit      int
	windowSecs int64
	maxKeys    int
	buckets    map[string]*bucket
}

type bucket struct {
	window int64
	count  int
}

func newRateLimiter(limit, windowSeconds, maxKeys int) *rateLimiter {
	return &rateLimiter{
		limit:      limit,
		windowSecs: int64(windowSeconds),
		maxKeys:    maxKeys,
		buckets:    make(map[string]*bucket),
	}
}

func (r *rateLimiter) allow(key string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	window := now.UnixMilli() / (r.windowSecs * 1000)
	b, ok := r.buckets[key]
	if !ok || b.window != window {
		r.evictIfNeeded()
		r.buckets[key] = &bucket{window: window, count: 1}
		return true
	}
	if b.count >= r.limit {
		return false
	}
	b.count++
	return true
}

func (r *rateLimiter) evictIfNeeded() {
	if len(r.buckets) < r.maxKeys {
		return
	}
	var oldest int64 = 1<<62 - 1
	for _, b := range r.buckets {
		if b.window < oldest {
			oldest = b.window
		}
	}
	for k, b := range r.buckets {
		if b.window <= oldest {
			delete(r.buckets, k)
		}
	}
	if len(r.buckets) >= r.maxKeys {
		for k := range r.buckets {
			delete(r.buckets, k)
			break
		}
	}
}
