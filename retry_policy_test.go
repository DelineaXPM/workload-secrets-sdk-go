package workloadsecrets

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestRetryPolicy_ShouldRetryByMethodAndStatus(t *testing.T) {
	policy := defaultRetryPolicy()
	cases := []struct {
		method     string
		status     int
		retryAfter string
		want       bool
	}{
		{http.MethodGet, 502, "", true},
		{http.MethodGet, 503, "", true},
		{http.MethodGet, 504, "", true},
		{http.MethodGet, 408, "", true},
		{http.MethodGet, 429, "", true},
		{http.MethodGet, 500, "", false},
		{http.MethodGet, 404, "", false},
		{http.MethodGet, 400, "", false},
		{http.MethodPost, 502, "", false},
		{http.MethodPost, 504, "", false},
		{http.MethodPost, 408, "", false},
		{http.MethodPost, 503, "", false},
		{http.MethodPost, 503, "1", true},
		{http.MethodPost, 429, "", true},
		{http.MethodDelete, 502, "", false},
		{http.MethodPut, 503, "2", true},
	}
	for _, c := range cases {
		resp := &http.Response{StatusCode: c.status, Header: http.Header{}}
		if c.retryAfter != "" {
			resp.Header.Set("Retry-After", c.retryAfter)
		}
		if got := policy.shouldRetry(context.Background(), isSafeMethod(c.method), resp, nil); got != c.want {
			t.Errorf("%s %d (Retry-After %q) = %v, want %v", c.method, c.status, c.retryAfter, got, c.want)
		}
	}
}

func TestRetryPolicy_ShouldRetryByError(t *testing.T) {
	policy := defaultRetryPolicy()
	refused := &url.Error{Op: "Post", URL: "http://x", Err: &net.OpError{Op: "dial", Err: errors.New("connection refused")}}
	reset := &url.Error{Op: "Post", URL: "http://x", Err: &net.OpError{Op: "read", Err: errors.New("connection reset by peer")}}
	declined := &RedirectNotFollowedError{StatusCode: 307, Location: "http://other"}

	if !policy.shouldRetry(context.Background(), isSafeMethod(http.MethodPost), nil, refused) {
		t.Error("a refused connection (never sent) must be retried for POST")
	}
	if policy.shouldRetry(context.Background(), isSafeMethod(http.MethodPost), nil, reset) {
		t.Error("a reset after the request was sent must not be retried for POST")
	}
	if !policy.shouldRetry(context.Background(), isSafeMethod(http.MethodGet), nil, reset) {
		t.Error("a reset after the request was sent is retried for GET")
	}
	if policy.shouldRetry(context.Background(), isSafeMethod(http.MethodGet), nil, declined) {
		t.Error("a declined redirect must not be retried")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if policy.shouldRetry(cancelled, isSafeMethod(http.MethodGet), nil, refused) {
		t.Error("nothing is retried once the context is done")
	}
}

func TestRetryPolicy_DelayFollowsBackoffWithJitterAndCap(t *testing.T) {
	policy := defaultRetryPolicy()
	cases := []struct {
		retry    int
		min, max time.Duration
	}{
		{1, 250 * time.Millisecond, 500 * time.Millisecond},
		{2, 500 * time.Millisecond, time.Second},
		{3, time.Second, 2 * time.Second},
		{6, 4 * time.Second, 8 * time.Second}, // 500 ms * 2^5 = 16 s, capped at 8 s
	}
	for _, c := range cases {
		low, _ := policy.delay(c.retry, nil, func() float64 { return 0 })
		high, _ := policy.delay(c.retry, nil, func() float64 { return 0.999999 })
		if low != c.min {
			t.Errorf("retry %d lowest delay = %v, want %v", c.retry, low, c.min)
		}
		if high < c.max-time.Millisecond || high > c.max {
			t.Errorf("retry %d highest delay = %v, want about %v", c.retry, high, c.max)
		}
	}
}

func TestRetryPolicy_RetryAfterReplacesBackoffAndIsCapped(t *testing.T) {
	policy := defaultRetryPolicy()
	zero := func() float64 { return 0 }

	seconds := &http.Response{Header: http.Header{"Retry-After": {"3"}}}
	if d, ok := policy.delay(1, seconds, zero); !ok || d != 3*time.Second {
		t.Errorf("Retry-After 3 = %v, %v, want 3s, true", d, ok)
	}
	date := &http.Response{Header: http.Header{"Retry-After": {time.Now().Add(5 * time.Second).UTC().Format(http.TimeFormat)}}}
	if d, ok := policy.delay(1, date, zero); !ok || d < 3*time.Second || d > 5*time.Second {
		t.Errorf("Retry-After date = %v, %v, want about 4-5s, true", d, ok)
	}
	over := &http.Response{Header: http.Header{"Retry-After": {"60"}}}
	if _, ok := policy.delay(1, over, zero); ok {
		t.Error("Retry-After above the limit must stop retrying")
	}
	junk := &http.Response{Header: http.Header{"Retry-After": {"soon"}}}
	if d, ok := policy.delay(1, junk, zero); !ok || d != 250*time.Millisecond {
		t.Errorf("unparsable Retry-After = %v, %v, want the computed backoff", d, ok)
	}
}
