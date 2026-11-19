package workloadsecrets

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fastPolicy() retryPolicy {
	policy := defaultRetryPolicy()
	policy.baseDelay = time.Millisecond
	return policy
}

func retryClient(policy retryPolicy) *http.Client {
	return &http.Client{Transport: newRetryTransport(policy, newOperationSafety(""), http.DefaultTransport, nil)}
}

func TestRetryTransport_RetriesSafeMethodUntilSuccess(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	defer server.Close()

	resp, err := retryClient(fastPolicy()).Get(server.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK || calls.Load() != 3 {
		t.Errorf("status %d after %d calls, want 200 after 3", resp.StatusCode, calls.Load())
	}
}

func TestRetryTransport_StopsAtMaxAttempts(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	resp, err := retryClient(fastPolicy()).Get(server.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable || calls.Load() != 4 {
		t.Errorf("status %d after %d calls, want 503 after 4", resp.StatusCode, calls.Load())
	}
}

func TestRetryTransport_DoesNotRetryUnsafeMethodOn502(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	resp, err := retryClient(fastPolicy()).Post(server.URL, "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	resp.Body.Close()

	if calls.Load() != 1 {
		t.Errorf("calls = %d, want 1", calls.Load())
	}
}

func TestRetryTransport_RetriesUnsafeMethodOn503WithRetryAfterAndReplaysBody(t *testing.T) {
	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		if len(bodies) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer server.Close()

	resp, err := retryClient(fastPolicy()).Post(server.URL, "text/plain", strings.NewReader("payload"))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	resp.Body.Close()

	if len(bodies) != 2 || bodies[0] != "payload" || bodies[1] != "payload" {
		t.Errorf("bodies = %v, want the payload on both attempts", bodies)
	}
}

func TestRetryTransport_ReturnsResponseWhenRetryAfterIsOverTheLimit(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	start := time.Now()
	resp, err := retryClient(fastPolicy()).Get(server.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable || calls.Load() != 1 || time.Since(start) > 2*time.Second {
		t.Errorf("status %d, %d calls, %v: want the 503 returned at once after one call", resp.StatusCode, calls.Load(), time.Since(start))
	}
}

func TestRetryTransport_CancelDuringWaitReturnsPromptly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)

	start := time.Now()
	_, err := retryClient(fastPolicy()).Do(req)

	if err == nil || time.Since(start) > 2*time.Second {
		t.Errorf("err = %v after %v, want a context error well before the 5 s wait", err, time.Since(start))
	}
}

func TestRetryTransport_PerAttemptTimeoutRetriesSafeMethod(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			time.Sleep(400 * time.Millisecond)
		}
	}))
	defer server.Close()

	policy := fastPolicy()
	policy.perAttempt = 100 * time.Millisecond
	resp, err := retryClient(policy).Get(server.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK || calls.Load() != 2 {
		t.Errorf("status %d after %d calls, want 200 after 2 (first attempt timed out)", resp.StatusCode, calls.Load())
	}
}

func TestRetryTransport_BodyReadAfterRoundTripIsNotCutOff(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte("late body"))
	}))
	defer server.Close()

	policy := fastPolicy()
	policy.perAttempt = 2 * time.Second
	resp, err := retryClient(policy).Get(server.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)

	if err != nil || string(body) != "late body" {
		t.Errorf("body %q, err %v, want the whole body read after RoundTrip returned", body, err)
	}
}

func TestRetryTransport_TotalTimeoutBoundsTheCall(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	policy := fastPolicy()
	policy.total = 1500 * time.Millisecond
	start := time.Now()
	_, err := retryClient(policy).Get(server.URL)

	if err == nil || time.Since(start) > 2*time.Second || calls.Load() != 2 {
		t.Errorf("err %v after %v and %d calls, want a deadline error at about 1.5 s after 2 calls", err, time.Since(start), calls.Load())
	}
}
