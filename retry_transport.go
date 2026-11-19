package workloadsecrets

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"time"
)

// retryTransport retries transient failures under retryPolicy: exponential backoff with jitter, Retry-After honoured,
// a per-attempt timeout, a total deadline over all attempts and waits, and a rule that keeps requests that may already
// have been processed from being sent twice unless the API contract marks the operation retry-safe.
type retryTransport struct {
	policy retryPolicy
	safety operationSafety
	next   http.RoundTripper
	logger *slog.Logger
	// random returns a value in [0, 1); replaceable in tests.
	random func() float64
}

func newRetryTransport(policy retryPolicy, safety operationSafety, next http.RoundTripper, logger *slog.Logger) *retryTransport {
	return &retryTransport{policy: policy, safety: safety, next: next, logger: logger, random: rand.Float64}
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		req.Body.Close()
	}

	retrySafe := t.safety.retrySafe(req)
	ctx, cancelTotal := context.WithTimeout(req.Context(), t.policy.total)
	for attempt := 1; ; attempt++ {
		attemptCtx, cancelAttempt := context.WithTimeout(ctx, t.policy.perAttempt)
		out := req.Clone(attemptCtx)
		if body != nil {
			out.Body = io.NopCloser(bytes.NewReader(body))
			out.ContentLength = int64(len(body))
			out.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
		}

		resp, err := t.next.RoundTrip(out)
		if attempt >= t.policy.maxAttempts || !t.policy.shouldRetry(ctx, retrySafe, resp, err) {
			return t.finish(resp, err, cancelAttempt, cancelTotal)
		}
		wait, ok := t.policy.delay(attempt, resp, t.random)
		if !ok {
			return t.finish(resp, err, cancelAttempt, cancelTotal)
		}
		t.logRetry(req, attempt, wait, resp, err)
		if resp != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		cancelAttempt()

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			cancelTotal()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

// finish returns the final outcome. The contexts stay alive until the caller closes the response body, so a body that is
// read after RoundTrip returns is not cut off.
func (t *retryTransport) finish(resp *http.Response, err error, cancelAttempt, cancelTotal context.CancelFunc) (*http.Response, error) {
	if err != nil || resp == nil {
		cancelAttempt()
		cancelTotal()
		return resp, err
	}
	resp.Body = &cancelOnClose{ReadCloser: resp.Body, cancel: func() {
		cancelAttempt()
		cancelTotal()
	}}
	return resp, nil
}

func (t *retryTransport) logRetry(req *http.Request, attempt int, wait time.Duration, resp *http.Response, err error) {
	if t.logger == nil {
		return
	}
	attrs := []any{slog.String("method", req.Method), slog.String("path", req.URL.Path), slog.Int("attempt", attempt), slog.Duration("wait", wait)}
	if resp != nil {
		attrs = append(attrs, slog.Int("status", resp.StatusCode))
	}
	if err != nil {
		attrs = append(attrs, slog.String("error", err.Error()))
	}
	t.logger.Debug("retrying request", attrs...)
}
