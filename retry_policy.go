package workloadsecrets

import (
	"context"
	"errors"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// retryPolicy is the retry behaviour shared by the .NET and Go SDKs: the values and rules are those in
// src/SDK/behavior/sdk-behavior.json, which the conformance suite checks on the wire.
type retryPolicy struct {
	maxAttempts   int
	baseDelay     time.Duration
	multiplier    float64
	capDelay      time.Duration
	jitterMin     float64
	retryAfterMax time.Duration
	perAttempt    time.Duration
	total         time.Duration
}

func defaultRetryPolicy() retryPolicy {
	return retryPolicy{
		maxAttempts:   4,
		baseDelay:     500 * time.Millisecond,
		multiplier:    2,
		capDelay:      8 * time.Second,
		jitterMin:     0.5,
		retryAfterMax: 30 * time.Second,
		perAttempt:    15 * time.Second,
		total:         60 * time.Second,
	}
}

// shouldRetry decides whether an attempt's outcome is worth another attempt. retrySafe says whether the operation may be
// sent again after the server may have received it (operationSafety.retrySafe; the token request passes false).
//
// A retry-safe operation retries on a connection failure, a failure after the request was sent, and 408, 429, 502, 503
// and 504. Any other operation retries only when the request provably was not processed: the connection was never
// established, 429, or 503 carrying Retry-After (the API sends it only when it shed the request).
func (p retryPolicy) shouldRetry(ctx context.Context, retrySafe bool, resp *http.Response, err error) bool {
	if err != nil {
		var declined *RedirectNotFollowedError
		if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.As(err, &declined) {
			return false
		}
		return isConnectFailure(err) || retrySafe
	}
	if resp == nil {
		return false
	}
	switch resp.StatusCode {
	case http.StatusTooManyRequests:
		return true
	case http.StatusServiceUnavailable:
		return retrySafe || resp.Header.Get("Retry-After") != ""
	case http.StatusRequestTimeout, http.StatusBadGateway, http.StatusGatewayTimeout:
		return retrySafe
	default:
		return false
	}
}

// delay is the wait before retry number retryNumber (1 for the first retry). A Retry-After header replaces the computed
// backoff; one above retryAfterMax makes ok false, which means the response is returned instead of waited out.
func (p retryPolicy) delay(retryNumber int, resp *http.Response, random func() float64) (d time.Duration, ok bool) {
	if resp != nil {
		if wait, present := retryAfter(resp, time.Now()); present {
			if wait > p.retryAfterMax {
				return 0, false
			}
			return wait, true
		}
	}
	backoff := float64(p.baseDelay) * math.Pow(p.multiplier, float64(retryNumber-1))
	if limit := float64(p.capDelay); backoff > limit {
		backoff = limit
	}
	return time.Duration(backoff * (p.jitterMin + random()*(1-p.jitterMin))), true
}

// retryAfter reads Retry-After as whole seconds or an HTTP date.
func retryAfter(resp *http.Response, now time.Time) (time.Duration, bool) {
	value := strings.TrimSpace(resp.Header.Get("Retry-After"))
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.ParseFloat(value, 64); err == nil && seconds >= 0 {
		return time.Duration(seconds * float64(time.Second)), true
	}
	if date, err := http.ParseTime(value); err == nil {
		return max(0, date.Sub(now)), true
	}
	return 0, false
}

func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

// isConnectFailure reports a failure before any request bytes were sent: DNS lookup or dialing the server.
func isConnectFailure(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && op.Op == "dial"
}
