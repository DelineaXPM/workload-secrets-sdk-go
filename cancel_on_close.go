package workloadsecrets

import (
	"context"
	"io"
)

// cancelOnClose cancels a context when the response body is closed. A timeout context tied to a response must outlive
// RoundTrip, because the caller reads the body afterwards.
type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelOnClose) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}
