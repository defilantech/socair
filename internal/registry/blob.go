package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"time"
)

var errStalled = errors.New("stalled")

// OpenBlob streams a blob of the size its descriptor gives: an image layer,
// which can be many gigabytes, so it is never held in memory. The bytes are
// hashed as they are read. The reader fails if the registry sends more or
// fewer bytes than size, or if nothing arrives for the client's stall bound,
// and the read that reaches the end fails unless the bytes hash to digest: a
// caller trusts nothing it read until a read returns io.EOF. A redirect to a
// storage service is followed without credentials, as for Blob.
func (r *Repo) OpenBlob(ctx context.Context, digest string, size int64) (io.ReadCloser, error) {
	if err := ValidDigest(digest); err != nil {
		return nil, err
	}
	if size < 0 {
		return nil, fmt.Errorf("blob %s: negative size %d", digest, size)
	}
	ctx, cancel := context.WithCancelCause(ctx)
	rq := r.request(http.MethodGet, "/blobs/"+digest, false)
	resp, err := r.c.doWith(ctx, r.c.stream, rq)
	if err != nil {
		cancel(nil)
		return nil, fmt.Errorf("fetch blob %s: %w", digest, redact(err))
	}
	if resp.StatusCode != http.StatusOK {
		defer cancel(nil)
		defer drain(resp)
		return nil, r.c.statusError(rq, resp)
	}
	if resp.ContentLength >= 0 && resp.ContentLength != size {
		cancel(nil)
		drain(resp)
		return nil, fmt.Errorf("blob %s: the registry sends %d bytes, the manifest gives %d", digest, resp.ContentLength, size)
	}
	b := &blobReader{body: resp.Body, h: sha256.New(), digest: digest, size: size, ctx: ctx, cancel: cancel, stall: r.c.stall}
	b.timer = time.AfterFunc(b.stall, func() { cancel(errStalled) })
	return b, nil
}

type blobReader struct {
	body   io.ReadCloser
	h      hash.Hash
	digest string
	size   int64
	n      int64
	ctx    context.Context
	cancel context.CancelCauseFunc
	stall  time.Duration
	timer  *time.Timer
	err    error
}

func (b *blobReader) Read(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	// Read at most one byte past the size, to see a registry that sends
	// more.
	if rest := b.size - b.n + 1; int64(len(p)) > rest {
		p = p[:rest]
	}
	n, err := b.body.Read(p)
	if n > 0 {
		b.timer.Reset(b.stall)
	}
	b.h.Write(p[:n])
	b.n += int64(n)
	switch {
	case b.n > b.size:
		return 0, b.fail(fmt.Errorf("blob %s: the registry sent more than the %d bytes the manifest gives", b.digest, b.size))
	case err == io.EOF:
		if b.n != b.size {
			return 0, b.fail(fmt.Errorf("blob %s: the registry sent %d bytes, the manifest gives %d", b.digest, b.n, b.size))
		}
		if got := "sha256:" + hex.EncodeToString(b.h.Sum(nil)); got != b.digest {
			return 0, b.fail(fmt.Errorf("blob %s: the registry served bytes that hash to %s", b.digest, got))
		}
		b.err = io.EOF
		b.timer.Stop()
		return n, io.EOF
	case err != nil:
		if errors.Is(context.Cause(b.ctx), errStalled) {
			return 0, b.fail(fmt.Errorf("blob %s: no data for %s after %d of %d bytes", b.digest, b.stall, b.n, b.size))
		}
		return 0, b.fail(fmt.Errorf("blob %s: %w", b.digest, redact(err)))
	}
	return n, nil
}

func (b *blobReader) fail(err error) error {
	b.err = err
	b.timer.Stop()
	return err
}

func (b *blobReader) Close() error {
	b.timer.Stop()
	err := b.body.Close()
	b.cancel(nil)
	return err
}
