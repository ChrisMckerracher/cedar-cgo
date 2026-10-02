// Package capbuf provides a byte buffer that keeps only the start of what
// is written to it.
package capbuf

import (
	"bytes"
	"sync"
)

// Buffer keeps the first Limit bytes written to it and drops the rest. It
// is safe for concurrent use.
type Buffer struct {
	Limit int
	mu    sync.Mutex
	buf   []byte
}

// Write implements io.Writer. It never fails.
func (b *Buffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if room := b.Limit - len(b.buf); room > 0 {
		b.buf = append(b.buf, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

// String returns the kept bytes without surrounding white space.
func (b *Buffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(bytes.TrimSpace(b.buf))
}
