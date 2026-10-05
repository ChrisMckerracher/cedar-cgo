// Package capbuf bounds diagnostic capture so diagnostic output cannot exhaust host memory.
package capbuf

import (
	"bytes"
	"sync"
)

// Buffer keeps the first Limit bytes and is safe for concurrent use.
type Buffer struct {
	Limit int
	mu    sync.Mutex
	buf   []byte
}

// Write reports all bytes consumed even when truncating, so producers keep running.
func (b *Buffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if room := b.Limit - len(b.buf); room > 0 {
		b.buf = append(b.buf, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

func (b *Buffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(bytes.TrimSpace(b.buf))
}
