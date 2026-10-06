package compiled

import (
	"context"
	"errors"
)

func (s *Session) abort(reason error) {
	s.mu.Lock()
	if s.closed {
		done := s.abortDone
		s.mu.Unlock()
		<-done
		return
	}
	s.closed, s.reason = true, reason
	transport := s.transport
	close(s.done)
	s.mu.Unlock()
	s.cancel()
	if transport != nil {
		if err := transport.Close(); err != nil {
			s.mu.Lock()
			s.closeErr = errors.Join(s.closeErr, err)
			s.mu.Unlock()
		}
	}

	close(s.abortDone)
}

func (s *Session) closeNative() {
	if s.instance != nil {
		err := s.instance.Close(context.WithoutCancel(s.lifetime))
		s.instance = nil
		s.mu.Lock()
		s.closeErr = errors.Join(s.closeErr, err)
		s.mu.Unlock()
	}
	if s.module != nil {
		err := s.module.Close(context.WithoutCancel(s.lifetime))
		s.module = nil
		s.mu.Lock()
		s.closeErr = errors.Join(s.closeErr, err)
		s.mu.Unlock()
	}
	s.releaseOnce.Do(func() {
		if s.config.OnClosed != nil {
			s.config.OnClosed()
		}
	})
}

func (s *Session) closeWithReason(reason error) error {
	s.abort(reason)
	s.gate <- struct{}{}
	s.closeNative()
	<-s.gate
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeErr
}

// Close interrupts an active call and waits for its native resources to close.
func (s *Session) Close() error {
	if s == nil || s.gate == nil {
		return nil
	}
	return s.closeWithReason(ErrClosed)
}

func (s *Session) acquire(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return s.closedError()
	case s.gate <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-s.gate
			return err
		}
		select {
		case <-s.done:
			<-s.gate
			return s.closedError()
		default:
			return nil
		}
	}
}
