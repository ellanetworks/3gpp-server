// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/ishidawataru/sctp"
)

const sctpReadBufferSize = 65535

var (
	ErrSend    = errors.New("sctp send")
	ErrTimeout = errors.New("timeout waiting for message")
)

type framed[T any] struct {
	conn   *sctp.SCTPConn
	ppid   uint32
	decode func([]byte) (*T, error)
	key    func(*T) string

	closed atomic.Bool

	mu     sync.Mutex
	cond   *sync.Cond
	frames map[string][]*T
}

func dialFramed[T any](localAddr, remoteAddr string, ppid uint32, decode func([]byte) (*T, error), key func(*T) string) (*framed[T], error) {
	local := &sctp.SCTPAddr{
		IPAddrs: []net.IPAddr{
			{IP: net.ParseIP(localAddr)},
		},
	}

	remote, err := sctp.ResolveSCTPAddr("sctp", remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", remoteAddr, err)
	}

	conn, err := sctp.DialSCTPExt(
		"sctp", local, remote,
		sctp.InitMsg{NumOstreams: 2, MaxInstreams: 2},
	)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", remoteAddr, err)
	}

	if err := conn.SubscribeEvents(sctp.SCTP_EVENT_DATA_IO); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("subscribe SCTP events: %w", err)
	}

	t := &framed[T]{
		conn:   conn,
		ppid:   ppid,
		decode: decode,
		key:    key,
		frames: make(map[string][]*T),
	}
	t.cond = sync.NewCond(&t.mu)

	go t.runReceiver()

	return t, nil
}

func (t *framed[T]) runReceiver() {
	buf := make([]byte, sctpReadBufferSize)

	for {
		n, _, err := t.conn.SCTPRead(buf)
		if err != nil {
			if t.closed.Load() {
				return
			}

			if errors.Is(err, io.EOF) {
				return
			}

			return
		}

		if n == 0 {
			continue
		}

		cp := make([]byte, n)
		copy(cp, buf[:n])

		resp, err := t.decode(cp)
		if err != nil {
			continue
		}

		t.mu.Lock()
		k := t.key(resp)
		t.frames[k] = append(t.frames[k], resp)
		t.cond.Broadcast()
		t.mu.Unlock()
	}
}

func (t *framed[T]) Send(data []byte, nonUE bool) error {
	if t.closed.Load() {
		return fmt.Errorf("%w: transport is closed", ErrSend)
	}

	var streamID uint16
	if nonUE {
		streamID = 0
	} else {
		streamID = 1
	}

	info := sctp.SndRcvInfo{
		Stream: streamID,
		PPID:   t.ppid,
	}

	_, err := t.conn.SCTPWrite(data, &info)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSend, err)
	}

	return nil
}

func (t *framed[T]) WaitForMessage(ctx context.Context, messageTypes ...string) (*T, error) {
	return t.WaitForMessageMatching(ctx, nil, messageTypes...)
}

// A nil match accepts any frame.
func (t *framed[T]) WaitForMessageMatching(ctx context.Context, match func(*T) bool, messageTypes ...string) (*T, error) {
	// The receiver broadcasts only on new frames, so ctx expiry must wake waiters itself.
	stop := make(chan struct{})
	defer close(stop)

	go func() {
		select {
		case <-ctx.Done():
			t.mu.Lock()
			t.cond.Broadcast()
			t.mu.Unlock()
		case <-stop:
		}
	}()

	t.mu.Lock()
	defer t.mu.Unlock()

	for {
		for _, msgType := range messageTypes {
			frames := t.frames[msgType]
			for i, resp := range frames {
				if match != nil && !match(resp) {
					continue
				}

				t.frames[msgType] = slices.Delete(frames, i, i+1)
				if len(t.frames[msgType]) == 0 {
					delete(t.frames, msgType)
				}

				return resp, nil
			}
		}

		if ctx.Err() != nil {
			return nil, fmt.Errorf("%w: %v", ErrTimeout, messageTypes)
		}

		t.cond.Wait()
	}
}

func (t *framed[T]) Close() error {
	if t.closed.Swap(true) {
		return nil
	}

	return t.conn.Close()
}
