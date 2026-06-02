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

	"github.com/free5gc/ngap"
	"github.com/ishidawataru/sctp"

	ngapCodec "github.com/ellanetworks/3gpp-server/internal/ngap"
)

const sctpReadBufferSize = 65535

type SCTPTransport struct {
	conn   *sctp.SCTPConn
	closed atomic.Bool

	mu     sync.Mutex
	cond   *sync.Cond // broadcast when a frame is buffered or a waiter must re-check
	frames map[string][]*ngapCodec.NGAPResponse
}

func Dial(localAddr, remoteAddr string) (*SCTPTransport, error) {
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

	t := &SCTPTransport{
		conn:   conn,
		frames: make(map[string][]*ngapCodec.NGAPResponse),
	}
	t.cond = sync.NewCond(&t.mu)

	go t.runReceiver()

	return t, nil
}

func (t *SCTPTransport) runReceiver() {
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

		resp, err := ngapCodec.Decode(cp)
		if err != nil {
			continue
		}

		t.mu.Lock()
		t.frames[resp.MessageType] = append(t.frames[resp.MessageType], resp)
		t.cond.Broadcast()
		t.mu.Unlock()
	}
}

func (t *SCTPTransport) Send(data []byte, nonUE bool) error {
	if t.closed.Load() {
		return fmt.Errorf("transport is closed")
	}

	var streamID uint16
	if nonUE {
		streamID = 0
	} else {
		streamID = 1
	}

	info := sctp.SndRcvInfo{
		Stream: streamID,
		PPID:   ngap.PPID,
	}

	_, err := t.conn.SCTPWrite(data, &info)
	if err != nil {
		return fmt.Errorf("sctp write: %w", err)
	}

	return nil
}

// WaitForMessage returns the next buffered downlink of one of messageTypes,
// blocking until one arrives or ctx expires.
func (t *SCTPTransport) WaitForMessage(ctx context.Context, messageTypes ...string) (*ngapCodec.NGAPResponse, error) {
	return t.WaitForMessageMatching(ctx, nil, messageTypes...)
}

// WaitForMessageMatching returns the next buffered downlink of one of
// messageTypes for which match returns true (a nil match accepts any). It lets
// several concurrent waiters on one association each claim the frame for their
// own UE without consuming another UE's downlink.
func (t *SCTPTransport) WaitForMessageMatching(ctx context.Context, match func(*ngapCodec.NGAPResponse) bool, messageTypes ...string) (*ngapCodec.NGAPResponse, error) {
	// Wake blocked waiters when ctx expires so they observe the deadline; the
	// receiver only broadcasts on new frames.
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
			return nil, fmt.Errorf("timeout waiting for %v", messageTypes)
		}

		t.cond.Wait()
	}
}

func (t *SCTPTransport) Close() error {
	if t.closed.Swap(true) {
		return nil
	}

	return t.conn.Close()
}
