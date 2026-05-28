package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
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
	frames map[string][]*ngapCodec.NGAPResponse
	notify chan struct{}
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
		notify: make(chan struct{}, 1),
	}

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
		t.mu.Unlock()

		select {
		case t.notify <- struct{}{}:
		default:
		}
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

func (t *SCTPTransport) WaitForMessage(ctx context.Context, messageTypes ...string) (*ngapCodec.NGAPResponse, error) {
	for {
		t.mu.Lock()

		for _, msgType := range messageTypes {
			if frames, ok := t.frames[msgType]; ok && len(frames) > 0 {
				resp := frames[0]
				if len(frames) == 1 {
					delete(t.frames, msgType)
				} else {
					t.frames[msgType] = frames[1:]
				}

				t.mu.Unlock()

				return resp, nil
			}
		}

		t.mu.Unlock()

		select {
		case <-t.notify:
		case <-ctx.Done():
			return nil, fmt.Errorf("timeout waiting for %v", messageTypes)
		}
	}
}

func (t *SCTPTransport) Close() error {
	if t.closed.Swap(true) {
		return nil
	}

	return t.conn.Close()
}
