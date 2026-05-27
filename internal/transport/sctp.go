package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"

	"github.com/free5gc/ngap"
	"github.com/ishidawataru/sctp"
)

const sctpReadBufferSize = 65535

type SCTPTransport struct {
	conn     *sctp.SCTPConn
	recvChan chan []byte
	closed   atomic.Bool
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
		conn:     conn,
		recvChan: make(chan []byte, 64),
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
		t.recvChan <- cp
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

func (t *SCTPTransport) Receive(ctx context.Context) ([]byte, error) {
	select {
	case data := <-t.recvChan:
		return data, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (t *SCTPTransport) Close() error {
	if t.closed.Swap(true) {
		return nil
	}
	return t.conn.Close()
}
