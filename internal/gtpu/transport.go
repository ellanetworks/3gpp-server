package gtpu

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
)

const readBufferSize = 65535

// Endpoint is an N3 GTP-U socket. It demultiplexes received G-PDUs by TEID and
// buffers path-management messages by type, mirroring the SCTP transport's
// buffer-and-wait pattern so concurrent waiters can each claim their packet.
type Endpoint struct {
	conn   *net.UDPConn
	closed atomic.Bool

	mu      sync.Mutex
	cond    *sync.Cond
	gpdus   map[uint32][][]byte // TEID -> received T-PDUs (inner IP packets)
	control map[uint8][]*Message
}

// Listen binds a GTP-U endpoint on localIP:2152.
func Listen(localIP string) (*Endpoint, error) {
	addr := &net.UDPAddr{IP: net.ParseIP(localIP), Port: Port}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen gtp-u on %s: %w", addr, err)
	}

	e := &Endpoint{
		conn:    conn,
		gpdus:   make(map[uint32][][]byte),
		control: make(map[uint8][]*Message),
	}
	e.cond = sync.NewCond(&e.mu)

	go e.runReceiver()

	return e, nil
}

func (e *Endpoint) runReceiver() {
	buf := make([]byte, readBufferSize)

	for {
		n, _, err := e.conn.ReadFromUDP(buf)
		if err != nil {
			if e.closed.Load() {
				return
			}

			return
		}

		if n == 0 {
			continue
		}

		cp := make([]byte, n)
		copy(cp, buf[:n])

		msg, err := Decode(cp)
		if err != nil {
			continue
		}

		e.mu.Lock()

		if msg.Type == MsgGPDU {
			e.gpdus[msg.TEID] = append(e.gpdus[msg.TEID], msg.Payload)
		} else {
			e.control[msg.Type] = append(e.control[msg.Type], msg)
		}

		e.cond.Broadcast()
		e.mu.Unlock()
	}
}

func (e *Endpoint) sendTo(remoteIP string, data []byte) error {
	if e.closed.Load() {
		return fmt.Errorf("gtp-u endpoint is closed")
	}

	addr := &net.UDPAddr{IP: net.ParseIP(remoteIP), Port: Port}
	if _, err := e.conn.WriteToUDP(data, addr); err != nil {
		return fmt.Errorf("gtp-u write to %s: %w", remoteIP, err)
	}

	return nil
}

// SendUplink encapsulates an inner IP packet in a G-PDU (with the uplink PDU
// Session Container / QFI) and sends it to the UPF (remoteIP) on the UPF's
// uplink TEID.
func (e *Endpoint) SendUplink(remoteIP string, ulTeid uint32, qfi uint8, innerIP []byte) error {
	return e.sendTo(remoteIP, EncodeGPDUWithQFI(ulTeid, qfi, innerIP))
}

// SendEchoRequest sends a GTP-U Echo Request to remoteIP.
func (e *Endpoint) SendEchoRequest(remoteIP string, seq uint16) error {
	return e.sendTo(remoteIP, EncodeEchoRequest(seq))
}

// WaitForDownlink returns the next downlink T-PDU received on the given DL TEID,
// blocking until one arrives or ctx expires.
func (e *Endpoint) WaitForDownlink(ctx context.Context, dlTeid uint32) ([]byte, error) {
	stop := make(chan struct{})
	defer close(stop)

	go func() {
		select {
		case <-ctx.Done():
			e.mu.Lock()
			e.cond.Broadcast()
			e.mu.Unlock()
		case <-stop:
		}
	}()

	e.mu.Lock()
	defer e.mu.Unlock()

	for {
		if pkts := e.gpdus[dlTeid]; len(pkts) > 0 {
			pkt := pkts[0]
			e.gpdus[dlTeid] = slices.Delete(pkts, 0, 1)

			if len(e.gpdus[dlTeid]) == 0 {
				delete(e.gpdus, dlTeid)
			}

			return pkt, nil
		}

		if ctx.Err() != nil {
			return nil, fmt.Errorf("timeout waiting for downlink on TEID %d", dlTeid)
		}

		e.cond.Wait()
	}
}

// WaitForControl returns the next buffered path-management message of the given
// type, blocking until one arrives or ctx expires.
func (e *Endpoint) WaitForControl(ctx context.Context, msgType uint8) (*Message, error) {
	stop := make(chan struct{})
	defer close(stop)

	go func() {
		select {
		case <-ctx.Done():
			e.mu.Lock()
			e.cond.Broadcast()
			e.mu.Unlock()
		case <-stop:
		}
	}()

	e.mu.Lock()
	defer e.mu.Unlock()

	for {
		if msgs := e.control[msgType]; len(msgs) > 0 {
			msg := msgs[0]
			e.control[msgType] = slices.Delete(msgs, 0, 1)

			return msg, nil
		}

		if ctx.Err() != nil {
			return nil, fmt.Errorf("timeout waiting for GTP-U message type %d", msgType)
		}

		e.cond.Wait()
	}
}

// LocalIP returns the IP the endpoint is bound to (the gNB's N3 address).
func (e *Endpoint) LocalIP() string {
	if a, ok := netip.AddrFromSlice(e.conn.LocalAddr().(*net.UDPAddr).IP); ok {
		return a.Unmap().String()
	}

	return ""
}

// Close shuts the endpoint down.
func (e *Endpoint) Close() error {
	if e.closed.Swap(true) {
		return nil
	}

	return e.conn.Close()
}
