// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

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

type Endpoint struct {
	conn   *net.UDPConn
	closed atomic.Bool

	mu      sync.Mutex
	cond    *sync.Cond
	gpdus   map[uint32][][]byte
	control map[uint8][]*Message
}

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

func (e *Endpoint) SendUplink(remoteIP string, ulTeid uint32, qfi uint8, innerIP []byte) error {
	return e.sendTo(remoteIP, EncodeGPDUWithQFI(ulTeid, qfi, innerIP))
}

// S1-U (4G) uplink carries no PDU Session Container, hence no QFI.
func (e *Endpoint) SendUplinkPlain(remoteIP string, ulTeid uint32, innerIP []byte) error {
	return e.sendTo(remoteIP, EncodeGPDU(ulTeid, innerIP))
}

func (e *Endpoint) SendEchoRequest(remoteIP string, seq uint16) error {
	return e.sendTo(remoteIP, EncodeEchoRequest(seq))
}

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

func (e *Endpoint) LocalIP() string {
	if a, ok := netip.AddrFromSlice(e.conn.LocalAddr().(*net.UDPAddr).IP); ok {
		return a.Unmap().String()
	}

	return ""
}

func (e *Endpoint) Close() error {
	if e.closed.Swap(true) {
		return nil
	}

	return e.conn.Close()
}
