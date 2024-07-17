package coap

import (
	"bytes"
	"net"
	"slices"
	"time"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/coap/message"
)

type Result struct {
	path     string
	messages []*message.Message
}

type Probe struct {
	header  []byte
	timeout time.Duration
	results []*Result
	decoder message.Decoder
	conn    net.Conn
}

func (p *Probe) Do(path string) *zgrab2.ScanError {
	u := p.getUriPath(path)
	pkt := slices.Concat(p.header, u)
	msgs, err := p.handle(pkt)
	if err != nil {
		return err
	}

	res := &Result{
		path:     path,
		messages: msgs,
	}
	p.results = append(p.results, res)
	return nil
}

func (p *Probe) handle(packet []byte) ([]*message.Message, *zgrab2.ScanError) {
	msgs := []*message.Message{}
	for b := 0; ; b++ {
		msg, err := p.handleBlock(packet, b)
		if err != nil {
			return nil, err
		}
		msgs = append(msgs, msg)
		block := msg.GetBlock()
		if block == nil || !block.More {
			return msgs, nil
		}
	}
}

func (p *Probe) handleBlock(packet []byte, block int) (*message.Message, *zgrab2.ScanError) {
	if b := p.getBlock(block); len(b) > 0 {
		packet = append(packet, b...)
	}

	if err := p.conn.SetReadDeadline(time.Now().Add(p.timeout)); err != nil {
		zgrab2.NewScanError(zgrab2.SCAN_UNKNOWN_ERROR, err)
	}

	if _, err := p.conn.Write(packet); err != nil {
		return nil, zgrab2.DetectScanError(err)
	}

	buf := make([]byte, 1024)
	n, err := p.conn.Read(buf)
	if err != nil {
		return nil, zgrab2.DetectScanError(err)
	}

	msg := message.NewMessage()
	if err := p.decoder.Decode(buf[:n], msg); err != nil {
		return nil, zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, err)
	}
	return msg, nil
}

func (p *Probe) getUriPath(path string) []byte {
	const uriOption int = 11

	if path == "" {
		panic("empty path not allowed")
	}

	if path == "/" {
		// Option delta and length for an empty path segment
		option := (uriOption << 4)
		return []byte{byte(option)}
	}

	// Transform to bytes and separate by the URI separator
	var buf bytes.Buffer
	paths := bytes.Split([]byte(path), []byte("/"))

	// Include option delta number, length and value
	option := (uriOption << 4) + len(paths[0])
	buf.WriteByte(byte(option))
	buf.Write(paths[0])

	// Extend the option with length and value
	for _, p := range paths[1:] {
		buf.WriteByte(byte(len(p)))
		buf.Write(p)
	}
	return buf.Bytes()
}

func (p *Probe) getBlock(n int) []byte {
	if n < 1 {
		return []byte{}
	}

	var buf bytes.Buffer
	b := (12 << 4) + 1 // 193
	c := (n << 4) + 3
	buf.WriteByte(byte(b))
	buf.WriteByte(byte(c))
	return buf.Bytes()
}

type ProbeBuilder struct {
	decoder message.Decoder
	header  []byte
	timeout time.Duration
}

func (b *ProbeBuilder) Build(conn net.Conn) *Probe {
	p := &Probe{
		header:  b.header,
		decoder: b.decoder,
		timeout: b.timeout,
		conn:    conn,
		results: []*Result{},
	}
	return p
}

func (b *ProbeBuilder) setHeader() *ProbeBuilder {
	b.header = []byte{
		0x40,       // CoAP version and type (version: 1, type: Confirmable)
		0x01,       // CoAP code (GET)
		0x12, 0x34, // Message ID (0x0001)
	}
	return b
}

func (b *ProbeBuilder) setDecoder() *ProbeBuilder {
	b.decoder = message.NewDecoder()
	return b
}

func (b *ProbeBuilder) setTimeout(t time.Duration) *ProbeBuilder {
	b.timeout = t
	return b
}

func newProbeBuilder(timeout time.Duration) *ProbeBuilder {
	b := new(ProbeBuilder)
	b.setHeader()
	b.setDecoder()
	b.setTimeout(timeout)
	return b
}
