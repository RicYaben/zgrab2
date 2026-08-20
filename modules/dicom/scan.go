package dicom

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/zmap/zgrab2"
)

type rspCb func(*Response)
type Request func(net.Conn, any, uint16, rspCb) *zgrab2.ScanError

type Response struct {
	Command string            `json:"command"`
	Data    []*PDU            `json:"data,omitempty"`
	Error   *zgrab2.ScanError `json:"error,omitempty"`
}

func newResponse(command string) *Response {
	return &Response{
		Command: command,
		Data:    make([]*PDU, 0),
	}
}

type Responses []*Response

type PreparedRequest struct {
	Req   Request
	Args  any
	MsgID uint16
}

type Requests struct {
	Assoc    PreparedRequest   `json:"association"`
	Commands []PreparedRequest `json:"cmd"`
}

type Probe struct {
	Requests  Requests  `json:"-"`
	Responses Responses `json:"responses"`
}

func (p Probe) title(t string) Probe {
	a := p.Requests.Assoc.Args.(AssociateArgs)
	a.CalledAETitle = t
	p.Requests.Assoc.Args = a
	return p
}

type ScanResult struct {
	Scheme    string         `json:"scheme"`
	TLSLog    *zgrab2.TLSLog `json:"tls,omitempty"`
	Responses Responses      `json:"responses"`
}

type scan struct {
	ctx       context.Context
	dialGroup *zgrab2.DialerGroup

	target  *zgrab2.ScanTarget
	scanner *Scanner
	scheme  string
	result  ScanResult
}

func (s *scan) connect() (net.Conn, *zgrab2.ScanError) {
	addr := net.JoinHostPort(s.target.Host(), strconv.Itoa(int(s.target.Port)))
	conn, err := s.dialGroup.L4Dialer(s.target)(s.ctx, "tcp", addr)
	if err != nil {
		return nil, zgrab2.NewScanError(zgrab2.TryGetScanStatus(err), fmt.Errorf("error opening connection to target %s: %w", s.target.Host(), err))
	}

	if s.scheme == "tls" {
		w := s.dialGroup.TLSWrapper
		if w == nil {
			return nil, zgrab2.NewScanError(zgrab2.SCAN_INVALID_INPUTS, fmt.Errorf("missing TLS wrapper"))
		}
		conn, err = w(s.ctx, s.target, conn)
		if err != nil {
			return nil, zgrab2.DetectScanError(err)
		}
	}

	return conn, nil
}

type dimse struct{}

func (d *dimse) sendAAssociateRQ(conn net.Conn, args AssociateArgs) error {
	assoc := makeAAssociateRQ(1,
		args.CallingAETitle,
		args.CalledAETitle,
		args.ImplementationClassUID,
		args.ImplementationVersionName,
	)

	// assoc.addTransferSyntax(0x30, "1.2.840.10008.1.1") // abstract
	assoc.addTransferSyntax(0x30, "1.2.840.10008.5.1.4.1.2.2.1") // Study root

	// these are retired and added for mainly for compatibility with older versions
	assoc.addTransferSyntax(0x40, "1.2.840.10008.1.2.1").
		addTransferSyntax(0x40, "1.2.840.10008.1.2.2")

	assoc.addTransferSyntax(0x40, "1.2.840.10008.1.2")

	pdu := newPDU(PDUType(1)).withMessage(assoc)

	if _, err := conn.Write(pdu.bytes()); err != nil {
		return fmt.Errorf("failed to send Association request: %w", err)
	}
	return nil
}

type AssociateArgs struct {
	CalledAETitle             string
	CallingAETitle            string
	ImplementationClassUID    string
	ImplementationVersionName string
}

func (d *dimse) associate(conn net.Conn, kwargs any, _ uint16, cb rspCb) *zgrab2.ScanError {
	args := kwargs.(AssociateArgs)
	rsp := newResponse("associate")
	cb(rsp)

	if err := d.sendAAssociateRQ(
		conn,
		args,
	); err != nil {
		return zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, err)
	}

	pdu, err := parsePDU(conn)
	if err != nil {
		err = fmt.Errorf("failed to parse association response: %w", err)
		return zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, err)
	}

	rsp.Data = append(rsp.Data, pdu)
	return nil
}

func (d *dimse) sendRelease(conn net.Conn) error {
	rel := makeReleaseRQ()
	pdu := newPDU(PDUType(5)).withMessage(rel)
	if _, err := conn.Write(pdu.bytes()); err != nil {
		return fmt.Errorf("failed to send Release request: %w", err)
	}
	return nil
}

func (d *dimse) release(conn net.Conn) *zgrab2.ScanError {
	if err := d.sendRelease(conn); err != nil {
		return zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, err)
	}

	if _, err := parsePDU(conn); err != nil {
		return zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, fmt.Errorf("failed to parse Release response: %w", err))
	}
	return nil
}

func (d *dimse) sendCEchoRQ(conn net.Conn, msgID uint16) error {
	echo := makeCEchoRQ(msgID)
	pdu := newPDU(PDUType(4)).withMessage(echo)

	if _, err := conn.Write(pdu.bytes()); err != nil {
		return fmt.Errorf("failed to send Echo request: %w", err)
	}
	return nil
}

func (d *dimse) echo(conn net.Conn, _ any, msgID uint16, cb rspCb) *zgrab2.ScanError {
	rsp := newResponse("echo")
	cb(rsp)

	if err := d.sendCEchoRQ(conn, msgID); err != nil {
		return zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, err)
	}

	pdu, err := parsePDU(conn)
	if err != nil {
		err = fmt.Errorf("failed to parse Echo response: %w", err)
		return zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, err)
	}
	rsp.Data = append(rsp.Data, pdu)
	return nil
}

func (d *dimse) sendCFindRQ(conn net.Conn, msgID uint16, model string, keys []string) error {
	f1, f2 := makeCFindRQ(msgID, model, keys)
	pdu1 := newPDU(PDUType(4)).withMessage(f1)
	pdu2 := newPDU(PDUType(4)).withMessage(f2)

	b := []byte{}
	b = append(b, pdu1.bytes()...)
	b = append(b, pdu2.bytes()...)

	if _, err := conn.Write(b); err != nil {
		return fmt.Errorf("failed to send Find request PDU2: %w", err)
	}
	return nil
}

type CFindArgs struct {
	Model   string
	Keys    []string
	NCancel int
}

var (
	CFindPendingStatus = PDVCommand{GroupTag: 0x0000, ElementTag: 0x0900, Value: []byte{0x00, 0xFF}}
)

func (d *dimse) status(pdu *PDU) *PDVCommand {
	body := pdu.Msg.(*PDV)
	for _, cmd := range body.Commands {
		cmd := cmd.(*PDVCommand)
		if cmd.GroupTag == 0x0000 && cmd.ElementTag == 0x0900 {
			return cmd
		}
	}
	return nil
}

func (d *dimse) find(conn net.Conn, kwargs any, msgID uint16, cb rspCb) *zgrab2.ScanError {
	args := kwargs.(CFindArgs)
	rsp := newResponse("find")
	cb(rsp)

	if err := d.sendCFindRQ(conn, msgID, args.Model, args.Keys); err != nil {
		return zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, err)
	}

	for i := 0; args.NCancel == 0 || i < args.NCancel; i++ {
		pdu, err := parsePDU(conn)
		if err != nil {
			if err == io.EOF {
				break
			}

			err = fmt.Errorf("failed to parse Find response: %w", err)
			return zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, err)
		}

		if d.status(pdu) != &CFindPendingStatus {
			break
		}

		rsp.Data = append(rsp.Data, pdu)
	}
	return nil
}

func (d *dimse) makeRequest(req string, args any, msgID uint16) PreparedRequest {
	var cb Request
	switch req {
	case "echo":
		cb = d.echo
	case "find":
		cb = d.find
	default:
		panic(fmt.Errorf("unknown command: %s", req))
	}

	return PreparedRequest{Req: cb, Args: args, MsgID: msgID}
}

func (s *scan) Grab(probe Probe) *zgrab2.ScanError {
	conn, err := s.connect()
	if err != nil {
		return err
	}
	defer func() {
		// Check if we have a TLS conn and grab the log
		if tlsConn, ok := conn.(*zgrab2.TLSConnection); ok {
			s.result.TLSLog = tlsConn.GetLog()
		}
		// cleanup conn
		zgrab2.CloseConnAndHandleError(conn)
	}()

	cb := func(rsp *Response) {
		s.result.Responses = append(s.result.Responses, rsp)
	}

	rqs := []PreparedRequest{probe.Requests.Assoc}
	rqs = append(rqs, probe.Requests.Commands...)
	for _, rq := range rqs {
		if err := rq.Req(conn, rq.Args, rq.MsgID, cb); err != nil {
			return err
		}
	}

	d := dimse{}
	d.release(conn)
	return nil
}

type ScanBuilder struct {
	scanner *Scanner
}

func NewScanBuilder(scn *Scanner) *ScanBuilder {
	return &ScanBuilder{scn}
}

func (b *ScanBuilder) Build(ctx context.Context, dialGroup *zgrab2.DialerGroup, t *zgrab2.ScanTarget, scheme string) *scan {
	return &scan{
		ctx:       ctx,
		dialGroup: dialGroup,
		scanner:   b.scanner,
		target:    t,
		scheme:    scheme,
		result: ScanResult{
			Scheme: scheme,
		},
	}
}
