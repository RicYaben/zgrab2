package dicom

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/zmap/zgrab2"
)

type Request func(net.Conn, *Response, any) *zgrab2.ScanError

type Response struct {
	Command string `json:"command"`
	Data    []*PDU `json:"data,omitempty"`
	Error   error  `json:"error,omitempty"`
}

type PreparedRequest struct {
	Req    Request
	Kwargs any
}

type ScanResult struct {
	Scheme    string         `json:"scheme"`
	TLSLog    *zgrab2.TLSLog `json:"tls,omitempty"`
	Responses []*Response    `json:"responses,omitempty"`
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
		return nil, zgrab2.NewScanError(zgrab2.TryGetScanStatus(err), fmt.Errorf("error opening connection to target %v: %w", addr, err))
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

func (d *dimse) sendAAssociateRQ(conn net.Conn, calledAE, callingAE, implUID, implVName string) error {
	assoc := makeAAssociateRQ(1, callingAE, calledAE, implUID, implVName)
	assoc.addTransferSyntax(0x30, "1.2.840.10008.1.1") // abstract
	assoc.addTransferSyntax(0x40, "1.2.840.10008.1.2") // default for DICOM

	pdu := newPDU(PDUType(1)).withMessage(assoc)

	if _, err := conn.Write(pdu.bytes()); err != nil {
		return fmt.Errorf("failed to send Association request: %v", err)
	}
	return nil
}

type AssociateArgs struct {
	CalledAETitle             string
	CallingAETitle            string
	ImplementationClassUID    string
	ImplementationVersionName string
}

func (d *dimse) associate(conn net.Conn, rsp *Response, kwargs any) *zgrab2.ScanError {
	args := kwargs.(*AssociateArgs)
	rsp.Command = "associate"

	if err := d.sendAAssociateRQ(
		conn,
		args.CalledAETitle,
		args.CallingAETitle,
		args.ImplementationClassUID,
		args.ImplementationVersionName,
	); err != nil {
		rsp.Error = err
		return zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, err)
	}

	pdu, err := parsePDU(conn)
	if err != nil {
		rsp.Error = fmt.Errorf("failed to parse association response: %v", err)
		return zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, rsp.Error)
	}

	rsp.Data = append(rsp.Data, pdu)
	return nil
}

func (d *dimse) sendCEchoRQ(conn net.Conn) error {
	echo := makeCEchoRQ(1)
	pdu := newPDU(PDUType(4)).withMessage(echo)

	if _, err := conn.Write(pdu.bytes()); err != nil {
		return fmt.Errorf("failed to send Echo request: %v", err)
	}
	return nil
}

func (d *dimse) echo(conn net.Conn, rsp *Response, _ any) *zgrab2.ScanError {
	rsp.Command = "echo"

	if err := d.sendCEchoRQ(conn); err != nil {
		rsp.Error = err
		return zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, err)
	}

	pdu, err := parsePDU(conn)
	if err != nil {
		rsp.Error = fmt.Errorf("failed to parse Echo response: %v", err)
		return zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, rsp.Error)
	}

	rsp.Data = append(rsp.Data, pdu)
	return nil
}

func (d *dimse) sendCFindRQ(conn net.Conn, model string, keys []string) error {
	f1, f2 := makeCFindRQ(1, model, keys)
	pdu1 := newPDU(PDUType(PDUType(4))).withMessage(f1)
	pdu2 := newPDU(PDUType(PDUType(4))).withMessage(f2)

	b := []byte{}
	b = append(b, pdu1.bytes()...)
	b = append(b, pdu2.bytes()...)

	if _, err := conn.Write(b); err != nil {
		return fmt.Errorf("failed to send Find request PDU2: %v", err)
	}
	return nil
}

type CFindArgs struct {
	Model   string
	Keys    []string
	NCancel int
}

func (d *dimse) find(conn net.Conn, rsp *Response, kwargs any) *zgrab2.ScanError {
	args := kwargs.(*CFindArgs)
	rsp.Command = "find"

	if err := d.sendCFindRQ(conn, args.Model, args.Keys); err != nil {
		return zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, err)
	}

	for i := 0; i < args.NCancel; i++ {
		pdu, err := parsePDU(conn)
		if err != nil {
			if err == io.EOF {
				break
			}

			rsp.Error = fmt.Errorf("failed to parse Find response: %v", err)
			return zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, rsp.Error)
		}
		rsp.Data = append(rsp.Data, pdu)
	}

	return nil
}

func (d *dimse) makeRequest(req string, args any) PreparedRequest {
	var cb Request
	switch req {
	case "associate":
		cb = d.associate
	case "echo":
		cb = d.echo
	case "find":
		cb = d.find
	default:
		panic(fmt.Errorf("unknown request: %s", req))
	}

	return PreparedRequest{Req: cb, Kwargs: args}
}

func (s *scan) Grab(requests []PreparedRequest) *zgrab2.ScanError {
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

	for _, r := range requests {
		rsp := &Response{
			Data: make([]*PDU, 0),
		}

		s.result.Responses = append(s.result.Responses, rsp)
		if err := r.Req(conn, rsp, r.Kwargs); err != nil {
			return err
		}
	}
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
