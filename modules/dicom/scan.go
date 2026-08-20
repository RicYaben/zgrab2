package dicom

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/zmap/zgrab2"
)

type Request func(net.Conn, any) Response

type Response struct {
	Command string            `json:"command"`
	Data    []*PDU            `json:"data,omitempty"`
	Error   *zgrab2.ScanError `json:"error,omitempty"`
}

type PreparedRequest struct {
	Req  Request
	Args any
}

type Requests struct {
	Assoc   PreparedRequest `json:"association"`
	Command PreparedRequest `json:"cmd"`
}

type Probe struct {
	Requests  Requests
	Responses []Response
}

type Probes []Probe

func (p Probes) title(t string) {
	for _, pr := range p {
		a := pr.Requests.Assoc.Args.(AssociateArgs)
		a.CalledAETitle = t
	}
}

func (p Probes) reset() {
	for _, pr := range p {
		pr.Responses = make([]Response, 0)
	}
}

type ScanResult struct {
	Scheme string         `json:"scheme"`
	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`
	Result Probes         `json:"result"`
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

func (d *dimse) sendAAssociateRQ(conn net.Conn, args AssociateArgs) error {
	assoc := makeAAssociateRQ(1,
		args.CallingAETitle,
		args.CalledAETitle,
		args.ImplementationClassUID,
		args.ImplementationVersionName,
	)

	// set the intent of the request
	switch args.Command {
	case "echo":
		assoc.addTransferSyntax(0x30, "1.2.840.10008.1.1") // abstract
	case "find":
		assoc.addTransferSyntax(0x30, "1.2.840.10008.5.1.4.1.2.2.1")
	default:
		panic(fmt.Errorf("unsuported command: %s", args.Command))
	}

	// these are retired and added for mainly for compatibility with older versions
	assoc.addTransferSyntax(0x40, "1.2.840.10008.1.2.1").
		addTransferSyntax(0x40, "1.2.840.10008.1.2.2")

	assoc.addTransferSyntax(0x40, "1.2.840.10008.1.2")

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
	Command                   string
}

func (d *dimse) associate(conn net.Conn, kwargs any) Response {
	args := kwargs.(AssociateArgs)
	rsp := Response{
		Command: "associate",
		Data:    make([]*PDU, 0),
	}

	if err := d.sendAAssociateRQ(
		conn,
		args,
	); err != nil {
		rsp.Error = zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, err)
		return rsp
	}

	pdu, err := parsePDU(conn)
	if err != nil {
		err = fmt.Errorf("failed to parse association response: %v", err)
		zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, err)
		return rsp
	}

	rsp.Data = append(rsp.Data, pdu)
	return rsp
}

func (d *dimse) sendCEchoRQ(conn net.Conn) error {
	echo := makeCEchoRQ(1)
	pdu := newPDU(PDUType(4)).withMessage(echo)

	if _, err := conn.Write(pdu.bytes()); err != nil {
		return fmt.Errorf("failed to send Echo request: %v", err)
	}
	return nil
}

func (d *dimse) echo(conn net.Conn, _ any) Response {
	rsp := Response{
		Command: "echo",
		Data:    make([]*PDU, 0),
	}

	if err := d.sendCEchoRQ(conn); err != nil {
		rsp.Error = zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, err)
		return rsp
	}

	pdu, err := parsePDU(conn)
	if err != nil {
		rsp.Error = zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, fmt.Errorf("failed to parse Echo response: %v", err))
		return rsp
	}

	rsp.Data = append(rsp.Data, pdu)
	return rsp
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

func (d *dimse) find(conn net.Conn, kwargs any) Response {
	args := kwargs.(CFindArgs)

	rsp := Response{
		Command: "find",
		Data:    make([]*PDU, 0),
	}

	if err := d.sendCFindRQ(conn, args.Model, args.Keys); err != nil {
		rsp.Error = zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, err)
		return rsp
	}

	for i := 0; i < args.NCancel; i++ {
		pdu, err := parsePDU(conn)
		if err != nil {
			if err == io.EOF {
				break
			}

			err = fmt.Errorf("failed to parse Find response: %v", err)
			rsp.Error = zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, err)
			return rsp
		}
		rsp.Data = append(rsp.Data, pdu)
	}

	return rsp
}

func (d *dimse) makeRequest(req string, args any) PreparedRequest {
	var cb Request
	switch req {
	case "echo":
		cb = d.echo
	case "find":
		cb = d.find
	default:
		panic(fmt.Errorf("unknown command: %s", req))
	}

	return PreparedRequest{Req: cb, Args: args}
}

func (s *scan) Grab(probes Probes) *zgrab2.ScanError {
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

	for _, pr := range probes {
		for _, rq := range []PreparedRequest{pr.Requests.Assoc, pr.Requests.Command} {
			rsp := rq.Req(conn, rq.Args)
			pr.Responses = append(pr.Responses, rsp)
			if err := rsp.Error; err != nil {
				return err
			}
		}
	}
	s.result.Result = probes

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
