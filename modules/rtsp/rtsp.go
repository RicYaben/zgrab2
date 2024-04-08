// This package implements a probe for the Real-Time Streaming Protocol (RTPS)
// The probe supports versions 1.0 and 2.0. v2.0 is not backwards compatible,
// so probes sent to devices running v1.0 may not yield any result.
//
// This protocol is primarily used in streaming media devices, such as IP cameras
// media servers, and such.
// These devices use the port 554 to serve RTPS over TCP or UDP, but TCP is more
// common.
//
// This probe sends a DESCRIBE request, which should list the media streams
// the server controlls. Other implementations have used the OPTIONS paramenter.
// However, this does not tell anything about the device or the media streams it
// allows. In contrast, DESCRIBE requests should return more information without
// invading the device. Worst case scenarion we receive either "non-supported
// method" or "unauthorized" responses.
package rtsp

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"log"
	"net"
	"net/textproto"
	"net/url"
	"strings"

	"github.com/zmap/zgrab2"
)

type Flags struct {
	zgrab2.BaseFlags
	UserAgent string `long:"user-agent" default:"Mozilla/5.0 zgrab/0.x" description:"Set a custom user agent"`
}

func (flags *Flags) Validate(args []string) error { return nil }

func (flags *Flags) Help() string {
	return ""
}

type Module struct{}

func (module *Module) NewFlags() interface{} {
	return new(Flags)
}

func (module *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

func (module *Module) Description() string {
	return `
	Porbe for RTSP media servers.
	
	The probe consists on sending an HTTP DESCRIBE request over TCP to a target.
	`
}

type Results struct {
	Responses []*Response `json:"response,omitempty"`
}

func (res *Results) Add(resp *Response) {
	res.Responses = append(res.Responses, resp)
}

type Client struct {
	UserAgent  string
	Connection net.Conn
	Url        *url.URL
}

func (c *Client) Do(req *Request) (resp *Response, err error) {
	conn := c.Connection

	// Send the request
	reqBytes, err := req.Encode()
	if err != nil {
		return nil, err
	}

	if _, err := conn.Write(reqBytes); err != nil {
		return nil, err
	}

	// TODO: Replace this value with some user-defined buffer max value?
	buf := make([]byte, 256*1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, zgrab2.NewScanError(zgrab2.SCAN_UNKNOWN_ERROR, err)
	}

	respBuf := bufio.NewReader(bytes.NewBuffer(buf[:n]))
	statusLine, err := respBuf.ReadString('\n')
	if err != nil {
		return nil, zgrab2.NewScanError(zgrab2.SCAN_UNKNOWN_ERROR, err)
	}

	if err = validateStatus(statusLine); err != nil {
		return nil, zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, err)
	}

	headers := &textproto.MIMEHeader{}
	for {
		line, err := respBuf.ReadString('\n')
		if err != nil {
			return nil, zgrab2.NewScanError(
				zgrab2.SCAN_APPLICATION_ERROR,
				errors.New("malformed response. Message ended without properly terminating headers"),
			)
		}

		// break the look when we finish the headers
		if line == "\r\n" {
			break
		}

		line = strings.TrimSpace(line)
		headerSplit := strings.SplitN(line, ":", 2)
		if len(headerSplit) != 2 {
			return nil, zgrab2.NewScanError(
				zgrab2.SCAN_APPLICATION_ERROR,
				fmt.Errorf("malformied header: %s", line),
			)
		}

		headers.Add(
			strings.TrimSpace(headerSplit[0]),
			strings.TrimSpace(headerSplit[1]),
		)
	}

	return &Response{
		Headers: *headers,
		Status:  statusLine,
	}, nil
}

type scan struct {
	scanner *Scanner
	target  *zgrab2.ScanTarget
	results Results
	client  *Client
}

func (scan *scan) Grab() *zgrab2.ScanError {
	req := scan.Options()
	resp, err := scan.client.Do(req)

	scan.results.Add(resp)
	if err != nil {
		return zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, err)
	}

	// TODO: Inspect the headers for indicators of specific implementations,
	// map it to some path, and send a DESCRIBE request
	return nil
}

func (scan *scan) Describe() *Request {
	return &Request{
		Method: "DESCRIBE",
		Headers: textproto.MIMEHeader{
			"Accept":     []string{"application/sdp"},
			"CSeq":       []string{"1"},
			"User-Agent": []string{scan.scanner.config.UserAgent},
		},
		Url: scan.client.Url,
	}
}

func (scan *scan) Options() *Request {
	return &Request{
		Method: "OPTIONS",
		Headers: textproto.MIMEHeader{
			"CSeq":       []string{"1"},
			"User-Agent": []string{scan.scanner.config.UserAgent},
		},
		Url: scan.client.Url,
	}
}

type Scanner struct {
	config *Flags
}

func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f

	return nil
}

// InitPerSender initializes the scanner for a given sender.
func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

// GetName returns the Scanner name defined in the Flags.
func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

// GetTrigger returns the Trigger defined in the Flags.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// Protocol returns the protocol identifier of the scan.
func (scanner *Scanner) Protocol() string {
	return "rtsp"
}

// TODO: Divide the duties of the scan and client in a better way.
// This constructor is rather bad.
func (scanner *Scanner) newRTSPScan(target *zgrab2.ScanTarget, conn net.Conn) *scan {
	port := uint16(scanner.config.BaseFlags.Port)
	if target.Port != nil {
		port = uint16(*target.Port)
	}

	host := target.Domain
	if len(host) == 0 {
		host = target.IP.String()
	}

	return &scan{
		scanner: scanner,
		target:  target,
		client: &Client{
			Connection: conn,
			UserAgent:  scanner.config.UserAgent,
			Url: &url.URL{
				Scheme: "rtsp",
				Host:   fmt.Sprintf("%s:%d", host, port),
			},
		},
	}
}

func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	conn, err := target.Open(&scanner.config.BaseFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer conn.Close()

	scan := scanner.newRTSPScan(&target, conn)
	scanErr := scan.Grab()
	if scanErr != nil {
		return scanErr.Unpack(&scan.results)
	}

	return zgrab2.SCAN_SUCCESS, &scan.results, nil
}

func RegisterModule() {
	var module Module
	if _, err := zgrab2.AddCommand("rtsp", "rtsp", module.Description(), 554, &module); err != nil {
		log.Fatal(err)
	}
}
