package amqp

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net"
	"net/url"

	"github.com/zmap/zgrab2"
)

type Flags struct {
	zgrab2.BaseFlags

	Method  string `long:"method" default:"M-SEARCH" description:"Request method. Either M-SEARCH or NOTIFY"`
	Product string `long:"product" default:"zgrab/0.x" description:"Set a custom value as the product scanning"`
}

// Module implements the zgrab2.Module interface.
type Module struct {
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
}

type Results struct {
	Response *Response `json:"response,omitempty"`
}

type Request struct {
	Length    int               // Length of the packet
	Doff      int               // DOFF - data offset
	SASL      interface{}       // Type of the content, always SASL
	Channel   int               // Channel to use, ignored otherwise
	Method    string            // Method to authenticate
	Arguments map[string]string // Additional arguments included in the packet. Ignored if not known
}

type Client struct {
	Connection net.Conn
	Url        *url.URL
	Properties map[string]string
	Auth       struct {
		Username    string
		Password    string
		Certificate string
	}
}

func (client *Client) Do(req *Request) (*Response, error) {
	conn := client.Connection

	// Send the request
	reqBytes, err := req.Encode()
	if err != nil {
		return nil, err
	}

	if _, err := conn.Write(reqBytes); err != nil {
		return nil, err
	}

	buf := make([]byte, 256*1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, zgrab2.NewScanError(zgrab2.SCAN_UNKNOWN_ERROR, err)
	}

	respBuf := bufio.NewReader(bytes.NewBuffer(buf[:n]))
	// Parse the response here and return the response... This should follow the
	// schema of the protocol, as first opening the connection, checking for
	// security policies, authenticating, and joining the broker to retrieve some
	// info.
	return nil, nil
}

type scan struct {
	scanner *Scanner
	target  *zgrab2.ScanTarget
	results Results
	client  *Client
}

// RegisterModule registers the zgrab2 module.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("amqp", "amqp", module.Description(), 5672, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a default Flags object.
func (module *Module) NewFlags() interface{} {
	return new(Flags)
}

// NewScanner returns a new Scanner instance.
func (module *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns text uses in the help for this module.
func (module *Module) Description() string {
	return `
	This is an AMQP standard request that test whether the server accepts
	unauthenticated connections and encryption. The body of the AMQP
	banner contains sever identifiers such as product version, name,
	and platform in use.

	The probe covers AMQP 0.9.1, which is completely different from
	1.0. Since AMQP requires authentication by default, we will use
	a self-signed certificate or empty credentials.
	`
}

// Validate checks that the flags are valid.
// On success, returns nil.
// On failure, returns an error instance describing the error.
func (flags *Flags) Validate(args []string) error {
	return nil
}

// Help returns the module's help string.
func (flags *Flags) Help() string {
	return ""
}

// Init initializes the Scanner.
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
	return "amqp"
}

func (scanner *Scanner) newAMQPScan(target *zgrab2.ScanTarget, conn net.Conn) *scan {

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
			Url: &url.URL{
				Scheme: "amqp",
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

	port := uint16(scanner.config.BaseFlags.Port)
	if target.Port != nil {
		port = uint16(*target.Port)
	}

	host := target.Domain
	if len(host) == 0 {
		host = target.IP.String()
	}

	ret := &Results{}
	handler := scanner.newAMQPRequest(host, port)

	return zgrab2.SCAN_SUCCESS, ret, nil
}
