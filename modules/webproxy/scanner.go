// Package webproxy cointains the zgrab2 module to identify open proxies.
//
// The module is designed to test whether an address is running web proxy of some kind
// including HTTP(S) and SOCKS. This module implements an HTTP server to receive
// connections from these proxies. The flow of the connection is simplistic and attempts
// to reduce the number of packets in the communication. Since the we "own" the vantage
// point and the destination of the probe, there is no need to respond to our probe.
// Instead, the probe contains a non-fungible token (an identifier) that verifies the
// the request and the procedence. This implementation decission is based on the notion
// that web proxies may not be the entry and exit nodes may not be the same (e.g., in SOCKS),
// but a black tunnel that relays messages.
//
// NOTE: The common request method is an HTTP GET request, but there are other valid alternatives,
// such as TRACE, OPTIONS, and CONNECT. These methods may be useful to identify specific
// web proxy implementations. For HTTPS connections, we will use CONNECT first, and then
// submit the GET request.
package webproxy

import (
	"encoding/csv"
	"errors"
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/http"
	"github.com/zmap/zgrab2/modules/webproxy/request"
	"github.com/zmap/zgrab2/modules/webproxy/scan"
	"github.com/zmap/zgrab2/modules/webproxy/token"
)

type Flags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags

	Method    string `long:"method" default:"POST" description:"Set HTTP request method type"`
	Endpoint  string `long:"endpoint" default:"/" description:"Send an HTTP request to an endpoint"`
	UserAgent string `long:"user-agent" default:"Mozilla/5.0 zgrab/0.x" description:"Set a custom user agent"`

	MaxSize      int    `long:"max-size" default:"256" description:"Max kilobytes to read in response to an HTTP request"`
	MaxRedirects int    `long:"max-redirects" default:"0" description:"Max number of redirects to follow"`
	HmacKey      string `long:"hmac-key" description:"HMAC secret to create and verify JWT identifiers"`

	CustomHeadersNames     string `long:"custom-headers-names" description:"CSV of custom HTTP headers to send to server"`
	CustomHeadersValues    string `long:"custom-headers-values" description:"CSV of custom HTTP header values to send to server. Should match order of custom-headers-names."`
	CustomHeadersDelimiter string `long:"custom-headers-delimiter" description:"Delimiter for customer header name/value CSVs"`

	RawHeaders bool `long:"raw-headers" description:"Extract raw response up through headers"`
}

// Module is an implementation of the zgrab2.Module interface.
type Module struct{}

// Scanner is the implementation of the zgrab2.Scanner interface.
type Scanner struct {
	config     *Flags
	hmacSecret []byte

	scanBuilder    scan.ScanBuilder
	requestBuilder request.HttpRequestBuilder
	tokenBuilder   token.TokenBuilder
}

// Validate performs any needed validation on the arguments
func (flags *Flags) Validate(args []string) error {
	return nil
}

// Help returns module-specific help
func (flags *Flags) Help() string {
	return ""
}

// NewFlags returns an empty Flags object.
func (module *Module) NewFlags() interface{} {
	return new(Flags)
}

// NewScanner returns a new instance Scanner instance.
func (module *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns an overview of this module.
func (module *Module) Description() string {
	return "Circuits back an HTTP request through a web proxy"
}

// Protocol returns the protocol identifer for the scanner.
func (scanner *Scanner) Protocol() string {
	return "webproxy"
}

// GetName returns the name defined in the Flags.
func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

// GetTrigger returns the Trigger defined in the Flags.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// InitPerSender does nothing in this module.
func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	fl, _ := flags.(*Flags)
	scanner.config = fl

	// Parse the headers
	headers, err := parseHeadersCSV(fl.CustomHeadersNames, fl.CustomHeadersValues, fl.CustomHeadersDelimiter)
	if err != nil {
		return err
	}

	// Set the request builder
	if fl.Method == "" {
		fl.Method = "POST"
	}
	reqBuilder, err := request.NewHttpRequestBuilder(fl.Method, fl.Endpoint, headers)
	if err != nil {
		return err
	}
	scanner.requestBuilder = reqBuilder

	// Set the scan builder
	if fl.Timeout == 0 {
		fl.Timeout = 10 * time.Second
	}

	scanBuilder := scan.NewProxyHttpScanBuilder(fl.MaxRedirects, fl.RawHeaders, fl.UserAgent, fl.Timeout, fl.MaxSize)
	scanner.scanBuilder = scanBuilder

	// Set the token builder
	if len(fl.HmacKey) == 0 {
		return errors.New("HMAC must be included to create JWT identifiers")
	} else if len(fl.HmacKey) != 32 {
		return errors.New("invalid secret length: must be 32 bytes (256 bits)")
	}

	secret := []byte(fl.HmacKey)
	scanner.hmacSecret = secret
	tknBuilder := token.NewJWTBuilder(scanner.hmacSecret)
	scanner.tokenBuilder = tknBuilder

	return nil
}

func (scanner *Scanner) Scan(t zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	// Assign the port if it does not exist yet
	if t.Port == nil {
		t.Port = &scanner.config.BaseFlags.Port
	}

	// Build the token (body)
	addr := fmt.Sprintf("%s:%d", t.IP.String(), t.Port)
	tkn, err := scanner.tokenBuilder.GenerateToken(addr)
	if err != nil {
		return zgrab2.SCAN_UNKNOWN_ERROR, nil, err
	}

	// Build the request
	req, err := scanner.requestBuilder.Build(tkn)
	if err != nil {
		return zgrab2.SCAN_UNKNOWN_ERROR, nil, err
	}

	// Build the scan
	s := scanner.scanBuilder.Build(t)
	err = s.Init()
	if err != nil {
		return zgrab2.SCAN_UNKNOWN_ERROR, nil, err
	}
	defer s.Cleanup()

	// Grab the results
	grabError := s.Grab(req)
	results := s.GetResults()
	if grabError != nil {
		return grabError.Unpack(results)
	}

	return zgrab2.SCAN_SUCCESS, results, nil
}

// RegisterModule is called by modules/http.go to register this module with the
// zgrab2 framework.
func RegisterModule() {
	var module Module

	_, err := zgrab2.AddCommand("webproxy", "HTTP proxy Banner Grab", module.Description(), 8080, &module)
	if err != nil {
		log.Fatal(err)
	}
}

func parseHeadersCSV(names string, values string, delimiter string) (http.Header, error) {

	if len(names) == 0 && len(values) == 0 {
		return nil, nil
	} else if len(names) > 0 || len(values) > 0 {
		if len(names) == 0 {
			return nil, fmt.Errorf("names must be specified if values are provided")
		} else if len(values) == 0 {
			return nil, fmt.Errorf("values must be specified if names are provided")
		}
	}

	// By default, the CSV delimiter will remain a comma unless explicitly specified
	dlim := ','
	if len(delimiter) == 1 {
		dlim = rune(delimiter[0])
	} else if len(delimiter) > 1 {
		return nil, fmt.Errorf("invalid delimiter, must be a single character")
	}

	// Function to parse CSV string into a slice of strings
	parseCSV := func(data string) ([]string, error) {
		reader := csv.NewReader(strings.NewReader(data))
		reader.Comma = dlim
		return reader.Read()
	}

	// Parse the input strings
	hNames, err := parseCSV(names)
	if err != nil {
		return nil, fmt.Errorf("error parsing names: %v", err)
	}

	hValues, err := parseCSV(values)
	if err != nil {
		return nil, fmt.Errorf("error parsing values: %v", err)
	}

	// Create and populate the Headers map
	headers := make(http.Header)
	for i, v := range hNames {
		headers.Set(strings.ToLower(v), hValues[i])
	}

	return headers, nil
}
