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
	"encoding/base64"
	"encoding/csv"
	"errors"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/webproxy/request"
	"github.com/zmap/zgrab2/modules/webproxy/scan"
	"github.com/zmap/zgrab2/modules/webproxy/token"
)

// Module is an implementation of the zgrab2.Module interface.
type Module struct{}

// Scanner is the implementation of the zgrab2.Scanner interface.
type Scanner struct {
	config     *scan.Flags
	hmacSecret []byte

	scanBuilder    scan.ScanBuilder
	requestBuilder request.HttpRequestBuilder
	tokenBuilder   token.TokenBuilder
}

// NewFlags returns an empty Flags object.
func (module *Module) NewFlags() interface{} {
	return new(scan.Flags)
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
	fl, _ := flags.(*scan.Flags)
	scanner.config = fl

	// Parse the headers
	if !(len(fl.CustomHeadersNames) > 0 && len(fl.CustomHeadersValues) > 0) {
		log.Panicf("custom-headers-names and custom-headers-values must be specified if one or the other is provided")
	}

	namesReader := csv.NewReader(strings.NewReader(fl.CustomHeadersNames))
	if namesReader == nil {
		log.Panicf("unable to read custom-headers-names in CSV reader")
	}

	valuesReader := csv.NewReader(strings.NewReader(fl.CustomHeadersValues))
	if valuesReader == nil {
		log.Panicf("unable to read custom-headers-values in CSV reader")
	}

	headerNames, err := namesReader.Read()
	if err != nil {
		return err
	}

	headerValues, err := valuesReader.Read()
	if err != nil {
		return err
	}

	if len(headerNames) != len(headerValues) {
		log.Panicf("inconsistent number of HTTP header names and values")
	}

	// By default, the CSV delimiter will remain a comma unless explicitly specified
	hDelimiter := fl.CustomHeadersDelimiter
	if len(hDelimiter) > 1 {
		log.Panicf("Invalid delimiter custom-header delimiter, must be a single character")
	} else if hDelimiter != "" {
		valuesReader.Comma = rune(hDelimiter[0])
		namesReader.Comma = rune(hDelimiter[0])
	}

	headers := &request.Headers{}
	for i, h := range headerNames {
		hName := strings.ToLower(h)
		hValue := headerValues[i]

		headers.Set(hName, hValue)
	}

	// Set the request builder
	reqBuilder, err := request.NewHttpRequestBuilder(fl.Method, fl.Endpoint, headers)
	if err != nil {
		return err
	}
	scanner.requestBuilder = reqBuilder

	// Set the scan builder
	scanBuilder := scan.NewProxyHttpScanBuilder(fl.MaxRedirects, fl.RawHeaders, fl.UserAgent, fl.Timeout, fl.MaxSize)
	scanner.scanBuilder = scanBuilder

	// Set the token builder
	if len(fl.HmacKey) == 0 {
		return fmt.Errorf("HMAC must be included to create JWT identifiers")
	}

	secret, err := base64.StdEncoding.DecodeString(fl.HmacKey)
	if err != nil {
		return fmt.Errorf("failed to decode base64 secret: %w", err)
	}

	if len(secret) != 32 { // 256 bits
		return errors.New("invalid secret length: must be 32 bytes (256 bits)")
	}

	scanner.hmacSecret = secret
	tknBuilder := token.NewJWTBuilder(scanner.hmacSecret)
	scanner.tokenBuilder = tknBuilder

	return nil
}

func (scanner *Scanner) Scan(t zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	// Build the token (body)
	tkn, err := scanner.tokenBuilder.GenerateToken(t.IP.String())
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
