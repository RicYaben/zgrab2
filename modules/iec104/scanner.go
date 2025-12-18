package iec104

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

// IEC104ScanResults stores the scan output
type IEC104ScanResults struct {
	Scheme        string         `json:"scheme"`
	StartDT       string         `json:"startdt,omitempty"`
	TestFR        string         `json:"testfr,omitempty"`
	Interrogation []*ASDU        `json:"interrogation,omitempty"`
	TLSLog        *zgrab2.TLSLog `json:"tls,omitempty"`
}

// Flags defines IEC-104 command-line options
type Flags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags

	Limit int `long:"n-limit" description:"max. number of CAs to read. no limit: 0" default:"10"`

	// TODO: Implement this behavior
	CARanges    string `long:"ca-ranges" description:"CA's to scan for. Comma separated, e.g.: 1-2,10-100" default:"1"`
	CADelimiter string `long:"delimiter" default:","`
	CASeparator string `long:"separator" default:"-"`

	RetryTLS bool `long:"retry-tls" description:"retry the connection now over TLS"`
	UseTLS   bool `long:"use-tls" description:"force TLS handshake"`
}

// Module implements the zgrab2.Module interface.
type Module struct{}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags

	caRanges [][]uint16
	limit    int

	dialerGroupConfig *zgrab2.DialerGroupConfig
}

// RegisterModule registers the IEC-104 scanner module
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("iec104", "IEC 60870-5-104", module.Description(), 2404, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a default Flags object.
func (module *Module) NewFlags() any {
	return new(Flags)
}

// NewScanner returns a new Scanner instance.
func (module *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns an overview of this module.
func (module *Module) Description() string {
	return "Scan for IEC 60870-5-104 devices and retrieve protocol responses."
}

// Validate ensures correct flag usage.
func (flags *Flags) Validate(args []string) error {
	return nil
}

// Help returns the module's help string.
func (flags *Flags) Help() string {
	return ""
}

func parseRange(s, sep string) ([]uint16, error) {
	ran := strings.SplitN(strings.TrimSpace(s), sep, 2)
	from, err := strconv.ParseUint(strings.TrimSpace(ran[0]), 0, 16)
	if err != nil {
		return nil, err
	}

	result := []uint16{uint16(from)}
	if len(ran) == 1 {
		return append(result, result[0]), nil
	}

	to, err := strconv.ParseUint(strings.TrimSpace(ran[1]), 0, 16)
	if err != nil {
		return nil, err
	}
	return append(result, uint16(to)), nil
}

// Init initializes the Scanner.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f

	scanner.caRanges = [][]uint16{}
	for i, r := range strings.Split(f.CARanges, f.CADelimiter) {
		if strings.TrimSpace(r) == "" {
			continue
		}
		rBuf, err := parseRange(r, f.CASeparator)
		if err != nil {
			return errors.Unwrap(fmt.Errorf("failed to parse CA range %d (%q): %v", i, r, err))
		}
		scanner.caRanges = append(scanner.caRanges, rBuf)
	}

	scanner.limit = f.Limit
	scanner.dialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
		NeedSeparateL4Dialer:            true,
		BaseFlags:                       &f.BaseFlags,
		TLSEnabled:                      f.UseTLS || f.RetryTLS,
		TLSFlags:                        &f.TLSFlags,
	}
	return nil
}

// InitPerSender initializes the scanner for a given sender.
func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

// GetName returns the scanner name.
func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

// GetScanMetadata returns any metadata on the scan itself from this module.
func (scanner *Scanner) GetScanMetadata() any {
	return nil
}

// GetTrigger returns the Trigger defined in the Flags.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// Protocol returns the protocol identifier of the scan.
func (scanner *Scanner) Protocol() string {
	return "iec104"
}

func (scanner *Scanner) GetDialerGroupConfig() *zgrab2.DialerGroupConfig {
	return scanner.dialerGroupConfig
}

// connect establishes a connection (with or without TLS based on scheme)
func (scanner *Scanner) connect(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget, scheme string) (net.Conn, *zgrab2.ScanError) {
	addr := net.JoinHostPort(target.Host(), strconv.Itoa(int(target.Port)))
	conn, err := dialGroup.L4Dialer(target)(ctx, "tcp", addr)
	if err != nil {
		return nil, zgrab2.NewScanError(zgrab2.TryGetScanStatus(err), fmt.Errorf("error opening connection to target %v: %w", addr, err))
	}

	if scheme == "ssl" {
		w := dialGroup.TLSWrapper
		if w == nil {
			return nil, zgrab2.NewScanError(zgrab2.SCAN_INVALID_INPUTS, fmt.Errorf("missing TLS wrapper"))
		}
		conn, err = w(ctx, target, conn)
		if err != nil {
			return nil, zgrab2.DetectScanError(err)
		}
	}

	return conn, nil
}

// scan performs a single scan attempt with the given scheme (tcp or ssl)
func (scanner *Scanner) scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget, scheme string) (zgrab2.ScanStatus, any, error) {
	result := &IEC104ScanResults{
		Scheme:        scheme,
		Interrogation: []*ASDU{},
	}

	conn, scanErr := scanner.connect(ctx, dialGroup, target, scheme)
	if scanErr != nil {
		return scanErr.Status, result, scanErr.Err
	}

	defer func() {
		zgrab2.CloseConnAndHandleError(conn)
	}()

	// Check if we have a TLS conn and grab the log
	if tlsConn, ok := conn.(*zgrab2.TLSConnection); ok {
		result.TLSLog = tlsConn.GetLog()
	}

	testResponse, tErr := SendAPDU(conn, TestFR)
	result.TestFR = testResponse
	if tErr != nil {
		return zgrab2.TryGetScanStatus(tErr), result, tErr
	}

	startResponse, sErr := SendAPDU(conn, StartDT)
	result.StartDT = startResponse
	if sErr != nil {
		return zgrab2.TryGetScanStatus(sErr), result, sErr
	}

	if pErr := probeCA(result, conn, scanner.caRanges, scanner.limit); pErr != nil {
		return pErr.Unpack(result)
	}

	return zgrab2.SCAN_SUCCESS, result, nil
}

// getRetryIterator returns the list of schemes to try
func (scanner *Scanner) getRetryIterator() []string {
	var schemes []string
	var base string

	switch {
	case scanner.config.UseTLS:
		base = "ssl"
	default:
		base = "tcp"
	}

	schemes = append(schemes, base)
	if scanner.config.RetryTLS && !scanner.config.UseTLS {
		schemes = append(schemes, "ssl")
	}
	return schemes
}

// Scan performs the IEC-104 scan with optional TLS retry
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (status zgrab2.ScanStatus, results any, err error) {
	schemes := scanner.getRetryIterator()
	for _, scheme := range schemes {
		if status, results, err = scanner.scan(ctx, dialGroup, target, scheme); status == zgrab2.SCAN_SUCCESS {
			return
		}
	}
	return
}
