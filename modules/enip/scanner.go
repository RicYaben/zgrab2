package enip

import (
	"context"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"net"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

// Default Ethernet/IP port
// TCP port 44818 explicit messaging
const DefaultPort = 44818

// EthernetIPScanResults stores the scan output
type EthernetIPScanResults struct {
	Scheme                      string         `json:"scheme"`
	ListIdentityRawResponse     string         `json:"ListIdentityRaw_Response,omitempty"`
	ListIdentityRequestResponse string         `json:"ListIdentity_Response,omitempty"`
	ListServicesRawResponse     string         `json:"ListServicesRaw_Response,omitempty"`
	ListServicesRequestResponse string         `json:"ListServices_Response,omitempty"`
	RegisterSessionRawResponse  string         `json:"RegisterSessionRaw_Response,omitempty"`
	RegisterSessionResponse     string         `json:"RegisterSession_Response,omitempty"`
	RoundTripTime               time.Duration  `json:"round_trip_time,omitempty"`
	TLSLog                      *zgrab2.TLSLog `json:"tls,omitempty"`
}

// Flags defines Ethernet/IP command-line options
type Flags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags

	Verbose         bool   `long:"verbose" description:"Enable verbose logging"`
	RegisterSession bool   `long:"register-session" description:"Register a session with server to enable CIP commands"`
	SessionHandle   string `long:"session-handle" description:"a session tracker. You can place an identifier here, e.g., zgrab2-scanner"`

	RetryTLS bool `long:"retry-tls" description:"retry the connection now over TLS"`
	UseTLS   bool `long:"use-tls" description:"force TLS handshake"`
}

// Module implements the zgrab2.Module interface.
type Module struct{}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	config            *Flags
	sessionHandle     uint32
	dialerGroupConfig *zgrab2.DialerGroupConfig
}

// RegisterModule registers the EtherNet/IP scanner module
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("ethernetip", "EtherNet/IP", module.Description(), DefaultPort, &module)
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
	return "Scan for EtherNet/IP devices and retrieve protocol responses."
}

// GetScanMetadata returns any metadata on the scan itself from this module.
func (scanner *Scanner) GetScanMetadata() any {
	return nil
}

// Validate ensures correct flag usage.
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

	h := fnv.New32a()
	h.Write([]byte(f.SessionHandle))
	scanner.sessionHandle = h.Sum32()
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

// GetTrigger returns the Trigger defined in the Flags.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// Protocol returns the protocol identifier of the scan.
func (scanner *Scanner) Protocol() string {
	return "ethernetip"
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
	conn, scanErr := scanner.connect(ctx, dialGroup, target, scheme)
	if scanErr != nil {
		return scanErr.Status, nil, scanErr.Err
	}

	defer func() {
		zgrab2.CloseConnAndHandleError(conn)
	}()

	// Starts sending commands and saving responses
	startTime := time.Now()

	lstIdentReq := ListIdentityRequest
	lstIdentReq.SessionHandle = scanner.sessionHandle
	listIdentityRequestResponse, listIdentityRawResponse, err := SendEtherNetIPMessage(conn, lstIdentReq)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	ListIdentityRawBytes, err := hex.DecodeString(listIdentityRawResponse)
	if err != nil || !IsValidEthernetIPHeaderListIdentity(ListIdentityRawBytes) {
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, fmt.Errorf("invalid ListIdentity response header, (raw = %s)", listIdentityRawResponse)
	}

	result := &EthernetIPScanResults{
		Scheme:                      scheme,
		ListIdentityRequestResponse: listIdentityRequestResponse,
		ListIdentityRawResponse:     listIdentityRawResponse,
		RoundTripTime:               time.Since(startTime),
	}

	lstServReq := ListServicesRequest
	lstServReq.SessionHandle = scanner.sessionHandle
	listServicesRequestResponse, listServicesRawResponse, err := SendEtherNetIPMessage(conn, lstServReq)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), result, err
	}
	result.ListServicesRequestResponse = listServicesRequestResponse
	result.ListServicesRawResponse = listServicesRawResponse

	// If register session flag is used send additional command to start session.
	if scanner.config.RegisterSession {
		regSesReq := RegisterSession
		regSesReq.SessionHandle = scanner.sessionHandle
		registerSessionResponse, registerSessionRawResponse, err := SendEtherNetIPMessage(conn, regSesReq)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), result, err
		}
		result.RegisterSessionResponse = registerSessionResponse
		result.RegisterSessionRawResponse = registerSessionRawResponse
	}

	// Check if we have a TLS conn and grab the log
	if tlsConn, ok := conn.(*zgrab2.TLSConnection); ok {
		result.TLSLog = tlsConn.GetLog()
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

// Scan performs the EtherNet/IP scan with optional TLS retry
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (status zgrab2.ScanStatus, results any, err error) {
	schemes := scanner.getRetryIterator()
	for _, scheme := range schemes {
		if status, results, err = scanner.scan(ctx, dialGroup, target, scheme); status == zgrab2.SCAN_SUCCESS {
			return
		}
	}
	return
}
