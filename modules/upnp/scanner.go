package upnp

import (
	"net/http"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

// Flags holds the command-line configuration for the bacnet scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags
	zgrab2.UDPFlags

	Method    string `long:"method" default:"M-SEARCH" description:"Request method. Either M-SEARCH or NOTIFY"`
	UserAgent string `long:"user-agent" default:"Mozilla/5.0 UPnP/2.0 zgrab/0.x" description:"Set a custom user agent"` // Format: "OS/version UPnP/2.0 APP/version"; you may want to set some extra information in this header, e.g., a link to a website.
	Man       string `long:"man" default:"ssdp:discover" description:"Extension framework"`
	St        string `long:"st" default:"upnp:rootdevice" description:"Search target"`
}

// Module implements the zgrab2.Module interface.
type Module struct {
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	config  *Flags
	builder SSDPBuilder
}

type Results struct {
	Response *http.Response `json:"response,omitempty"`
}

// RegisterModule registers the zgrab2 module.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("upnp", "upnp", module.Description(), 1900, &module)
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
	Probe for UPnP servers.
	
	The probe consists on sending a unicast HTTP over UDP datagram to a target address.
	The datagram is structured as an SSDP discover request with the M-SEARCH header to order a "MUST" respond.
	It uses a UDP port connection to send the datagram and receive the response.
	The function adds a waiting time to the listener and finishes once the time delay has passed.
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

	builder, err := NewSSDPBuilder(f.Method, f.UserAgent, f.Man, f.St)
	if err != nil {
		return err
	}

	scanner.builder = builder
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
	return "upnp"
}

func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	conn, err := target.OpenUDP(&scanner.config.BaseFlags, &scanner.config.UDPFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer conn.Close()

	port := uint16(scanner.config.BaseFlags.Port)
	if target.Port != nil {
		port = uint16(*target.Port)
	}

	host := target.Domain
	if len(host) == 0 {
		host = target.IP.String()
	}

	ret := &Results{}
	handler := scanner.builder.Build(host, port)

	// NOTE: Not an expert on ZGrab error conventions,
	// For this protocol it only matters to send the request
	// and get an HTTP response. If we don't get an HTTP response
	// we have an issue; and if the response is other than a
	// valid UPnP SSDP discover response we should return another
	// type of error altogether. For the rest of the cases,
	// this handler will do the job.
	b, err := handler.Encode()
	if err != nil {
		return zgrab2.SCAN_UNKNOWN_ERROR, ret, err
	}

	if _, err := conn.Write(b); err != nil {
		return zgrab2.SCAN_UNKNOWN_ERROR, ret, err
	}

	resp, err := handler.ReadHttpResponse(conn)
	if err != nil {
		return zgrab2.SCAN_UNKNOWN_ERROR, ret, err
	}

	ret.Response = resp
	// [4/3/2024] TODO: Handle the different HTTP status and parse the response somehow?
	return zgrab2.SCAN_SUCCESS, ret, nil
}
