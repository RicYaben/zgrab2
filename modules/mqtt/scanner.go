// Package mqtt contains the zgrab2 Module implementation for MQTT.
//
// The flags allow to define the QoS mode (1,2 or 3)

package mqtt

import (
	"log"
	"net"

	"github.com/zmap/zgrab2"
)

// Flags holds the command-line configuration for the IMAP scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
}

// Module implements the zgrab2.Module interface.
type Module struct {
}

// A Results object returned from the MQTT module's Scanner.Scan().
type Results struct {
}

// scan holds the state for a single scan. This may entail multiple connections.
// It is used to implement the zgrab2.Scanner interface.
type scan struct {
	connections []net.Conn
	scanner     *Scanner
	target      *zgrab2.ScanTarget
	results     Results
	url         string
}

// Validate performs any needed validation on the arguments
func (flags *Flags) Validate(args []string) error {
	return nil
}

// Help returns module-specific help
func (flags *Flags) Help() string {
	return ""
}

// Protocol returns the protocol identifer for the scanner.
func (scanner *Scanner) Protocol() string {
	return "mqtt"
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

// NewFlags returns an empty Flags object.
func (module *Module) NewFlags() interface{} {
	return new(Flags)
}

func (scanner *Scanner) newMQTTScan(t *zgrab2.ScanTarget) *scan {
	ret := scan{
		scanner: scanner,
		target:  t,
	}

	return &ret
}

// Grab starts the scan
func (scan *scan) Grab() *zgrab2.ScanError {

}

// Scan implements the zgrab2.Scanner interface and performs the full scan of
// the target. If the scanner is configured to follow redirects, this may entail
// multiple TCP connections to hosts other than target.
func (scanner *Scanner) Scan(t zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	// Start the scan
	scan := scanner.newMQTTScan(&t)
	return zgrab2.SCAN_SUCCESS, &scan.results, nil
}

// NewScanner returns a new instance Scanner instance.
func (module *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns an overview of this module.
func (module *Module) Description() string {
	return "Send an MQTT request and read the response."
}

// RegisterModule is called by modules/mqtt.go to register this module with the
// zgrab2 framework.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("mqtt", "MQTT Banner Grab", module.Description(), 143, &module)
	if err != nil {
		log.Fatal(err)
	}
}
