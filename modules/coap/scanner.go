package coap

import (
	"encoding/csv"
	"log"
	"strings"
	"time"

	"github.com/zmap/zgrab2"
)

type Flags struct {
	zgrab2.BaseFlags
	zgrab2.UDPFlags

	Paths          string `json:"paths" default:"'.well-known/core','/'" description:"list of paths to send the probe to"`
	PathsDelimiter string `json:"separator" default:"," description:"separator used to split the paths"`
}

// Validate performs any needed validation on the arguments
func (flags *Flags) Validate(args []string) error {
	return nil
}

// Help returns module-specific help
func (flags *Flags) Help() string {
	return ""
}

// Module implements the zgrab2.Module interface.
type Module struct {
}

// NewScanner returns a new instance Scanner instance.
func (module *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns an overview of this module.
func (module *Module) Description() string {
	return "Send an CoAP request and read the response."
}

// scan holds the state for a single scan. This may entail multiple connections.
// It is used to implement the zgrab2.Scanner interface.
type scan struct {
	scanner *Scanner
	target  *zgrab2.ScanTarget
	results []*Result
}

// Grab starts the scan
func (scan *scan) Grab() *zgrab2.ScanError {
	conn, err := scan.target.OpenUDP(&scan.scanner.config.BaseFlags, &scan.scanner.config.UDPFlags)
	if err != nil {
		return zgrab2.NewScanError(zgrab2.TryGetScanStatus(err), err)
	}
	defer conn.Close()

	probe := scan.scanner.probe.Build(conn)
	for _, p := range scan.scanner.paths {
		if err := probe.Do(p); err != nil {
			return err
		}
	}
	defer func() {
		scan.results = probe.results
	}()

	return nil
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
	probe  *ProbeBuilder
	paths  []string
}

// Protocol returns the protocol identifer for the scanner.
func (scanner *Scanner) Protocol() string {
	return "coap"
}

// Init initializes the Scanner.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	fl, _ := flags.(*Flags)
	scanner.config = fl

	pathsReader := csv.NewReader(strings.NewReader(fl.Paths))
	if pathsReader == nil {
		log.Panicf("unable to read paths in CSV reader")
	}

	if len(fl.PathsDelimiter) > 1 {
		log.Panicf("Invalid delimiter, must be a single character")
	} else if fl.PathsDelimiter != "" {
		pathsReader.Comma = rune(fl.PathsDelimiter[0])
	}

	paths, err := pathsReader.Read()
	if err != nil {
		return err
	}
	scanner.paths = paths

	if fl.Timeout <= 0 {
		fl.Timeout = 10 * time.Second
	}

	scanner.probe = newProbeBuilder(fl.Timeout)

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

func (scanner *Scanner) newCoAPscan(t *zgrab2.ScanTarget) *scan {
	ret := &scan{
		target:  t,
		scanner: scanner,
	}
	return ret
}

func (scanner *Scanner) Scan(t zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	scan := scanner.newCoAPscan(&t)
	if err := scan.Grab(); err != nil {
		return err.Unpack(&scan.results)
	}
	return zgrab2.SCAN_SUCCESS, &scan.results, nil
}

// RegisterModule is called by modules/coap.go to register this module with the
// zgrab2 framework.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("coap", "CoAP Banner Grab", module.Description(), 5683, &module)
	if err != nil {
		log.Fatal(err)
	}
}
