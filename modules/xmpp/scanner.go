package xmpp

import (
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

type Flags struct {
	zgrab2.BaseFlags
	zgrab2.UDPFlags
}

type Result struct {
	Response string `json:"banner,omitempty"`
}

type Module struct{}

type Scanner struct {
	config *Flags
}

// Validate performs any needed validation on the arguments
func (flags *Flags) Validate(args []string) error {
	return nil
}

// Help returns module-specific help
func (flags *Flags) Help() string {
	return ""
}

func (module *Module) NewFlags() interface{} {
	return new(Flags)
}

// NewScanner returns a new Scanner instance.
func (module *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns text uses in the help for this module.
func (module *Module) Description() string {
	return "Probe for devices that run XMPP."
}
func (module *Module) Help() string {
	return "Scan for XMPP (Extensible Messaging and Presence Protocol) protocol"
}

func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("xmpp", "Extensible Messaging and Presence Protocol", module.Description(), 5222, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// Protocol returns the protocol identifier of the scan.
func (scanner *Scanner) Protocol() string {
	return "xmpp"
}

// GetName returns the Scanner name defined in the Flags.
func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

// GetTrigger returns the Trigger defined in the Flags.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// InitPerSender initializes the scanner for a given sender.
func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f

	if f.Timeout <= 0 {
		f.Timeout = 10 * time.Second
	}

	return nil
}

type scan struct {
	scanner *Scanner
	target  *zgrab2.ScanTarget
	result  *Result
}

func (scan *scan) Grab() *zgrab2.ScanError {
	conn, err := scan.target.OpenUDP(&scan.scanner.config.BaseFlags, &scan.scanner.config.UDPFlags)
	if err != nil {
		return zgrab2.NewScanError(zgrab2.TryGetScanStatus(err), err)
	}
	defer conn.Close()

	stanza := fmt.Sprintf(`<?xml version="1.0"?>`+
		`<stream:stream xmlns:stream="http://etherx.jabber.org/streams" xmlns="jabber:client" to="%s" version="1.0">`,
		scan.target.Host(),
	)

	if err := conn.SetReadDeadline(time.Now().Add(scan.scanner.config.Timeout)); err != nil {
		return zgrab2.NewScanError(zgrab2.SCAN_UNKNOWN_ERROR, err)
	}

	if _, err := conn.Write([]byte(stanza)); err != nil {
		return zgrab2.DetectScanError(err)
	}

	response, err := zgrab2.ReadAvailable(conn)
	if err != nil {
		return zgrab2.DetectScanError(err)
	}

	scan.result = &Result{
		Response: string(response),
	}

	return nil
}

func (scanner *Scanner) newXMPPscan(t *zgrab2.ScanTarget) *scan {
	return &scan{
		target:  t,
		scanner: scanner,
	}
}

// perform the XMPP scan
func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	scan := scanner.newXMPPscan(&target)
	err := scan.Grab()
	if err != nil {
		return err.Unpack(&scan.result)
	}
	return zgrab2.SCAN_SUCCESS, &scan.result, nil
}
