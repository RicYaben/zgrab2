// Package mqtt contains the zgrab2 Module implementation for MQTT.
//
// The flags allow to define the QoS mode (1,2 or 3)
package mqtt

import (
	log "github.com/sirupsen/logrus"

	"github.com/zmap/zgrab2"
)

// Flags holds the command-line configuration for the IMAP scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags

	ClientID string `long:"client-id" default:"default" description:"client ID used to stablish a connection to the broker"`
	RetryTLS bool   `long:"retry-tls" description:"retry the connection now over TLS"`
	UseTLS   bool   `long:"use-tls" description:"force TLS handshake"`

	//UseWebSocket bool `long:"use-ws" description:"force use Web Sockets as the communication channel"`
	//UserAgent       string `long:"user-agent" default:"Mozilla/5.0 zgrab/0.x" description:"Set a custom user agent"`

	LimitMessages int `long:"limit-messages" description:"messages per topic, one is enough to prove read access. Default: 0; Limitless: -1;"`
	LimitTopics   int `long:"limit-topics" description:"number of topics to include, 100 topics cover most use cases. Default: 0; Limitless: -1;"`

	SubscribeTopics string `long:"subscribe-topics" default:"#,$SYS/#" description:"list of topics to subscribe to. Defaults to wildcard all and system."`
	TopicsSeparator string `long:"separator" default:"," description:"subscribe topics separator"`

	UserAuth bool   `long:"user-auth" description:"whether to authenticate using a set of credentials"`
	Username string `long:"username" description:"username to authenticate"`
	Password string `long:"password" description:"password to authenticate"`
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
	return "Send an MQTT request and read the response."
}

// A Result object returned from the MQTT module's Scanner.Scan().
type Result struct {
	Topics       map[string][]string `json:"topics,omitempty"`
	Certificates [][]byte            `json:"certificate,omitempty"`
	Scheme       string              `json:"scheme"`
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	config  *Flags
	builder *ScanBuilder
}

// Protocol returns the protocol identifer for the scanner.
func (scanner *Scanner) Protocol() string {
	return "mqtt"
}

// Init initializes the Scanner.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	scanner.config = flags.(*Flags)
	scanner.builder = NewScanBuilder(scanner)
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

func (s *Scanner) getRetryIterator() []string {
	var schemes []string
	var base string
	switch {
	case s.config.UseTLS:
		base = "ssl"
	default:
		base = "tcp"
	}

	schemes = append(schemes, base)
	if s.config.RetryTLS && !s.config.UseTLS {
		schemes = append(schemes, "ssl")
	}
	return schemes
}

func (s *Scanner) scan(t *zgrab2.ScanTarget, scheme string) (zgrab2.ScanStatus, interface{}, error) {
	scan := s.builder.Build(t, scheme)
	if err := scan.Grab(); err != nil {
		return err.Unpack(scan.result)
	}
	return zgrab2.SCAN_SUCCESS, scan.result, nil
}

// Scan implements the zgrab2.Scanner interface and performs the full scan of
// the target. If the scanner is configured to follow redirects, this may entail
// multiple TCP connections to hosts other than target.
func (s *Scanner) Scan(t zgrab2.ScanTarget) (status zgrab2.ScanStatus, results interface{}, err error) {
	schemes := s.getRetryIterator()
	for _, scheme := range schemes {
		if status, results, err = s.scan(&t, scheme); status == zgrab2.SCAN_SUCCESS {
			return
		}
	}
	return
}

// RegisterModule is called by modules/mqtt.go to register this module with the
// zgrab2 framework.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("mqtt", "MQTT Banner Grab", module.Description(), 1883, &module)
	if err != nil {
		log.Fatal(err)
	}
}
