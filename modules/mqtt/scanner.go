// Package mqtt contains the zgrab2 Module implementation for MQTT.
//
// The flags allow to define the QoS mode (1,2 or 3)
package mqtt

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	paho "github.com/eclipse/paho.mqtt.golang"
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

	SubscribeTopics  string        `long:"subscribe-topics" default:"#,$SYS/#" description:"list of topics to subscribe to. Defaults to wildcard all and system."`
	TopicsSeparator  string        `long:"separator" default:"," description:"subscribe topics separator"`
	SubscribeTimeout time.Duration `long:"wait" default:"10s" description:"time to accept messages from the subscribed topics. Defaults to 10 seconds"`

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

// A Results object returned from the MQTT module's Scanner.Scan().
type Results struct {
	topics map[string][]string
}

// scan holds the state for a single scan. This may entail multiple connections.
// It is used to implement the zgrab2.Scanner interface.
type scan struct {
	scanner *Scanner
	target  *zgrab2.ScanTarget
	client  paho.Client
	results *Results
	tls     bool
}

func (scan *scan) getTLSConfig() (*tls.Config, error) {
	cfg, err := scan.scanner.config.TLSFlags.GetTLSConfigForTarget(scan.target)
	if err != nil {
		return nil, err
	}

	var (
		b []byte
		t *tls.Config
	)
	if b, err = cfg.MarshalJSON(); err != nil {
		return nil, err
	}

	if err = json.Unmarshal(b, &t); err != nil {
		return nil, err
	}

	return t, nil
}

func (scan *scan) makeClient() (paho.Client, error) {
	// TODO: implement support for web-sockets as well?
	o := paho.NewClientOptions()

	// Add TLS
	scheme := "tcp"
	if scan.scanner.config.UseTLS {
		scheme = "ssl"
		cfg, err := scan.getTLSConfig()
		if err != nil {
			return nil, err
		}
		o.SetTLSConfig(cfg)
	}

	// Add broker
	port := &scan.scanner.config.Port
	if scan.target.Port != nil {
		port = scan.target.Port
	}
	t := fmt.Sprintf("%s://%s:%d", scheme, scan.target.IP.String(), *port)
	o.AddBroker(t)

	// Add auth details
	if scan.scanner.config.UserAuth {
		o.SetUsername(scan.scanner.config.Username)
		o.SetPassword(scan.scanner.config.Password)
	}

	o.SetClientID(scan.scanner.config.ClientID)
	o.SetCleanSession(true)
	return paho.NewClient(o), nil
}

func (scan *scan) Init() (*scan, error) {
	c, err := scan.makeClient()
	if err != nil {
		return nil, err
	}
	scan.client = c
	return scan, nil
}

// Grab starts the scan
func (scan *scan) Grab() *zgrab2.ScanError {
	if t := scan.client.Connect(); t.Wait() && t.Error() != nil {
		return zgrab2.NewScanError(zgrab2.SCAN_CONNECTION_REFUSED, t.Error())
	}

	topics := strings.Split(scan.scanner.config.SubscribeTopics, scan.scanner.config.TopicsSeparator)
	filt := make(map[string]byte)
	for _, topic := range topics {
		filt[topic] = 2
	}

	msgs := make(chan paho.Message)
	handler := func(c paho.Client, m paho.Message) {
		msgs <- m
	}

	if t := scan.client.SubscribeMultiple(filt, handler); t.Wait() && t.Error() != nil {
		return zgrab2.NewScanError(zgrab2.SCAN_CONNECTION_REFUSED, t.Error())
	}

	go func() {
		time.Sleep(scan.scanner.config.SubscribeTimeout)
		scan.client.Unsubscribe(topics...)
		close(msgs)
	}()

	for m := range msgs {
		// handle here to addd the results to the scan
		msgs := scan.results.topics[m.Topic()]
		msgs = append(msgs, string(m.Payload()))
		scan.results.topics[m.Topic()] = msgs
	}

	return nil
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
}

// Protocol returns the protocol identifer for the scanner.
func (scanner *Scanner) Protocol() string {
	return "mqtt"
}

// Init initializes the Scanner.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	scanner.config = flags.(*Flags)
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

func (scanner *Scanner) newMQTTScan(t *zgrab2.ScanTarget, tls bool) (*scan, error) {
	ret := &scan{
		scanner: scanner,
		target:  t,
		results: &Results{
			topics: make(map[string][]string),
		},
		tls: tls,
	}
	return ret.Init()
}

// Scan implements the zgrab2.Scanner interface and performs the full scan of
// the target. If the scanner is configured to follow redirects, this may entail
// multiple TCP connections to hosts other than target.
func (scanner *Scanner) Scan(t zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	// Start the scan
	scan, err := scanner.newMQTTScan(&t, scanner.config.UseTLS)
	if err != nil {
		return zgrab2.SCAN_APPLICATION_ERROR, nil, err
	}

	scanerr := scan.Grab()
	if scanerr != nil {
		if scanner.config.RetryTLS && !scanner.config.UseTLS {
			retry, err := scanner.newMQTTScan(&t, true)
			if err != nil {
				return zgrab2.SCAN_APPLICATION_ERROR, nil, err
			}

			retryError := retry.Grab()
			if retryError != nil {
				return retryError.Unpack(&scan.results)
			}
			return zgrab2.SCAN_SUCCESS, &retry.results, nil
		}
		return scanerr.Unpack(&scan.results)
	}
	return zgrab2.SCAN_SUCCESS, &scan.results, nil
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
