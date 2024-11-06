// Package mqtt contains the zgrab2 Module implementation for MQTT.
//
// The flags allow to define the QoS mode (1,2 or 3)
package mqtt

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"

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

// A Results object returned from the MQTT module's Scanner.Scan().
type Results struct {
	Topics map[string][]string `json:"topics,omitempty"`
}

// scan holds the state for a single scan. This may entail multiple connections.
// It is used to implement the zgrab2.Scanner interface.
type scan struct {
	scanner *Scanner
	target  *zgrab2.ScanTarget
	client  paho.Client
	results Results
	tls     bool
}

func (scan *scan) getTLSConfig() (*tls.Config, error) {
	cfg, err := scan.scanner.config.TLSFlags.GetTLSConfigForTarget(scan.target)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS config for target: %w", err)
	}

	b, err := cfg.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal zgrab TLS config: %w", err)
	}

	var t tls.Config
	if err = json.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("failed to unmarshal TLS config: %w", err)
	}

	return &t, nil
}

func (scan *scan) makeClient() (paho.Client, error) {
	// TODO: implement support for web-sockets as well?
	opts := paho.NewClientOptions()

	// Add TLS
	scheme := "tcp"
	if scan.scanner.config.UseTLS {
		scheme = "ssl"
		cfg, err := scan.getTLSConfig()
		if err != nil {
			return nil, err
		}
		opts.SetTLSConfig(cfg)
	}

	// Add broker
	port := &scan.scanner.config.Port
	if scan.target.Port != nil {
		port = scan.target.Port
	}
	t := fmt.Sprintf("%s://%s:%d", scheme, scan.target.Host(), *port)
	opts.AddBroker(t)

	// Add auth details
	if scan.scanner.config.UserAuth {
		opts.SetUsername(scan.scanner.config.Username)
		opts.SetPassword(scan.scanner.config.Password)
	}

	// TODO: change the dialer to a zgrab2 one.
	// opts.SetDialer()
	opts.SetClientID(scan.scanner.config.ClientID)
	opts.SetCleanSession(true)
	opts.SetOrderMatters(false)
	opts.SetAutoReconnect(true)
	return paho.NewClient(opts), nil
}

func (scan *scan) Init() (*scan, error) {
	c, err := scan.makeClient()
	if err != nil {
		return nil, err
	}
	scan.client = c
	return scan, nil
}

func (scan *scan) messageHandler(msgChan chan paho.Message) func(c paho.Client, m paho.Message) {
	mLimit := scan.scanner.config.LimitMessages
	tLimit := scan.scanner.config.LimitTopics
	tCount := make(map[string]int)

	var mu sync.Mutex

	isFull := func(t string) bool {
		mu.Lock()
		defer mu.Unlock()

		tc, ok := tCount[t]
		// if the array does not exist, check the number of topics
		if !ok && (tLimit > -1 && len(tCount) >= tLimit) {
			return true
		}

		// check the number of messages in the topic
		if mLimit > -1 && tc >= mLimit {
			return true
		}
		return false
	}

	var addToCount = func(topic string) {
		mu.Lock()
		defer mu.Unlock()
		tCount[topic]++
	}

	var addMessage = func(c paho.Client, m paho.Message) {
		topic := m.Topic()
		if isFull(topic) {
			c.Unsubscribe(topic)
			return
		}
		addToCount(topic)
		select {
		case msgChan <- m:
			// sent
		default:
			//ignore
		}
	}

	// We cannot block here, so call a goroutine to handle
	// the message instead.
	return func(c paho.Client, m paho.Message) {
		go addMessage(c, m)
	}
}

// Grab starts the scan
func (scan *scan) Grab() *zgrab2.ScanError {
	if t := scan.client.Connect(); t.Wait() && t.Error() != nil {
		return zgrab2.NewScanError(zgrab2.SCAN_CONNECTION_REFUSED, t.Error())
	}
	defer scan.client.Disconnect(250)

	subs := strings.Split(scan.scanner.config.SubscribeTopics, scan.scanner.config.TopicsSeparator)
	filt := make(map[string]byte)
	for _, topic := range subs {
		filt[topic] = 2
	}

	// Limit the number of messages we get
	msgs := make(chan paho.Message)
	handler := scan.messageHandler(msgs)

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		topics := make(map[string][]string)
		for m := range msgs {
			// handle here to addd the results to the scan
			msg := topics[m.Topic()]
			msg = append(msg, string(m.Payload()))
			topics[m.Topic()] = msg
		}
		scan.results.Topics = topics
	}()

	if t := scan.client.SubscribeMultiple(filt, handler); t.Wait() && t.Error() != nil {
		return zgrab2.NewScanError(zgrab2.SCAN_CONNECTION_REFUSED, t.Error())
	}

	ctx, cancel := context.WithTimeout(context.Background(), scan.scanner.config.Timeout)
	defer cancel()

	<-ctx.Done()
	scan.client.Unsubscribe(subs...)
	close(msgs)
	wg.Wait()
	return nil
}

func (scan *scan) handleMessages(msgs chan paho.Message, wg *sync.WaitGroup) {

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
		results: Results{
			Topics: make(map[string][]string),
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
