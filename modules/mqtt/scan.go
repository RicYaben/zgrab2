package mqtt

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"

	paho "github.com/eclipse/paho.mqtt.golang"
	"github.com/zmap/zgrab2"
)

type scan struct {
	target  *zgrab2.ScanTarget
	scanner *Scanner
	scheme  string

	topics  []string
	filters map[string]byte

	result Result
}

func (s *scan) getTLSConfig() (*tls.Config, error) {
	cfg, err := s.scanner.config.TLSFlags.GetTLSConfigForTarget(s.target)
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

	// Handle certificate
	t.InsecureSkipVerify = true
	t.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		s.result.Certificates = rawCerts
		return nil
	}

	return &t, nil
}

func (s *scan) getBrokerURL() string {
	port := &s.scanner.config.Port
	if s.target.Port != nil {
		port = s.target.Port
	}
	return fmt.Sprintf("%s://%s:%d", s.scheme, s.target.Host(), *port)
}

func (s *scan) getClientOptions() (*paho.ClientOptions, error) {
	opts := paho.NewClientOptions().
		SetClientID(s.scanner.config.ClientID).
		SetCleanSession(true).
		SetAutoReconnect(true)

	switch s.scheme {
	case "ssl":
		tls, err := s.getTLSConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to make TLS config: %w", err)
		}
		opts.SetTLSConfig(tls)
	case "wss":
		panic("not implemented yet")
	}

	if s.scanner.config.UserAuth {
		opts.SetUsername(s.scanner.config.Username)
		opts.SetPassword(s.scanner.config.Password)
	}

	broker := s.getBrokerURL()
	opts.AddBroker(broker)
	return opts, nil
}

func (s *scan) SetFilters() {
	s.topics = strings.Split(s.scanner.config.SubscribeTopics, s.scanner.config.TopicsSeparator)
	filters := make(map[string]byte)
	for _, topic := range s.topics {
		filters[topic] = 2
	}
	s.filters = filters
}

func (s *scan) makeMessageHandler() func(c paho.Client, m paho.Message) {
	mLimit := s.scanner.config.LimitMessages
	tLimit := s.scanner.config.LimitTopics
	tCount := make(map[string]int)

	var isFull = func(topic string) bool {
		tc, ok := tCount[topic]
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

	var handler = func(c paho.Client, m paho.Message) {
		topic := m.Topic()
		if isFull(topic) {
			c.Unsubscribe(topic)
			return
		}

		tCount[topic]++
		msg := s.result.Topics[m.Topic()]
		msg = append(msg, string(m.Payload()))
		s.result.Topics[m.Topic()] = msg
	}

	return handler
}

func (s *scan) wait(client paho.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), s.scanner.config.Timeout)
	defer cancel()

	<-ctx.Done()
	client.Unsubscribe(s.topics...)
	client.Disconnect(250)
}

func (s *scan) Grab() *zgrab2.ScanError {
	options, err := s.getClientOptions()
	if err != nil {
		return zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, err)
	}

	client := paho.NewClient(options)
	if t := client.Connect(); t.Wait() && t.Error() != nil {
		return zgrab2.NewScanError(zgrab2.SCAN_CONNECTION_REFUSED, t.Error())
	}

	s.SetFilters()
	handler := s.makeMessageHandler()
	if t := client.SubscribeMultiple(s.filters, handler); t.Wait() && t.Error() != nil {
		return zgrab2.NewScanError(zgrab2.SCAN_CONNECTION_REFUSED, t.Error())
	}

	s.wait(client)
	return nil
}

type ScanBuilder struct {
	scanner *Scanner
}

func NewScanBuilder(scanner *Scanner) *ScanBuilder {
	builder := &ScanBuilder{
		scanner: scanner,
	}
	return builder
}

func (b *ScanBuilder) Build(t *zgrab2.ScanTarget, scheme string) *scan {
	scan := &scan{
		scanner: b.scanner,
		target:  t,
		scheme:  scheme,
		result: Result{
			Topics:       make(map[string][]string),
			Scheme:       scheme,
			Certificates: make([][]byte, 0),
		},
	}
	return scan
}
