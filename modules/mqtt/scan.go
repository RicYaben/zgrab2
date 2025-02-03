package mqtt

import (
	"context"
	"crypto/rand"
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

func (s *scan) randomizeClientID() string {
	const (
		charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
		maxLen  = 23 // as defined by MQTT 3.1
	)

	if len(s.scanner.config.ClientID) > maxLen {
		return s.scanner.config.ClientID[:maxLen]
	}

	var (
		suffix []byte
		cap    = maxLen - len(s.scanner.config.ClientID)
	)

	for i := 0; i < cap; i++ {
		r := make([]byte, 1)
		rand.Read(r)
		suffix = append(suffix, charset[r[0]%byte(len(charset))])
	}
	return s.scanner.config.ClientID + string(suffix)
}

func (s *scan) getClientOptions() (*paho.ClientOptions, error) {
	id := s.randomizeClientID()
	opts := paho.NewClientOptions().
		SetClientID(id).
		SetCleanSession(true).
		SetAutoReconnect(false)

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
			// unsubscribe and ignore the message
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

	// timeout, finish now
	<-ctx.Done()
	// do **not** wait for the unsubscribe to return anything
	client.Unsubscribe(s.topics...)
}

func (s *scan) Grab() *zgrab2.ScanError {
	options, err := s.getClientOptions()
	if err != nil {
		return zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, err)
	}

	client := paho.NewClient(options)
	if t := client.Connect(); t.WaitTimeout(s.scanner.config.Timeout) && t.Error() != nil {
		return zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, t.Error())
	}
	defer client.Disconnect(250)

	go func() {
		defer func() {
			// Stop panic
			// The paho client tends to panic on:
			// github.com/eclipse/paho%2emqtt%2egolang.startIncomingComms.func1()
			// ...github.com/eclipse/paho.mqtt.golang@v1.5.0/net.go:212 +0x101d
			// This is caused by the server returning more returnCodes than the number
			// of responses for the subscribed topics.
			if r := recover(); r != nil {
				s.result.Error = r
			}
		}()

		s.SetFilters()
		handler := s.makeMessageHandler()
		if t := client.SubscribeMultiple(s.filters, handler); t.WaitTimeout(s.scanner.config.Timeout) && t.Error() != nil {
			s.result.Error = t.Error()
		}
	}()

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
