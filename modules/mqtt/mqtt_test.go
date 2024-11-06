// Run this test with a Docker container running a standard broker to test the validity of the probe
package mqtt

import (
	"testing"

	"github.com/zmap/zgrab2"
)

type mqttTester struct {
	addr           string
	port           int
	expectedStatus zgrab2.ScanStatus
}

func (t *mqttTester) getScanner() (*Scanner, error) {
	var module Module
	flags := module.NewFlags().(*Flags)
	flags.Port = uint(t.port)

	// Identifiers
	flags.ClientID = "testClient" // MQTT-specific
	flags.ClientRandom = "blabla" // on the TCP handshake

	// Client and user
	flags.SubscribeTopics = "#,$SYS/#"
	flags.TopicsSeparator = ","
	flags.LimitMessages = 1
	flags.LimitTopics = 10

	// Attempt anonymous auth with
	// an empty user and password as the
	flags.UserAuth = true
	flags.Username = ""
	flags.Password = ""

	scanner := module.NewScanner()
	if err := scanner.Init(flags); err != nil {
		return nil, err
	}

	return scanner.(*Scanner), nil
}

func (t *mqttTester) runTest(test *testing.T, name string) {
	scanner, err := t.getScanner()
	if err != nil {
		test.Fatalf("[%s] Unexpected error: %v", name, err)
	}

	target := zgrab2.ScanTarget{
		Domain: t.addr,
	}

	status, ret, err := scanner.Scan(target)
	if status != t.expectedStatus {
		test.Errorf("[%s] Wrong status: expected %s, got %s", name, t.expectedStatus, status)
	}

	if err != nil {
		test.Errorf("[%s] Unexpected error: %v", name, err)
	}

	if ret == nil {
		test.Errorf("[%s] Got empty response", name)
	}
}

var tests = map[string]*mqttTester{
	"success": {
		addr:           "test.mosquitto.org",
		port:           1883,
		expectedStatus: zgrab2.SCAN_SUCCESS,
	},
}

func TestMQTT(t *testing.T) {
	for tname, cfg := range tests {
		cfg.runTest(t, tname)
	}
}
