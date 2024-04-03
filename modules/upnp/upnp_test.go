package upnp

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/zmap/zgrab2"
)

type upnpTester struct {
	port           int
	expectedStatus zgrab2.ScanStatus
}

func (cfg *upnpTester) runFakeUPnPServer(t *testing.T) {
	endpoint := fmt.Sprintf("127.0.0.1:%d", cfg.port)
	listener, err := net.ListenPacket("udp", endpoint)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		defer listener.Close()

		// just read something?
		buf := make([]byte, 1024)
		_, addr, err := listener.ReadFrom(buf)
		if err != nil {
			t.Logf("Unexpected error while reading %v", err)
		}

		header := "HTTP/1.1 200 OK\r\n"
		headerSuffix := "CACHE-CONTROL: max-age=1800\r\nEXT: \r\nST: upnp:rootdevice\r\nLOCATION: http://192.168.0.1:80/config.xml\r\nUSN: uuid:abc\r\n\r\n"
		msg := fmt.Sprintf("%s%s", header, headerSuffix)

		if _, err := listener.WriteTo([]byte(msg), addr); err != nil {
			t.Logf("Failed writing to client: %v", err)
			return
		}
	}()
}

func (cfg *upnpTester) getScanner() (*Scanner, error) {
	var module Module
	flags := module.NewFlags().(*Flags)
	flags.Method = "M-SEARCH"
	flags.Man = "ssdp:discover"
	flags.St = "upnp:rootdevice"
	flags.UserAgent = "Mozilla/5.0 UPnP/2.0 zgrab/0.1.6"
	flags.Port = uint(cfg.port)
	flags.Timeout = 1 * time.Second

	scanner := module.NewScanner()
	if err := scanner.Init(flags); err != nil {
		return nil, err
	}

	return scanner.(*Scanner), nil
}

func (cfg *upnpTester) runTest(t *testing.T, testName string) {
	scanner, err := cfg.getScanner()
	if err != nil {
		t.Fatalf("[%s] Unexpected error: %v", testName, err)
	}
	cfg.runFakeUPnPServer(t)

	target := zgrab2.ScanTarget{
		IP: net.ParseIP("127.0.0.1"),
	}
	status, ret, err := scanner.Scan(target)
	if status != cfg.expectedStatus {
		t.Errorf("[%s] Wrong status: expected %s, got %s", testName, cfg.expectedStatus, status)
	}

	if err != nil {
		t.Errorf("[%s] Unexpected error: %v", testName, err)
	}

	if ret == nil {
		t.Errorf("[%s] Got empty response", testName)
	}
}

var tests = map[string]*upnpTester{
	"success": {
		port:           1901, // Very often the UPnP port 1900 is already binded
		expectedStatus: zgrab2.SCAN_SUCCESS,
	},
}

func TestUPnP(t *testing.T) {
	for tname, cfg := range tests {
		cfg.runTest(t, tname)
	}
}
