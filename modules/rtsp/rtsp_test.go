package rtsp

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/zmap/zgrab2"
)

type rtspTester struct {
	port           int
	expectedStatus zgrab2.ScanStatus
}

func (cfg *rtspTester) runFakeUPnPServer(t *testing.T) {
	endpoint := fmt.Sprintf("127.0.0.1:%d", cfg.port)
	listener, err := net.Listen("tcp", endpoint)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		defer listener.Close()

		sock, err := listener.Accept()
		if err != nil {
			t.Logf("Failed to accept connection: %v", err)
			return
		}
		defer sock.Close()

		header := "RTSP/1.0 200 OK\r\n"
		headerSuffix := "Cseq: 1\r\n" +
			"Server: MyServer/1.0\r\n" +
			"Supported: com.support.com\r\n" +
			"\r\n"

		msg := fmt.Sprintf("%s%s", header, headerSuffix)

		buf := make([]byte, 1)
		_, err = sock.Read(buf)
		if err != nil {
			// any error, including EOF, is unexpected -- the client should send something
			t.Logf("Unexpected error reading from client: %v", err)
			return
		}

		if _, err := sock.Write([]byte(msg)); err != nil {
			t.Logf("write error: %v", err)
			return
		}

	}()
}

func (cfg *rtspTester) getScanner() (*Scanner, error) {
	var module Module
	flags := module.NewFlags().(*Flags)
	flags.UserAgent = "Mozilla/5.0 RTSP/2.0 zgrab/0.x"
	flags.Port = uint(cfg.port)
	flags.Timeout = 1 * time.Second

	scanner := module.NewScanner()
	if err := scanner.Init(flags); err != nil {
		return nil, err
	}

	return scanner.(*Scanner), nil
}

func (cfg *rtspTester) runTest(t *testing.T, testName string) {
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

var tests = map[string]*rtspTester{
	"success": {
		port:           554,
		expectedStatus: zgrab2.SCAN_SUCCESS,
	},
}

func TestUPnP(t *testing.T) {
	for tname, cfg := range tests {
		cfg.runTest(t, tname)
	}
}
