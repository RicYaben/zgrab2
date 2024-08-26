package webproxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/http"
	"golang.org/x/net/proxy"
)

type webproxyTester struct {
	pport    uint
	lport    uint
	paddress string
	laddress string
	hmackey  string
	bChan    chan string
	slug     bool
}

func (cfg *webproxyTester) runHTTPServer(t *testing.T) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Read and log the body of the request
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Unable to read request body", http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()

		cfg.bChan <- string(body)

		// Respond with a 404 status
		http.Error(w, "Not Found", http.StatusNotFound)
	})
	t.Logf("Starting server on :%d", cfg.lport)
	http.ListenAndServe(fmt.Sprintf(":%d", cfg.lport), nil)
}

func (cfg *webproxyTester) getScanner() (*Scanner, error) {
	var module Module
	flags := module.NewFlags().(*Flags)
	flags.Method = "POST"
	flags.UserAgent = "Mozilla/5.0 HTTPproxy/1.0 zgrab/0.1.6"
	flags.Port = cfg.pport
	flags.Timeout = 30 * time.Second
	flags.Endpoint = fmt.Sprintf("%s:%d", cfg.laddress, cfg.lport)
	flags.HmacKey = cfg.hmackey
	flags.SlugToken = cfg.slug
	flags.UseSOCKS = true
	flags.MaxSize = 4096

	scanner := module.NewScanner()
	if err := scanner.Init(flags); err != nil {
		return nil, err
	}
	return scanner.(*Scanner), nil
}

func (cfg *webproxyTester) runTest(t *testing.T, testName string) {
	target := zgrab2.ScanTarget{
		IP:   net.ParseIP(cfg.paddress),
		Port: &cfg.pport,
	}

	// Run the server and start the scan
	//go cfg.runHTTPServer(t)

	scanner, err := cfg.getScanner()
	if err != nil {
		t.Fatalf("[%s] Unexpected error: %v", testName, err)
	}

	if st, res, err := scanner.Scan(target); err != nil {
		t.Fatalf("[%s] error while scanning: %v, %v", testName, err, st)
	} else {
		t.Logf("%+v", res)
	}

	// Wait for the request to get to the server and read from the channel
	// to parse the token.
	token := <-cfg.bChan
	keyFunk := func(tkn *jwt.Token) (interface{}, error) {
		if _, ok := tkn.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", tkn.Header["alg"])
		}
		return []byte(cfg.hmackey), nil
	}
	parsedToken, err := jwt.Parse(token, keyFunk)
	if err != nil {
		t.Fatalf("[%s] error parsing token: %v", testName, err)
	}

	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok && parsedToken.Valid {
		// Check if the token is expired
		if claims["addr"] != cfg.paddress {
			t.Fatalf("[%s] missmatch, got %s, but expected %s", testName, claims["addr"], cfg.paddress)
		}
	}
}

var tests = map[string]*webproxyTester{
	"success": {
		paddress: "82.165.198.169",
		laddress: "130.226.254.28",
		pport:    41569,
		lport:    80,
		bChan:    make(chan string, 1),
		hmackey:  "gz13WcqhVBy09Mnw7ZZYNCqqlWvyRfJx",
	},
}

// This test requires a proxy in the middle. You can use an out-of-the-box Mikrotik RouterOS
// virtual machine, which has a web proxy forwarder listening at :8080. The server is handled
// locally to capture the JWT identifier as soon as it reaches the server.
//
// The goal is only to make sure the request reaches the server with a JWT.
// The server is in charge of logging this information and make sense of it.
// The recommended approach is to start a tcpdump session and filter requests to
// the designated port. The content can be parsed offline by matching the timestamp
// and the token with the key and looking at the claims, which will contain the
// "recipient" (i.e., the targetted proxy), and the expiration timestamp.
// Keep in mind that the server needs to handle 5-10x the number of requests we make
// per second - consider latency and other factors that will push connections together.
//
// It is not recommended to validate the requests as they come. This is a waste of resources!
// A .pcapng file with the logs far more convenient.
// If disk space is an issue, consider having a server that logs the HTTP requests only.
// You are interested on the headers, the IP source, body, and timestamp.
//
// Since the probe does not consider HTTPS connections, you do not need to handle certificates,
// authentication, encryption, or anything like that. We only care about proxies relaying requests.
func TestProxy(t *testing.T) {
	for tname, cfg := range tests {
		cfg.runTest(t, tname)
	}
}

func TestClient(t *testing.T) {
	proxyURL := "98.181.137.80:4145"
	dialer, err := proxy.SOCKS5("tcp", proxyURL, nil, proxy.Direct)
	if err != nil {
		fmt.Printf("Failed to create dialer: %v\n", err)
		return
	}

	dc := dialer.(interface {
		DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	})

	dfunc := func(ctx context.Context, network string, address string) (net.Conn, error) {
		t := 10 * time.Second
		tc, _ := context.WithTimeout(ctx, t)
		cded, _ := context.WithDeadline(tc, time.Now().Add(t))
		conn, err := dc.DialContext(cded, network, address)
		return conn, err
	}

	transport := &http.Transport{
		DialContext: dfunc,
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
		UserAgent: "Go-http-client/1.1",
	}

	req, _ := http.NewRequest("POST", "http://130.226.254.28:80", nil)

	resp, err := client.Do(req)
	if err != nil {
		t.Error(err)
	}
	defer resp.Body.Close()
}

func TestRequestBuilder(t *testing.T) {
	b := NewRequestBuilder("POST", "localhost:8080", true, http.Header{"cookie": {"123test"}})
	var times = 3
	for range times {
		r, err := b.Build("123test")
		if err != nil {
			t.Fatal(err)
		}
		if r.URL.RawQuery != "token=123test" {
			t.Fatalf("unexpected query: %s", r.URL.RawQuery)
		}
	}
}

type tokenTester struct {
	address    string
	hmacSecret []byte
}

func (cfg *tokenTester) runTest(t *testing.T, testName string) {
	// load a new token
	builder := NewJWTBuilder(cfg.hmacSecret)

	token, err := builder.GenerateToken(cfg.address)
	if err != nil {
		t.Fatalf("[%s] error while generating token: %v", testName, err)
	}

	isValid, err := builder.Verify(token)
	if err != nil {
		t.Fatalf("[%s] error while validating token: %v", testName, err)
	}

	if !isValid {
		t.Errorf("[%s] unexpected validation error", testName)
	}
}

var tokenTests = map[string]*tokenTester{
	"success": {
		address:    "192.168.0.1:8080",
		hmacSecret: []byte("gz13WcqhVBy09Mnw7ZZYNCqqlWvyRfJx"),
	},
}

func TestToken(t *testing.T) {
	for tname, cfg := range tokenTests {
		cfg.runTest(t, tname)
	}
}
