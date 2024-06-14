package token

import "testing"

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

var tests = map[string]*tokenTester{
	"success": {
		address:    "192.168.0.1:8080",
		hmacSecret: []byte("gz13WcqhVBy09Mnw7ZZYNCqqlWvyRfJx"),
	},
}

func TestToken(t *testing.T) {
	for tname, cfg := range tests {
		cfg.runTest(t, tname)
	}
}
