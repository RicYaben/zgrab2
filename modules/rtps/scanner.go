package rtps

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

// Flags holds the command-line configuration for the dds scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags
	zgrab2.UDPFlags
}

type Result struct {
	RawMessage []byte       `json:"raw-message,omitempty"`
	Message    *RTPSMessage `json:"message,omitempty"`
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
}

type scan struct {
	scanner *Scanner
	result  Result
	target  *zgrab2.ScanTarget
	decoder *rtpsDecoder
}

// GetName implements zgrab2.Scanner.
func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

// GetTrigger implements zgrab2.Scanner.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// InitPerSender implements zgrab2.Scanner.
func (*Scanner) InitPerSender(senderID int) error {
	return nil
}

// Module implements the zgrab2.Module interface.
type Module struct {
}

func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("rtps", "DDSI-RTPS Banner Grab", module.Description(), 16166, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a default Flags object.
func (module *Module) NewFlags() interface{} {
	return new(Flags)
}

func (scanner *Scanner) Protocol() string {
	return "rtps"
}

// NewScanner returns a new Scanner instance.
func (module *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Help returns the module's help string.
func (flags *Flags) Help() string {
	return ""
}

func (flags *Flags) Validate(args []string) error {
	return nil
}

// Description returns an overview of this module.
func (module *Module) Description() string {
	return "Probe for DDSI-RTPS"
}

// Init initializes the Scanner.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	return nil
}

func (scanner *Scanner) newRTPSscan(t *zgrab2.ScanTarget) *scan {
	return &scan{
		scanner: scanner,
		target:  t,
		result: Result{
			RawMessage: nil,
			Message:    new(RTPSMessage),
		},
		decoder: new(rtpsDecoder),
	}
}

func (scanner *Scanner) Scan(t zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	scan := scanner.newRTPSscan(&t)
	if err := scan.Grab(); err != nil {
		return err.Unpack(scan.result)
	}
	return zgrab2.SCAN_SUCCESS, &scan.result, nil
}

func (s *scan) Grab() *zgrab2.ScanError {
	conn, err := s.target.OpenUDP(&s.scanner.config.BaseFlags, &s.scanner.config.UDPFlags)
	if err != nil {
		return zgrab2.DetectScanError(err)
	}
	defer conn.Close()

	pkt, err := s.makeDiscoveryPacket()
	if err != nil {
		zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, err)
	}

	if _, err := conn.Write(pkt); err != nil {
		return zgrab2.DetectScanError(err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return zgrab2.DetectScanError(err)
	}

	s.result.RawMessage = buf[:n]
	msg := new(RTPSMessage)
	if err := s.decoder.Decode(s.result.RawMessage, msg); err != nil {
		zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, err)
	}
	s.result.Message = msg
	return nil
}

func (s *scan) makeDiscoveryPacket() ([]byte, error) {
	// RTPS Header
	header := RTPSHeader{
		Magic:      [4]byte{'R', 'T', 'P', 'S'},
		Version:    [2]byte{2, 1}, // Version 2.1
		VendorID:   [2]byte{1, 0}, // Vendor-specific ID
		GUIDPrefix: [12]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
	}

	// Serialize the RTPS header
	buffer := new(bytes.Buffer)
	if err := binary.Write(buffer, binary.BigEndian, header); err != nil {
		return nil, fmt.Errorf("failed to write RTPS header: %w", err)
	}

	// INFO_TS Submessage
	currentTime := time.Now().Unix()
	infoTS := struct {
		Flags              uint8
		OctetsToNextHeader uint16
		Timestamp          int64 // Timestamp in nanoseconds
	}{
		Flags:              0x01, // Little-endian flag
		OctetsToNextHeader: 8,
		Timestamp:          currentTime,
	}

	// Write INFO_TS Submessage
	if err := binary.Write(buffer, binary.BigEndian, uint8(0x09)); // Submessage type: INFO_TS
	err != nil {
		return nil, fmt.Errorf("failed to write INFO_TS type: %w", err)
	}
	if err := binary.Write(buffer, binary.BigEndian, infoTS.Flags); err != nil {
		return nil, fmt.Errorf("failed to write INFO_TS flags: %w", err)
	}
	if err := binary.Write(buffer, binary.LittleEndian, infoTS.OctetsToNextHeader); err != nil {
		return nil, fmt.Errorf("failed to write INFO_TS octetsToNextHeader: %w", err)
	}
	if err := binary.Write(buffer, binary.LittleEndian, infoTS.Timestamp); err != nil {
		return nil, fmt.Errorf("failed to write INFO_TS timestamp: %w", err)
	}

	return buffer.Bytes(), nil
}
