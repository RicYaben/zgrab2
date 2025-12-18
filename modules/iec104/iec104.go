package iec104

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"

	"github.com/zmap/zgrab2"
)

// IEC104APDU represents an IEC-104 protocol APDU.
type IEC104APDU struct {
	Data []byte
}

// Predefined IEC-104 APDUs
var (
	StartDT = IEC104APDU{Data: []byte{0x68, 0x04, 0x07, 0x00, 0x00, 0x00}}
	StopDT  = IEC104APDU{Data: []byte{0x68, 0x04, 0x13, 0x00, 0x00, 0x00}}
	TestFR  = IEC104APDU{Data: []byte{0x68, 0x04, 0x43, 0x00, 0x00, 0x00}}
)

// SendAPDU sends an IEC-104 APDU and returns the response.
func SendAPDU(conn net.Conn, apdu IEC104APDU) (string, error) {
	_, err := conn.Write(apdu.Data)
	if err != nil {
		return "", err
	}

	// All of the regular testing probes have a length of 6 bytes
	buffer := make([]byte, 100)
	n, err := conn.Read(buffer)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(buffer[:n]), nil
}

type ASDU struct {
	TypeID uint8
	SQ     bool
	NumIx  uint8
	Cause  uint8
	OA     uint8
	CA     uint16
	IOAs   []IOA
	Raw    []byte
}

// IOA represents an Information Object within an ASDU.
type IOA struct {
	Address uint32 // 3-byte Information Object Address
	Data    []byte // Optional data following the IOA (e.g. QOI, measurement values, etc.)
}

func makeInterrogationAPDU(ca uint16) []byte {
	return []byte{
		0x68, 0x0E, 0x00, 0x00, 0x00, 0x00,
		0x64, 0x01, // TypeID = 100 = C_IC_NA_1 (Interrogation)
		0x06, 0x00, // COT=6 (activation)
		byte(ca & 0xff), byte(ca >> 8), // CA LSB & MSB
		0x00, 0x00, 0x00,
		0x14, // QOI = 20, station interrogation (global)
	}
}

func getASDUData(conn net.Conn) ([]byte, error) {
	buf := make([]byte, 2)
	_, bErr := conn.Read(buf)
	if bErr != nil {
		return nil, bErr
	}

	if buf[0] != 0x68 {
		return nil, fmt.Errorf("not IEC-104 (0byte = %d)", buf[0])
	}

	data := make([]byte, buf[1])
	_, dErr := conn.Read(data)
	if dErr != nil {
		return nil, dErr
	}

	return data, nil
}

// TODO: this is not right, the only cases we know are 100, 13, and 36
func getDataLength(typeID uint8) int {
	switch typeID {
	case 9, 11:
		return 3 // 2-byte value + 1-byte QDS
	case 13, 34:
		return 5 // float(4) + QDS(1)
	case 36:
		return 12 // float(4) + QDS(1) + CP56Time2a(7) = 12 after IOA
	default:
		return 1
	}
}

func parseIOAs(asdu *ASDU) {
	defer func() {
		if r := recover(); r != nil {
			return
		}
	}()

	if asdu == nil || len(asdu.Raw) < 6 {
		return // invalid input
	}

	if !slices.Contains([]uint8{36, 13, 100}, asdu.TypeID) {
		return
	}

	pos := 6
	var baseIOA uint32

	for j := uint8(0); j < asdu.NumIx; j++ {
		// --- Guard 1: check enough bytes for IOA ---
		if pos+3 > len(asdu.Raw) {
			// not enough bytes to read IOA
			return
		}

		var ioa uint32
		if asdu.SQ {
			if j == 0 {
				ioa = uint32(asdu.Raw[pos]) |
					uint32(asdu.Raw[pos+1])<<8 |
					uint32(asdu.Raw[pos+2])<<16
				baseIOA = ioa
				pos += 3
			} else {
				ioa = baseIOA + uint32(j)
			}
		} else {
			ioa = uint32(asdu.Raw[pos]) |
				uint32(asdu.Raw[pos+1])<<8 |
				uint32(asdu.Raw[pos+2])<<16
			pos += 3
		}

		dataLen := getDataLength(asdu.TypeID)
		if dataLen <= 0 {
			return
		}

		if pos+dataLen > len(asdu.Raw) {
			return // we finished
		}

		dataField := asdu.Raw[pos : pos+dataLen]
		pos += dataLen

		asdu.IOAs = append(asdu.IOAs, IOA{
			Address: ioa,
			Data:    append([]byte(nil), dataField...),
		})
	}
}

func parseASDU(data []byte) *ASDU {
	//  We only care about Type I, numbered information transfer (APCI I-frame control = 0)
	if len(data) == 0 || data[0]&0x01 != 0 {
		return nil
	}

	asdu := data[4:]
	a := &ASDU{
		TypeID: uint8(asdu[0]),
		NumIx:  asdu[1] & 0x7F, // 7 bits, number of objects
		SQ:     (asdu[1] & 0x80) != 0,
		Cause:  asdu[2],
		OA:     asdu[3],
		CA:     binary.LittleEndian.Uint16(asdu[4:6]),
		Raw:    asdu,
	}

	go parseIOAs(a)
	return a
}

func readASDUs(res *IEC104ScanResults, conn net.Conn, limit int) *zgrab2.ScanError {
	for i := 0; (limit <= 0) || i <= int(limit); i++ {
		data, err := getASDUData(conn)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return zgrab2.DetectScanError(err)
		}

		// maybe this is a channel?
		asdu := parseASDU(data)
		if asdu == nil {
			continue
		}

		res.Interrogation = append(res.Interrogation, asdu)
		if asdu.Cause == 10 {
			break
		}
	}
	return nil
}

func probeCA(res *IEC104ScanResults, conn net.Conn, caRanges [][]uint16, limit int) *zgrab2.ScanError {
	for _, caRange := range caRanges {
		for i := int(caRange[0]); i <= int(caRange[1]); i++ {
			apdu := makeInterrogationAPDU(uint16(i))
			if _, err := conn.Write(apdu); err != nil {
				return zgrab2.NewScanError(zgrab2.TryGetScanStatus(err), fmt.Errorf("send interrogation (%d)", i))
			}

			readASDUs(res, conn, limit)
		}
	}
	return nil
}
