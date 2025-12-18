package enip

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

// EtherNetIPMessage represents an EtherNet/IP protocol encapsulation message
// EtherNet/IP Encapsulation messages always use a 24-byte header format
// 2 bytes for command
// 2 bytes for length of additional data
// 4 bytes for session handle
// 4 bytes for response status
// 8 bytes for sender context
// 4 bytes for options (Reserved)
type EtherNetIPMessage struct {
	Command        uint16
	Length         uint16
	SessionHandle  uint32
	ResponseStatus uint32
	SenderContext  [8]byte
	Options        uint32
	AdditionalData []byte
}

var (
	ListIdentityRequest = EtherNetIPMessage{
		Command:        0x0063,
		Length:         0x0000,
		SessionHandle:  0x00000000,
		ResponseStatus: 0x00000000,
		SenderContext:  [8]byte{},
		Options:        0x00000000,
		AdditionalData: nil,
	}

	ListServicesRequest = EtherNetIPMessage{
		Command:        0x0004,
		Length:         0x0000,
		SessionHandle:  0x00000000,
		ResponseStatus: 0x00000000,
		SenderContext:  [8]byte{},
		Options:        0x00000000,
		AdditionalData: nil,
	}

	RegisterSession = EtherNetIPMessage{
		Command:        0x0065,
		Length:         0x0004,
		SessionHandle:  0x00000000,
		ResponseStatus: 0x00000000,
		SenderContext:  [8]byte{},
		Options:        0x00000000,
		AdditionalData: []byte{0x01, 0x00, 0x00, 0x00},
	}
)

func convertEtherNetIPCommandToByte(command EtherNetIPMessage) []byte {
	buffer := make([]byte, 24+len(command.AdditionalData))
	binary.LittleEndian.PutUint16(buffer[0:], command.Command)
	binary.LittleEndian.PutUint16(buffer[2:], command.Length)
	binary.LittleEndian.PutUint32(buffer[4:], command.SessionHandle)
	binary.LittleEndian.PutUint32(buffer[8:], command.ResponseStatus)
	copy(buffer[12:], command.SenderContext[:])
	binary.LittleEndian.PutUint32(buffer[20:], command.Options)
	copy(buffer[24:], command.AdditionalData)
	return buffer
}

func decodeEtherNetIPResponse(data []byte) (string, string, error) {
	if len(data) < 24 {
		return "", "", fmt.Errorf("response too short: expected at least 24 bytes, got %d", len(data))
	}

	command := binary.LittleEndian.Uint16(data[0:2])
	dlen := binary.LittleEndian.Uint16(data[2:4])
	raw := hex.EncodeToString(data)

	var senderContext [8]byte
	copy(senderContext[:], data[12:20])

	// Encapsulation header
	m := map[string]string{
		"command":        fmt.Sprint(command),
		"length":         fmt.Sprint(dlen),
		"session_handle": fmt.Sprint(binary.LittleEndian.Uint32(data[4:8])),
		"status":         fmt.Sprint(binary.LittleEndian.Uint32(data[8:12])),
		"sender_context": fmt.Sprint(senderContext),
		"options":        fmt.Sprint(binary.LittleEndian.Uint32(data[20:24])),
	}

	if len(data) < int(dlen)+24 {
		return "", raw, fmt.Errorf("response claims length %d but data is only %d bytes", dlen, len(data))
	}

	var (
		additionalData string
		decodeErr      error
	)

	payload := data[24 : 24+dlen]
	payloadHex := hex.EncodeToString(payload)
	switch command {
	case 0x0063:
		additionalData = safeDecode(DecodeListIdentityResponse, payloadHex)
	case 0x0004:
		additionalData = safeDecode(DecodeListServicesResponse, payloadHex)
	case 0x0065:
		additionalData = payloadHex
	default:
		additionalData = fmt.Sprintf("Unknown command 0x%04X Raw Payload: %s", command, payloadHex)
	}
	m["additional_data"] = additionalData

	s, err := json.Marshal(m)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse enip reponse: %v", err)
	}

	return string(s), raw, decodeErr
}

func safeDecode(fn func(string) (string, error), data string) (result string) {
	defer func() {
		if r := recover(); r != nil {
			result = fmt.Sprintf("Decoder panic: %v\nRaw Data: %s", r, data)
		}
	}()

	decoded, err := fn(data)
	if err != nil {
		return fmt.Sprintf("Decoder error: %v\nRaw Data: %s", err, data)
	}
	return decoded
}

func FindProductName(data []byte) string {
	start := -1
	for i := 0; i < len(data); i++ {
		if data[i] >= 0x20 && data[i] <= 0x7E {
			start = i
			break
		}
	}

	if start == -1 {
		return "Unknown Product"
	}

	productName := string(data[start:])
	productName = strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7E {
			return -1
		}
		return r
	}, productName)

	return productName
}

func DecodeListIdentityResponse(hexResponse string) (string, error) {
	data, err := hex.DecodeString(hexResponse)
	if err != nil {
		return "", fmt.Errorf("failed to decode hex string: %v", err)
	}
	if len(data) < 12 {
		return "", fmt.Errorf("data too short for identity header: %d bytes", len(data))
	}

	m := map[string]string{
		"vendor_id":     fmt.Sprint(binary.LittleEndian.Uint16(data[0:2])),
		"device_type":   fmt.Sprint(binary.LittleEndian.Uint16(data[2:4])),
		"product_code":  fmt.Sprint(binary.LittleEndian.Uint16(data[4:6])),
		"status":        fmt.Sprint(binary.LittleEndian.Uint16(data[6:8])),
		"serial_number": fmt.Sprint(binary.LittleEndian.Uint32(data[8:12])),
		"product_name":  FindProductName(data[12:]),
	}

	s, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("failed to convert ListIdentity response: %v", err)
	}
	return string(s), nil
}

func DecodeListServicesResponse(hexResponse string) (string, error) {
	data, err := hex.DecodeString(hexResponse)
	if err != nil {
		return "", fmt.Errorf("failed to decode hex: %v", err)
	}
	if len(data) < 2 {
		return "", fmt.Errorf("data too short for service count")
	}

	itemCount := binary.LittleEndian.Uint16(data[0:2])
	offset := 2
	var result strings.Builder
	result.WriteString(fmt.Sprintf("Service Count: %d\n", itemCount))

	for i := 0; i < int(itemCount); i++ {
		if offset+8 > len(data) {
			return "", fmt.Errorf("service item %d: header exceeds bounds", i)
		}

		typeID := binary.LittleEndian.Uint16(data[offset : offset+2])
		length := binary.LittleEndian.Uint16(data[offset+2 : offset+4])
		protocolVersion := binary.LittleEndian.Uint16(data[offset+4 : offset+6])
		capabilityFlags := binary.LittleEndian.Uint16(data[offset+6 : offset+8])
		offset += 8

		nameLength := int(length) - 4
		if offset+nameLength > len(data) {
			return "", fmt.Errorf("service item %d: service name exceeds bounds", i)
		}
		serviceName := string(data[offset : offset+nameLength])
		serviceName = strings.TrimRight(serviceName, "\x00")
		offset += nameLength

		m := map[string]string{
			"service":          fmt.Sprint(i + 1),
			"type_id":          fmt.Sprint(typeID),
			"length":           fmt.Sprint(length),
			"protocol_version": fmt.Sprint(protocolVersion),
			"capability_flags": fmt.Sprint(capabilityFlags),
			"service_name":     serviceName,
		}

		s, err := json.Marshal(m)
		if err != nil {
			return "", fmt.Errorf("failed to marshal ListServices response: %v", err)
		}
		result.WriteString(string(s))
	}
	return result.String(), nil
}

func IsValidEthernetIPHeaderListIdentity(resp []byte) bool {
	if len(resp) < 24 {
		return false
	}

	command := binary.LittleEndian.Uint16(resp[0:2])
	length := binary.LittleEndian.Uint16(resp[2:4])
	status := binary.LittleEndian.Uint32(resp[8:12])

	if command != 0x0063 {
		return false
	}

	if int(length) != len(resp[24:]) {
		return false
	}

	if status != 0 {
		return false
	}

	return true
}

func SendEtherNetIPMessage(conn net.Conn, msg EtherNetIPMessage) (string, string, error) {
	data := convertEtherNetIPCommandToByte(msg)
	_, err := conn.Write(data)
	if err != nil {
		return "", "", err
	}
	buffer := make([]byte, 256)
	n, err := conn.Read(buffer)
	if err != nil {
		return "", "", err
	}
	return decodeEtherNetIPResponse(buffer[:n])
}
