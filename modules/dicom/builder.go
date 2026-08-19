package dicom

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

// TODO: idially we would just wrap and unwrap messages from the packet structure instead
// of storing lengths everywere. I leave this for future rewrites. The same goes for types,
// just create an interface with bytes and wrap functions.
type PDUType uint8

const (
	ASSOC_RQ     PDUType = 1
	ASSOC_ACCEPT PDUType = 2
	ASSOC_REJECT PDUType = 3
	DATA         PDUType = 4
)

// 64KiB -- correct 16384
const MaxPDULength = 16384

type PDUMsg interface {
	bytes() []byte
}

type PDVFlag interface {
	bytes() []byte
}

type PDVCommand struct {
	GroupTag   uint16
	ElementTag uint16
	Length     uint32 // we only keep this value for sanity
	Value      []byte
}

func newPDVCommand(group, tag uint16, value []byte) *PDVCommand {
	// value is always an even number of bytes
	if len(value)%2 != 0 {
		value = append(value, 0x00)
	}

	return &PDVCommand{group, tag, uint32(len(value)), value}
}

func (cmd *PDVCommand) bytes() []byte {
	buf := make([]byte, 0, cmd.Length+8)
	w := bytes.NewBuffer(buf)

	if err := binary.Write(w, binary.LittleEndian, cmd.GroupTag); err != nil {
		panic(fmt.Errorf("failed to write group tag to buffer: %w", err))
	}

	if err := binary.Write(w, binary.LittleEndian, cmd.ElementTag); err != nil {
		panic(fmt.Errorf("failed to write element tag to buffer: %w", err))
	}

	if err := binary.Write(w, binary.LittleEndian, cmd.Length); err != nil {
		panic(fmt.Errorf("failed to write length to buffer: %w", err))
	}

	if _, err := w.Write(cmd.Value); err != nil {
		panic(fmt.Errorf("failed to write value to buffer: %w", err))
	}

	return w.Bytes()
}

type CFINDRQData struct {
	GroupTag   uint16
	ElementTag uint16
	VR         string
	Value      []byte
}

func (cmd *CFINDRQData) bytes() []byte {
	value := cmd.Value

	// Pad odd-length values according to VR.
	if len(value)%2 != 0 {
		value = append(value, 0x00)
	}

	var w bytes.Buffer

	if err := binary.Write(&w, binary.LittleEndian, cmd.GroupTag); err != nil {
		panic(fmt.Errorf("failed to write group tag: %w", err))
	}

	if err := binary.Write(&w, binary.LittleEndian, cmd.ElementTag); err != nil {
		panic(fmt.Errorf("failed to write element tag: %w", err))
	}

	if _, err := w.WriteString(cmd.VR); err != nil {
		panic(fmt.Errorf("failed to write VR: %w", err))
	}

	if err := binary.Write(&w, binary.LittleEndian, uint16(len(value))); err != nil {
		panic(fmt.Errorf("failed to write value length: %w", err))
	}

	if _, err := w.Write(value); err != nil {
		panic(fmt.Errorf("failed to write value: %w", err))
	}

	return w.Bytes()
}

type PDV struct {
	Legnth   uint32 // we only keep this value for sanity
	Context  uint8
	Flags    uint8
	Commands []PDVFlag
	// NOTE: we dont care about the dataset!
}

func (p *PDV) bytes() []byte {
	buf := make([]byte, 0, p.Legnth)
	w := bytes.NewBuffer(buf)
	if err := binary.Write(w, binary.BigEndian, p.Legnth); err != nil {
		panic(fmt.Errorf("failed to write to buffer: %w", err))
	}

	if _, err := w.Write([]byte{p.Context, p.Flags}); err != nil {
		panic(fmt.Errorf("failed to write to buffer: %w", err))
	}

	for _, cmd := range p.Commands {
		w.Write(cmd.bytes())
	}

	return w.Bytes()
}

func (p *PDV) addHead(buf *bytes.Buffer) {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(buf.Len()))
	head := newPDVCommand(0, 0, b)
	p.Commands = append([]PDVFlag{head}, p.Commands...)

	if _, err := buf.Write(head.bytes()); err != nil {
		panic(fmt.Errorf("failed to write to buffer: %w", err))
	}
}

func (p *PDV) setLength(cmd bool) *PDV {
	var w bytes.Buffer
	for _, cmd := range p.Commands {
		w.Write(cmd.bytes())
	}

	if cmd {
		p.addHead(&w)
	}

	p.Legnth = uint32(w.Len() + 2)
	return p
}

type PDUHeader struct {
	PDUType PDUType
	Length  uint32 // we only keep this value for sanity
}

func (h *PDUHeader) bytes() []byte {
	buf := make([]byte, 0)
	w := bytes.NewBuffer(buf)

	if _, err := w.Write([]byte{uint8(h.PDUType), 0x00}); err != nil {
		panic(fmt.Errorf("failed to write to buffer: %w", err))
	}

	if err := binary.Write(w, binary.BigEndian, h.Length); err != nil {
		panic(fmt.Errorf("failed to write to buffer: %w", err))
	}
	return w.Bytes()
}

type PDU struct {
	Header *PDUHeader
	Msg    PDUMsg
}

func newPDU(t PDUType) *PDU {
	return &PDU{
		Header: &PDUHeader{
			PDUType: t,
		},
	}
}

func (p *PDU) withMessage(msg PDUMsg) *PDU {
	p.Header.Length = uint32(len(msg.bytes()))
	p.Msg = msg
	return p
}

func (pdu *PDU) readHeader(data io.Reader) error {
	buf := make([]byte, 6)
	if _, err := data.Read(buf); err != nil {
		return fmt.Errorf("failed to read header bytes: %v", err)
	}

	pdu.Header = &PDUHeader{
		PDUType: PDUType(buf[0]),
		Length:  binary.BigEndian.Uint32(buf[2:6]),
	}
	return nil
}

func (pdu *PDU) parseAssociationMsg(data []byte) (*AAssociate, error) {
	trimString := func(b []byte) string {
		return strings.TrimRight(string(b), " \x00")
	}

	assoc := &AAssociate{
		ProtocolVersion: binary.BigEndian.Uint16(data[0:2]),
		CalledAETitle:   trimString(data[4:20]),
		CallingAETitle:  trimString(data[20:37]),
	}

	// 36 from the calling AE title + 32 reserved bytes
	i := 68
	for i+4 <= len(data) {
		iType := data[i]
		iLength := int(binary.BigEndian.Uint16(data[i+2 : i+4]))
		iValue := data[i+4 : i+4+int(iLength)]

		switch iType {
		// Application Context
		case 0x10:
			assoc.ApplicationContext = string(iValue)

		// Presentation context
		case 0x20, 0x21:
			buf := bytes.NewReader(iValue[4:])
			ps := newPresentationContext(iValue[0], iValue[2])

			for buf.Len() > 0 {
				item, err := parseItem(buf)
				if err != nil {
					return nil, fmt.Errorf("fialed to parse Presentation Context Item %w", err)
				}
				ps.Items = append(ps.Items, item)
			}
			assoc.PresentationContext = ps

		// User Info
		case 0x50:
			buf := bytes.NewReader(iValue)
			uInfo := newUserInfo()

			for buf.Len() > 0 {
				item, err := parseItem(buf)
				if err != nil {
					return nil, fmt.Errorf("failed to parse User Info Item: %w", err)
				}
				uInfo.Items = append(uInfo.Items, item)
			}
			assoc.UserInfo = uInfo
		}
		// sum 4 (iType + len) to the Item length
		i += 4 + iLength
	}

	return assoc, nil
}

func (pdu *PDU) parseDataMsg(data []byte) (*PDV, error) {
	if len(data) < 6 {
		return nil, errors.New("data too short to contain valid PDU header")
	}

	buf := bytes.NewReader(data)

	var length uint32
	if err := binary.Read(buf, binary.BigEndian, &length); err != nil {
		return nil, fmt.Errorf("failed to read PDU length: %w", err)
	}

	// Length must be at least 2 for ctx + flags
	if length < 2 {
		return nil, fmt.Errorf("invalid PDU length: %d", length)
	}

	ctx, err := buf.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read context ID: %w", err)
	}

	flags, err := buf.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read flags: %w", err)
	}

	cmdLen := int(length - 2)
	if buf.Len() < cmdLen {
		return nil, fmt.Errorf("not enough data to read PDU commands: want %d, have %d", cmdLen, buf.Len())
	}

	cmds := make([]byte, cmdLen)
	if _, err := io.ReadFull(buf, cmds); err != nil {
		return nil, fmt.Errorf("failed to read PDU commands: %w", err)
	}

	pdv := &PDV{
		Legnth:   uint32(len(cmds) + 2), // cms + ctx & flags
		Context:  ctx,
		Flags:    flags,
		Commands: []PDVFlag{},
	}

	r := bytes.NewReader(cmds)
	for r.Len() >= 8 {
		var tagGroup, tagElem uint16
		var length uint32

		if err := binary.Read(r, binary.LittleEndian, &tagGroup); err != nil {
			return nil, fmt.Errorf("failed to read tag group: %w", err)
		}
		if err := binary.Read(r, binary.LittleEndian, &tagElem); err != nil {
			return nil, fmt.Errorf("failed to read tag element: %w", err)
		}
		if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
			return nil, fmt.Errorf("failed to read element length: %w", err)
		}

		if uint32(r.Len()) < length {
			return nil, fmt.Errorf("element length (%d) exceeds remaining buffer (%d)", length, r.Len())
		}

		value := make([]byte, length)
		if _, err := io.ReadFull(r, value); err != nil {
			return nil, fmt.Errorf("failed to read element value: %w", err)
		}

		pdv.Commands = append(pdv.Commands, newPDVCommand(tagGroup, tagElem, value))
	}

	return pdv, nil
}

func (pdu *PDU) readMessage(data io.Reader) error {
	buff := make([]byte, pdu.Header.Length)
	if _, err := io.ReadFull(data, buff); err != nil {
		return fmt.Errorf("failed to read message bytes: %w", err)
	}

	switch pdu.Header.PDUType {
	case ASSOC_REJECT:
		return ErrAssociationReject
	case ASSOC_RQ, ASSOC_ACCEPT:
		msg, err := pdu.parseAssociationMsg(buff)
		if err != nil {
			return fmt.Errorf("failed to parse association message: %w", err)
		}
		pdu.Msg = msg
	case DATA:
		msg, err := pdu.parseDataMsg(buff)
		if err != nil {
			return fmt.Errorf("failed to parse association message: %w", err)
		}
		pdu.Msg = msg
	default:
		return fmt.Errorf("unable to parse PDU type %x", pdu.Header.PDUType)
	}
	return nil
}

func parsePDU(data io.Reader) (*PDU, error) {
	pdu := &PDU{}

	if err := pdu.readHeader(data); err != nil {
		return nil, fmt.Errorf("failed to parse PDU header: %w", err)
	}

	if pdu.Header.Length > MaxPDULength {
		return nil, fmt.Errorf("PDU too large: expected < %d, got %d", MaxPDULength, pdu.Header.Length)
	}

	if err := pdu.readMessage(data); err != nil {
		return nil, fmt.Errorf("failed to parse PDU content: %w", err)
	}

	return pdu, nil
}

func (pdu *PDU) bytes() []byte {
	w := new(bytes.Buffer)
	w.Write(pdu.Header.bytes())
	w.Write(pdu.Msg.bytes())
	return w.Bytes()
}

type TransferSyntax struct {
	IType uint8
	Value string
}

type PresentationContext struct {
	Type      uint8
	ContextID uint8
	Result    uint8
	Items     []*Item
}

func newPresentationContext(id, result uint8) *PresentationContext {
	return &PresentationContext{
		Type:      0x20,
		ContextID: id,
		Result:    result,
		Items:     []*Item{},
	}
}

func (p *PresentationContext) bytes() []byte {
	var tsW bytes.Buffer
	for _, ts := range p.Items {
		tsW.Write(ts.bytes())
	}

	buf := make([]byte, 0, 4+tsW.Len())
	w := bytes.NewBuffer(buf)

	// NOTE: those panics should never occur, but lint rules
	if _, err := w.Write([]byte{p.Type, 0x00}); err != nil {
		panic(fmt.Errorf("failed to write to buffer: %w", err))
	}

	if err := binary.Write(w, binary.BigEndian, uint16(tsW.Len()+4)); err != nil {
		panic(fmt.Errorf("failed to write to buffer: %w", err))
	}

	if _, err := w.Write([]byte{
		p.ContextID, 0x00,
		p.Result, 0x00,
	}); err != nil {
		panic(fmt.Errorf("failed to write to buffer: %w", err))
	}

	if _, err := w.Write(tsW.Bytes()); err != nil {
		panic(fmt.Errorf("failed to write to buffer: %w", err))
	}
	return w.Bytes()
}

type Item struct {
	Type   uint8
	Length uint16
	Value  []byte
}

func parseItem(data io.Reader) (*Item, error) {
	i := Item{}

	bType := make([]byte, 2)
	if _, err := data.Read(bType); err != nil {
		return nil, fmt.Errorf("failed to read Item Type: %w", err)
	}
	i.Type = uint8(bType[0])

	bLength := make([]byte, 2)
	if _, err := data.Read(bLength); err != nil {
		return nil, fmt.Errorf("failed to read Item Length: %w", err)
	}
	i.Length = binary.BigEndian.Uint16(bLength)

	bValue := make([]byte, i.Length)
	if _, err := data.Read(bValue); err != nil {
		return nil, fmt.Errorf("failed to read Item Value: %w", err)
	}
	i.Value = bValue

	return &i, nil
}

func newItem(t uint8, value []byte) *Item {
	return &Item{
		Type:   t,
		Length: uint16(len(value)),
		Value:  value,
	}
}

func (i *Item) bytes() []byte {
	var buf bytes.Buffer
	if _, err := buf.Write([]byte{i.Type, 0x00}); err != nil {
		panic(fmt.Errorf("failed to write to buffer: %w", err))
	}

	if err := binary.Write(&buf, binary.BigEndian, i.Length); err != nil {
		panic(fmt.Errorf("failed to write to buffer: %w", err))
	}

	if _, err := buf.Write(i.Value); err != nil {
		panic(fmt.Errorf("failed to write to buffer: %w", err))
	}

	return buf.Bytes()
}

type UserInfo struct {
	Type  uint8
	Items []*Item
}

func newUserInfo() *UserInfo {
	return &UserInfo{
		Type: 0x50, // Item Type = 0x50 (User Info)
	}
}

func (u *UserInfo) bytes() []byte {
	var buf bytes.Buffer

	for _, it := range u.Items {
		buf.Write(it.bytes())
	}

	var w bytes.Buffer

	// Item Type
	w.WriteByte(u.Type)

	// Reserved
	w.WriteByte(0x00)

	// Item Length
	if err := binary.Write(&w, binary.BigEndian, uint16(buf.Len())); err != nil {
		panic(fmt.Errorf("failed to write item length: %w", err))
	}

	// Item contents
	if _, err := w.Write(buf.Bytes()); err != nil {
		panic(fmt.Errorf("failed to write user info: %w", err))
	}

	return w.Bytes()
}

type AAssociate struct {
	ProtocolVersion     uint16
	CallingAETitle      string
	CalledAETitle       string
	ApplicationContext  string
	PresentationContext *PresentationContext
	UserInfo            *UserInfo
}

func makeAAssociateRQ(msgID uint8, callingAETitle, calledAETitle, impUID, impVName string) *AAssociate {
	uInfo := newUserInfo()

	maxPDULength := make([]byte, 4)
	binary.BigEndian.PutUint32(maxPDULength, MaxPDULength)

	uInfo.Items = []*Item{
		newItem(0x51, maxPDULength),
		// <root>.<project>.<component>.<major>.<minor>
		newItem(0x52, []byte(impUID)),
		newItem(0x55, []byte(impVName)),
	}

	return &AAssociate{
		ProtocolVersion:     1,
		CallingAETitle:      callingAETitle,
		CalledAETitle:       calledAETitle,
		ApplicationContext:  "1.2.840.10008.3.1.1.1",
		PresentationContext: newPresentationContext(msgID, 0xff),
		UserInfo:            uInfo,
	}
}

func (a *AAssociate) addTransferSyntax(iType uint8, value string) *AAssociate {
	a.PresentationContext.Items = append(a.PresentationContext.Items, newItem(iType, []byte(value)))
	return a
}

func (a *AAssociate) header() []byte {
	buf := make([]byte, 0, 68)

	w := bytes.NewBuffer(buf)
	if err := binary.Write(w, binary.BigEndian, a.ProtocolVersion); err != nil {
		panic(fmt.Errorf("failed to write to buffer: %w", err))
	}

	if _, err := w.Write([]byte{0x00, 0x00}); err != nil {
		panic(fmt.Errorf("failed to write to buffer: %w", err))
	}

	calledAETitle := [16]byte{}
	callingAETitle := [16]byte{}

	// Fill with spaces (0x20)
	for i := 0; i < 16; i++ {
		calledAETitle[i] = 0x20
		callingAETitle[i] = 0x20
	}

	// Copy AE titles (truncate if longer than 16)
	copy(calledAETitle[:], []byte(a.CalledAETitle))
	copy(callingAETitle[:], []byte(a.CallingAETitle))

	if _, err := w.Write(calledAETitle[:]); err != nil {
		panic(fmt.Errorf("failed to write to buffer: %w", err))
	}

	if _, err := w.Write(callingAETitle[:]); err != nil {
		panic(fmt.Errorf("failed to write to buffer: %w", err))
	}

	if _, err := w.Write(make([]byte, 32)); err != nil {
		panic(fmt.Errorf("failed to write to buffer: %w", err))
	}

	return w.Bytes()
}

func (a *AAssociate) applicationContext() []byte {
	buf := make([]byte, 0, len(a.ApplicationContext)+4)
	w := bytes.NewBuffer(buf)
	if _, err := w.Write([]byte{0x10, 0x00}); err != nil {
		panic(fmt.Errorf("failed to write to buffer: %w", err))
	}

	if err := binary.Write(w, binary.BigEndian, uint16(len(a.ApplicationContext))); err != nil {
		panic(fmt.Errorf("failed to write to buffer: %w", err))
	}

	if _, err := w.Write([]byte(a.ApplicationContext)); err != nil {
		panic(fmt.Errorf("failed to write to buffer: %w", err))
	}
	return w.Bytes()
}

func (a *AAssociate) bytes() []byte {
	var buf bytes.Buffer

	for _, data := range [][]byte{
		a.header(),
		a.applicationContext(),
		a.PresentationContext.bytes(),
		a.UserInfo.bytes(),
	} {
		if _, err := buf.Write(data); err != nil {
			panic(fmt.Errorf("failed to write to buffer: %w", err))
		}
	}

	return buf.Bytes()
}

func makeCEchoRQ(msgID uint16) *PDV {
	commands := append(
		[]PDVFlag{},
		newPDVCommand(0, 0x0002, []byte("1.2.840.10008.1.1")),
		newPDVCommand(0, 0x0100, []byte{0x30, 0x00}),
		newPDVCommand(0, 0x0110, []byte{byte(msgID) >> 0, byte(msgID) >> 1}),
		newPDVCommand(0, 0x0800, []byte{0x01, 0x01}),
	)

	pdv := &PDV{
		Legnth:   0,
		Context:  0x01,
		Flags:    0x03,
		Commands: commands,
	}
	pdv.setLength(true)
	return pdv
}

type Key struct {
	Group uint16
	Tag   uint16
	VR    string
}

// We do not support more of these since they may reveal PII
// source: https://dicom.nema.org/medical/dicom/current/output/html/part04.html#sect_C.6
// NOTE: supporting newer keys may result in fewer results
// Use StudyDate=01010001 for a simple test of whether the server responds to queries
// Include PatientID, and NumberOfPatientRelated* to enumerate patient studies/series/instances
// this is valuable to determine the activity or volume of the server
var StudyKeys = map[string]Key{
	"QueryRetrieveLevel": {0x0008, 0x0052, "CS"},
	//"StudyDate": {0x0008, 0x0020, }
	"PatientID": {0x0010, 0x0020, "LO"},
}

type SOPClassUID string

const (
	// NOTE: we won't support PATIENT, SERIES, or IMAGE for now
	STUDY SOPClassUID = "1.2.840.10008.5.1.4.1.2.2.1"
)

type keyFactory map[string]Key

func getSOPClassUID(model string) (SOPClassUID, keyFactory) {
	model = strings.ToUpper(model)
	switch model {
	case "STUDY":
		return STUDY, StudyKeys
	case "PATIENT", "SERIES", "IMAGE":
		panic("unsupported model: " + model)
	default:
		panic("unknown model: " + model)
	}
}

func cFindPDV1(msgID uint16, uid SOPClassUID) *PDV {
	cmd := append(
		[]PDVFlag{},
		newPDVCommand(0, 0x0002, []byte(uid)),
		newPDVCommand(0, 0x0100, []byte{0x20, 0x00}),
		newPDVCommand(0, 0x0110, []byte{byte(msgID) >> 0, byte(msgID) >> 1}),
		newPDVCommand(0, 0x0700, []byte{0x00, 0x00}),
		newPDVCommand(0, 0x0800, []byte{0x01, 0x00}),
	)

	pdv := &PDV{
		Legnth:   0,
		Context:  0x01,
		Flags:    0x03,
		Commands: cmd,
	}
	pdv.setLength(true)
	return pdv
}

func cFindPDV2(keys []string, f keyFactory) *PDV {
	cmd := []PDVFlag{}
	for _, key := range keys {
		// split the key by '=', always 2 parts even if there is no '='
		k, v, _ := strings.Cut(key, "=")
		if t, ok := f[k]; ok {
			cmd = append(cmd, &CFINDRQData{t.Group, t.Tag, t.VR, []byte(v)})
		}
	}

	pdv := &PDV{
		Legnth:   0,
		Context:  0x01,
		Flags:    0x02,
		Commands: cmd,
	}
	pdv.setLength(false)
	return pdv
}

func makeCFindRQ(msgID uint16, model string, keys []string) (*PDV, *PDV) {
	uid, factory := getSOPClassUID(model)
	pdv1 := cFindPDV1(msgID, uid)
	pdv2 := cFindPDV2(keys, factory)
	return pdv1, pdv2
}
