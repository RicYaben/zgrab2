package message

import "bytes"

type ContentFormat struct {
	Name      string
	StringRep string
}

var formats = map[uint16]ContentFormat{
	0:     {"TextPlain", "formatsxt/plain; charset=utf-8"},
	16:    {"AppCoseEncrypt0", "application/cose; cose-type=\"cose-encrypt0\""},
	17:    {"AppCoseMac0", "application/cose; cose-type=\"cose-mac0\""},
	18:    {"AppCoseSign1", "application/cose; cose-type=\"cose-sign1\""},
	40:    {"AppLinkFormat", "application/link-format"},
	41:    {"AppXML", "application/xml"},
	42:    {"AppOctets", "application/octet-stream"},
	47:    {"AppExi", "application/exi"},
	50:    {"AppJSON", "application/json"},
	51:    {"AppJSONPatch", "application/json-patch+json"},
	52:    {"AppJSONMergePatch", "application/merge-patch+json"},
	60:    {"AppCBOR", "application/cbor"},
	61:    {"AppCWT", "application/cwt"},
	96:    {"AppCoseEncrypt", "application/cose; cose-type=\"cose-encrypt\""},
	97:    {"AppCoseMac", "application/cose; cose-type=\"cose-mac\""},
	98:    {"AppCoseSign", "application/cose; cose-type=\"cose-sign\""},
	101:   {"AppCoseKey", "application/cose-key"},
	102:   {"AppCoseKeySet", "application/cose-key-set"},
	110:   {"AppSenmlJSON", "application/senml+json"},
	112:   {"AppSenmlCbor", "application/senml+cbor"},
	256:   {"AppCoapGroup", "coap-group+json"},
	320:   {"AppSenmlEtchJSON", "application/senml-etch+json"},
	322:   {"AppSenmlEtchCbor", "application/senml-etch+cbor"},
	10000: {"AppOcfCbor", "application/vnd.ocf+cbor"},
	11542: {"AppLwm2mTLV", "application/vnd.oma.lwm2m+tlv"},
	11543: {"AppLwm2mJSON", "application/vnd.oma.lwm2m+json"},
	11544: {"AppLwm2mCbor", "application/vnd.oma.lwm2m+cbor"},
}

type Payload struct {
	ContentFormat ContentFormat
	Body          []byte
	StringRep     string
}

func (p *Payload) Unmarshal(buf *bytes.Buffer, cType uint16) error {
	// set the content format if any
	p.ContentFormat = formats[cType]

	// set the raw body
	b := buf.Bytes()
	p.Body = b

	// parse the body. We just trim trailing empty values
	b = bytes.Trim(b, "\x00")
	p.StringRep = string(b)
	return nil
}
