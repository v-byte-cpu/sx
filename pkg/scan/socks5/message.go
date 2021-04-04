package socks5

import (
	"encoding/binary"
	"io"
)

const MethodNoAuth = 0

// MethodRequest is a negotiation request for the authentication method to be used.
// It is the initial message that the client sends to the SOCKS5 server.
// From RFC1928:
// +----+----------+----------+
// |VER | NMETHODS | METHODS  |
// +----+----------+----------+
// | 1  |    1     | 1 to 255 |
// +----+----------+----------+
type MethodRequest struct {
	Ver      byte // version of the protocol
	NMethods byte // number of method identifier octets that appear in the METHODS field.
	Methods  []byte
}

func NewMethodRequest(version byte, methods ...byte) *MethodRequest {
	return &MethodRequest{
		Ver:      version,
		NMethods: byte(len(methods)),
		Methods:  methods,
	}
}

func (r *MethodRequest) Len() int64 {
	return 2 + int64(r.NMethods)
}

func (r *MethodRequest) WriteTo(w io.Writer) (int64, error) {
	buf := make([]byte, 0, r.Len())
	buf = append(buf, r.Ver)
	buf = append(buf, r.NMethods)
	buf = append(buf, r.Methods...)
	n, err := w.Write(buf)
	return int64(n), err
}

// MethodReply is a negotiation reply for the authentication method to be used.
// From RFC1928:
// +----+--------+
// |VER | METHOD |
// +----+--------+
// | 1  |   1    |
// +----+--------+
type MethodReply struct {
	Ver    byte // version of the protocol
	Method byte // server selects from one of the methods given in the request METHODS field.
}

func (*MethodReply) Len() int64 {
	return 2
}

func (r *MethodReply) ReadFrom(in io.Reader) (int64, error) {
	return r.Len(), binary.Read(in, binary.BigEndian, r)
}
