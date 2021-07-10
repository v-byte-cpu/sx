//go:generate easyjson -output_filename result_easyjson.go icmp.go

package icmp

import (
	"fmt"
	"math/rand"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/v-byte-cpu/sx/pkg/packet"
	"github.com/v-byte-cpu/sx/pkg/scan"
)

const ScanType = "icmp"

type Response struct {
	Type uint8 `json:"type"`
	Code uint8 `json:"code"`
}

//easyjson:json
type ScanResult struct {
	ScanType string    `json:"scan"`
	IP       string    `json:"ip"`
	TTL      uint8     `json:"ttl"`
	ICMP     *Response `json:"icmp"`
}

func (r *ScanResult) String() string {
	return fmt.Sprintf("%-20s %-5d %-5d %-5d", r.IP, r.ICMP.Type, r.ICMP.Code, r.TTL)
}

func (r *ScanResult) ID() string {
	return r.IP
}

type ScanMethod struct {
	scan.PacketSource
	packet.Processor
	scan.Resulter
}

// Assert that icmp.ScanMethod conforms to the scan.PacketMethod interface
var _ scan.PacketMethod = (*ScanMethod)(nil)

func NewScanMethod(psrc scan.PacketSource, results scan.ResultChan, vpnMode bool) *ScanMethod {
	pp := NewPacketProcessor(ScanType, results, vpnMode)
	return &ScanMethod{
		PacketSource: psrc,
		Processor:    pp,
		Resulter:     pp,
	}
}

type PacketProcessor struct {
	scanType string
	results  scan.ResultChan
	parser   *gopacket.DecodingLayerParser

	rcvDecoded []gopacket.LayerType
	rcvEth     layers.Ethernet
	rcvIP      layers.IPv4
	rcvICMP    layers.ICMPv4
}

func NewPacketProcessor(scanType string, results scan.ResultChan, vpnMode bool) *PacketProcessor {
	p := &PacketProcessor{scanType: scanType, results: results}

	layerType := layers.LayerTypeEthernet
	if vpnMode {
		layerType = layers.LayerTypeIPv4
	}
	parser := gopacket.NewDecodingLayerParser(layerType, &p.rcvEth, &p.rcvIP, &p.rcvICMP)
	parser.IgnoreUnsupported = true
	p.parser = parser
	return p
}

func (p *PacketProcessor) Results() <-chan scan.Result {
	return p.results.Chan()
}

func (p *PacketProcessor) ProcessPacketData(data []byte, _ *gopacket.CaptureInfo) (err error) {
	if err = p.parser.DecodeLayers(data, &p.rcvDecoded); err != nil {
		return
	}
	if !validPacket(p.rcvDecoded) {
		return
	}

	p.results.Put(&ScanResult{
		ScanType: p.scanType,
		IP:       p.rcvIP.SrcIP.String(),
		TTL:      p.rcvIP.TTL,
		ICMP: &Response{
			Type: p.rcvICMP.TypeCode.Type(),
			Code: p.rcvICMP.TypeCode.Code(),
		},
	})
	return
}

func validPacket(decoded []gopacket.LayerType) bool {
	return len(decoded) == 3 || (len(decoded) == 2 && decoded[0] == layers.LayerTypeIPv4)
}

type PacketFiller struct {
	ttl     uint8
	length  uint16
	proto   layers.IPProtocol
	flags   layers.IPv4Flag
	typ     uint8
	code    uint8
	payload []byte
	vpnMode bool
}

// Assert that icmp.PacketFiller conforms to the scan.PacketFiller interface
var _ scan.PacketFiller = (*PacketFiller)(nil)

type PacketFillerOption func(f *PacketFiller)

func WithTTL(ttl uint8) PacketFillerOption {
	return func(f *PacketFiller) {
		f.ttl = ttl
	}
}

func WithIPTotalLength(length uint16) PacketFillerOption {
	return func(f *PacketFiller) {
		f.length = length
	}
}

func WithIPProtocol(proto uint8) PacketFillerOption {
	return func(f *PacketFiller) {
		f.proto = layers.IPProtocol(proto)
	}
}

func WithIPFlags(flags uint8) PacketFillerOption {
	return func(f *PacketFiller) {
		f.flags = layers.IPv4Flag(flags)
	}
}

func WithType(typ uint8) PacketFillerOption {
	return func(f *PacketFiller) {
		f.typ = typ
	}
}

func WithCode(code uint8) PacketFillerOption {
	return func(f *PacketFiller) {
		f.code = code
	}
}

func WithPayload(payload []byte) PacketFillerOption {
	return func(f *PacketFiller) {
		data := make([]byte, len(payload))
		copy(data, payload)
		f.payload = data
	}
}

func WithVPNmode(vpnMode bool) PacketFillerOption {
	return func(f *PacketFiller) {
		f.vpnMode = vpnMode
	}
}

func NewPacketFiller(opts ...PacketFillerOption) *PacketFiller {
	payload := make([]byte, 48)
	rand.Read(payload)
	f := &PacketFiller{
		// typical TTL value for Linux
		ttl:     64,
		proto:   layers.IPProtocolICMPv4,
		flags:   layers.IPv4DontFragment,
		typ:     layers.ICMPv4TypeEchoRequest,
		code:    0,
		payload: payload,
	}
	for _, o := range opts {
		o(f)
	}
	return f
}

func (f *PacketFiller) Fill(packet gopacket.SerializeBuffer, r *scan.Request) (err error) {

	ip := &layers.IPv4{
		Version: 4,
		// actually Linux kernel uses more complicated algorithm for ip id generation,
		// see __ip_select_ident function in net/ipv4/route.c
		// but we don't care and just spoof it ;)
		Id:    uint16(1 + rand.Intn(65535)),
		Flags: f.flags,
		// Typical 20 bytes IP header length
		IHL:      5,
		TTL:      f.ttl,
		Length:   f.length,
		Protocol: f.proto,
		SrcIP:    r.SrcIP,
		DstIP:    r.DstIP,
	}

	icmp := &layers.ICMPv4{
		Id:       uint16(1 + rand.Intn(65535)),
		Seq:      1,
		TypeCode: layers.CreateICMPv4TypeCode(f.typ, f.code),
	}

	opt := gopacket.SerializeOptions{ComputeChecksums: true}
	if ip.Length == 0 {
		opt.FixLengths = true
	}

	if f.vpnMode {
		return gopacket.SerializeLayers(packet, opt, ip, icmp, gopacket.Payload(f.payload))
	}
	eth := &layers.Ethernet{
		SrcMAC:       r.SrcMAC,
		DstMAC:       r.DstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	return gopacket.SerializeLayers(packet, opt, eth, ip, icmp, gopacket.Payload(f.payload))
}
