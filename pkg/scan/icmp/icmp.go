//go:generate go tool easyjson -output_filename result_easyjson.go icmp.go

package icmp

import (
	"fmt"
	rand "math/rand/v2"
	"net"
	"net/netip"

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
	TTL      uint8     `json:"ttl,omitempty"`
	HopLimit uint8     `json:"hop_limit,omitempty"`
	ICMP     *Response `json:"icmp"`
}

func (r *ScanResult) String() string {
	ttl := r.TTL
	width := 20
	if r.HopLimit != 0 {
		ttl = r.HopLimit
		width = 40
	}
	return fmt.Sprintf("%-*s %-5d %-5d %-5d", width, r.IP, r.ICMP.Type, r.ICMP.Code, ttl)
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

func NewScanMethod(psrc scan.PacketSource, results scan.ResultChan, vpnMode bool, ipv6 ...bool) *ScanMethod {
	pp := NewPacketProcessor(ScanType, results, vpnMode, ipv6...)
	return newScanMethod(psrc, pp)
}

func NewScanMethodForFamily(psrc scan.PacketSource, results scan.ResultChan, vpnMode, ipv6 bool, zone string) *ScanMethod {
	return newScanMethod(psrc, newPacketProcessor(ScanType, results, vpnMode, ipv6, zone))
}

func newScanMethod(psrc scan.PacketSource, pp *PacketProcessor) *ScanMethod {
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
	rcvIPv6    layers.IPv6
	rcvICMP    layers.ICMPv4
	rcvICMPv6  layers.ICMPv6
	ipv6       bool
	zone       string
}

func NewPacketProcessor(scanType string, results scan.ResultChan, vpnMode bool, ipv6 ...bool) *PacketProcessor {
	isIPv6 := false
	if len(ipv6) > 0 {
		isIPv6 = ipv6[0]
	}
	return newPacketProcessor(scanType, results, vpnMode, isIPv6, "")
}

func NewPacketProcessorForFamily(scanType string, results scan.ResultChan, vpnMode, ipv6 bool, zone string) *PacketProcessor {
	return newPacketProcessor(scanType, results, vpnMode, ipv6, zone)
}

func newPacketProcessor(scanType string, results scan.ResultChan, vpnMode, ipv6 bool, zone string) *PacketProcessor {
	p := &PacketProcessor{scanType: scanType, results: results, ipv6: ipv6, zone: zone}

	layerType := layers.LayerTypeEthernet
	if vpnMode {
		if p.ipv6 {
			layerType = layers.LayerTypeIPv6
		} else {
			layerType = layers.LayerTypeIPv4
		}
	}
	var parser *gopacket.DecodingLayerParser
	if p.ipv6 {
		parser = gopacket.NewDecodingLayerParser(layerType, &p.rcvEth, &p.rcvIPv6, &p.rcvICMPv6)
	} else {
		parser = gopacket.NewDecodingLayerParser(layerType, &p.rcvEth, &p.rcvIP, &p.rcvICMP)
	}
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
	if !p.validPacket() {
		return
	}
	if p.ipv6 {
		address, _ := netip.AddrFromSlice(p.rcvIPv6.SrcIP)
		if address.IsLinkLocalUnicast() && p.zone != "" {
			address = address.WithZone(p.zone)
		}
		p.results.Put(&ScanResult{
			ScanType: p.scanType,
			IP:       address.String(),
			HopLimit: p.rcvIPv6.HopLimit,
			ICMP: &Response{
				Type: p.rcvICMPv6.TypeCode.Type(),
				Code: p.rcvICMPv6.TypeCode.Code(),
			},
		})
		return nil
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

func (p *PacketProcessor) validPacket() bool {
	if p.ipv6 {
		return len(p.rcvDecoded) == 3 || (len(p.rcvDecoded) == 2 && p.rcvDecoded[0] == layers.LayerTypeIPv6)
	}
	return validPacket(p.rcvDecoded)
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

	hopLimit      uint8
	nextHeader    layers.IPProtocol
	payloadLength uint16
	icmpv6Type    uint8
	icmpv6Code    uint8
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

func WithHopLimit(hopLimit uint8) PacketFillerOption {
	return func(f *PacketFiller) { f.hopLimit = hopLimit }
}

func WithNextHeader(nextHeader uint8) PacketFillerOption {
	return func(f *PacketFiller) { f.nextHeader = layers.IPProtocol(nextHeader) }
}

func WithPayloadLength(payloadLength uint16) PacketFillerOption {
	return func(f *PacketFiller) { f.payloadLength = payloadLength }
}

func WithICMPv6Type(typ uint8) PacketFillerOption {
	return func(f *PacketFiller) { f.icmpv6Type = typ }
}

func WithICMPv6Code(code uint8) PacketFillerOption {
	return func(f *PacketFiller) { f.icmpv6Code = code }
}

func NewPacketFiller(opts ...PacketFillerOption) *PacketFiller {
	payload := make([]byte, 48)
	fillRandomPayload(payload)
	f := &PacketFiller{
		// typical TTL value for Linux
		ttl:        64,
		proto:      layers.IPProtocolICMPv4,
		flags:      layers.IPv4DontFragment,
		typ:        layers.ICMPv4TypeEchoRequest,
		code:       0,
		payload:    payload,
		hopLimit:   64,
		nextHeader: layers.IPProtocolICMPv6,
		icmpv6Type: layers.ICMPv6TypeEchoRequest,
	}
	for _, o := range opts {
		o(f)
	}
	return f
}

func fillRandomPayload(payload []byte) {
	for i := range payload {
		payload[i] = byte(rand.IntN(256))
	}
}

func (f *PacketFiller) Fill(packet gopacket.SerializeBuffer, r *scan.Request) (err error) {
	if r.DstIP.Is6() {
		return f.fillIPv6(packet, r)
	}

	ip := &layers.IPv4{
		Version: 4,
		// actually Linux kernel uses more complicated algorithm for ip id generation,
		// see __ip_select_ident function in net/ipv4/route.c
		// but we don't care and just spoof it ;)
		Id:    uint16(1 + rand.IntN(65535)),
		Flags: f.flags,
		// Typical 20 bytes IP header length
		IHL:      5,
		TTL:      f.ttl,
		Length:   f.length,
		Protocol: f.proto,
		SrcIP:    r.SrcIP.AsSlice(),
		DstIP:    r.DstIP.AsSlice(),
	}

	icmp := &layers.ICMPv4{
		Id:       uint16(1 + rand.IntN(65535)),
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

func (f *PacketFiller) fillIPv6(packet gopacket.SerializeBuffer, r *scan.Request) error {
	ipv6 := &layers.IPv6{
		Version:    6,
		Length:     f.payloadLength,
		NextHeader: f.nextHeader,
		HopLimit:   f.hopLimit,
		SrcIP:      net.IP(r.SrcIP.WithZone("").AsSlice()),
		DstIP:      net.IP(r.DstIP.WithZone("").AsSlice()),
	}
	icmpv6 := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(f.icmpv6Type, f.icmpv6Code)}
	if err := icmpv6.SetNetworkLayerForChecksum(ipv6); err != nil {
		return err
	}
	options := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: f.payloadLength == 0}
	layersToSerialize := []gopacket.SerializableLayer{ipv6, icmpv6, gopacket.Payload(f.payload)}
	if !f.vpnMode {
		layersToSerialize = append([]gopacket.SerializableLayer{&layers.Ethernet{
			SrcMAC: r.SrcMAC, DstMAC: r.DstMAC, EthernetType: layers.EthernetTypeIPv6,
		}}, layersToSerialize...)
	}
	return gopacket.SerializeLayers(packet, options, layersToSerialize...)
}
