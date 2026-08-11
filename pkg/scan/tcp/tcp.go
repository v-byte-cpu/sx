//go:generate go tool easyjson -output_filename result_easyjson.go tcp.go

package tcp

import (
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/v-byte-cpu/sx/pkg/scan"
)

const (
	SYNScanType   = "tcpsyn"
	FINScanType   = "tcpfin"
	NULLScanType  = "tcpnull"
	XmasScanType  = "tcpxmas"
	FlagsScanType = "tcpflags"
)

//easyjson:json
type ScanResult struct {
	ScanType string `json:"scan"`
	IP       string `json:"ip"`
	Port     uint16 `json:"port"`
	Flags    string `json:"flags,omitempty"`
}

func (r *ScanResult) String() string {
	width := 20
	if strings.ContainsRune(r.IP, ':') {
		width = 40
	}
	return fmt.Sprintf("%-*s %-5d %s", width, r.IP, r.Port, r.Flags)
}

func (r *ScanResult) ID() string {
	return net.JoinHostPort(r.IP, strconv.Itoa(int(r.Port)))
}

type PacketFilterFunc func(pkt *layers.TCP) bool
type PacketFlagsFunc func(pkt *layers.TCP) string

func TrueFilter(*layers.TCP) bool {
	return true
}

func EmptyFlags(*layers.TCP) string {
	return ""
}

func AllFlags(pkt *layers.TCP) string {
	var buf strings.Builder
	if pkt.SYN {
		buf.WriteRune('s')
	}
	if pkt.ACK {
		buf.WriteRune('a')
	}
	if pkt.FIN {
		buf.WriteRune('f')
	}
	if pkt.RST {
		buf.WriteRune('r')
	}
	if pkt.PSH {
		buf.WriteRune('p')
	}
	if pkt.URG {
		buf.WriteRune('u')
	}
	if pkt.ECE {
		buf.WriteRune('e')
	}
	if pkt.CWR {
		buf.WriteRune('c')
	}
	// NS bit, defined in RFC 3540, is now deprecated, see RFC 8311
	// however, still useful for recon ;)
	if pkt.NS {
		buf.WriteRune('n')
	}
	return buf.String()
}

type ScanMethod struct {
	scan.PacketSource
	scanType  string
	parser    *gopacket.DecodingLayerParser
	pktFilter PacketFilterFunc
	pktFlags  PacketFlagsFunc
	results   scan.ResultChan
	vpnMode   bool

	rcvDecoded []gopacket.LayerType
	rcvEth     layers.Ethernet
	rcvIP      layers.IPv4
	rcvIPv6    layers.IPv6
	rcvTCP     layers.TCP
	ipv6       bool
	zone       string
}

// Assert that tcp.ScanMethod conforms to the scan.PacketMethod interface
var _ scan.PacketMethod = (*ScanMethod)(nil)

type ScanMethodOption func(s *ScanMethod)

func WithPacketFilterFunc(pktFilter PacketFilterFunc) ScanMethodOption {
	return func(s *ScanMethod) {
		s.pktFilter = pktFilter
	}
}

func WithPacketFlagsFunc(pktFlags PacketFlagsFunc) ScanMethodOption {
	return func(s *ScanMethod) {
		s.pktFlags = pktFlags
	}
}

func WithScanVPNmode(vpnMode bool) ScanMethodOption {
	return func(s *ScanMethod) {
		s.vpnMode = vpnMode
	}
}

func WithScanIPv6(ipv6 bool) ScanMethodOption {
	return func(s *ScanMethod) { s.ipv6 = ipv6 }
}

func WithScanZone(zone string) ScanMethodOption {
	return func(s *ScanMethod) { s.zone = zone }
}

func NewScanMethod(scanType string, psrc scan.PacketSource,
	results scan.ResultChan, opts ...ScanMethodOption) *ScanMethod {
	sm := &ScanMethod{
		PacketSource: psrc,
		scanType:     scanType,
		results:      results,
		pktFilter:    TrueFilter,
		pktFlags:     AllFlags,
	}
	// options pattern
	for _, o := range opts {
		o(sm)
	}

	layerType := layers.LayerTypeEthernet
	if sm.vpnMode {
		if sm.ipv6 {
			layerType = layers.LayerTypeIPv6
		} else {
			layerType = layers.LayerTypeIPv4
		}
	}
	var parser *gopacket.DecodingLayerParser
	if sm.ipv6 {
		parser = gopacket.NewDecodingLayerParser(layerType, &sm.rcvEth, &sm.rcvIPv6, &sm.rcvTCP)
	} else {
		parser = gopacket.NewDecodingLayerParser(layerType, &sm.rcvEth, &sm.rcvIP, &sm.rcvTCP)
	}
	parser.IgnoreUnsupported = true
	sm.parser = parser
	return sm
}

func (s *ScanMethod) Results() <-chan scan.Result {
	return s.results.Chan()
}

func (s *ScanMethod) ProcessPacketData(data []byte, _ *gopacket.CaptureInfo) (err error) {
	if err = s.parser.DecodeLayers(data, &s.rcvDecoded); err != nil {
		return
	}
	if !s.validPacket() {
		return
	}

	if s.pktFilter(&s.rcvTCP) {
		srcIP := s.rcvIP.SrcIP
		if s.ipv6 {
			srcIP = s.rcvIPv6.SrcIP
		}
		address, _ := netip.AddrFromSlice(srcIP)
		if address.IsLinkLocalUnicast() && s.zone != "" {
			address = address.WithZone(s.zone)
		}
		s.results.Put(&ScanResult{
			ScanType: s.scanType,
			IP:       address.String(),
			Port:     uint16(s.rcvTCP.SrcPort),
			Flags:    s.pktFlags(&s.rcvTCP),
		})
	}
	return
}

func (s *ScanMethod) validPacket() bool {
	if s.ipv6 {
		return len(s.rcvDecoded) == 3 || (len(s.rcvDecoded) == 2 && s.rcvDecoded[0] == layers.LayerTypeIPv6)
	}
	return validPacket(s.rcvDecoded)
}

func validPacket(decoded []gopacket.LayerType) bool {
	return len(decoded) == 3 || (len(decoded) == 2 && decoded[0] == layers.LayerTypeIPv4)
}

type PacketFiller struct {
	SYN bool
	ACK bool
	FIN bool
	RST bool
	PSH bool
	URG bool
	ECE bool
	CWR bool
	NS  bool

	vpnMode       bool
	hopLimit      uint8
	nextHeader    layers.IPProtocol
	payloadLength uint16
}

// Assert that tcp.PacketFiller conforms to the scan.PacketFiller interface
var _ scan.PacketFiller = (*PacketFiller)(nil)

type PacketFillerOption func(f *PacketFiller)

func WithSYN() PacketFillerOption {
	return func(f *PacketFiller) {
		f.SYN = true
	}
}

func WithACK() PacketFillerOption {
	return func(f *PacketFiller) {
		f.ACK = true
	}
}

func WithFIN() PacketFillerOption {
	return func(f *PacketFiller) {
		f.FIN = true
	}
}

func WithRST() PacketFillerOption {
	return func(f *PacketFiller) {
		f.RST = true
	}
}

func WithPSH() PacketFillerOption {
	return func(f *PacketFiller) {
		f.PSH = true
	}
}

func WithURG() PacketFillerOption {
	return func(f *PacketFiller) {
		f.URG = true
	}
}

func WithECE() PacketFillerOption {
	return func(f *PacketFiller) {
		f.ECE = true
	}
}

func WithCWR() PacketFillerOption {
	return func(f *PacketFiller) {
		f.CWR = true
	}
}

func WithNS() PacketFillerOption {
	return func(f *PacketFiller) {
		f.NS = true
	}
}

func WithFillerVPNmode(vpnMode bool) PacketFillerOption {
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

func NewPacketFiller(opts ...PacketFillerOption) *PacketFiller {
	f := &PacketFiller{hopLimit: 64, nextHeader: layers.IPProtocolTCP}
	for _, o := range opts {
		o(f)
	}
	return f
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
		Id:       uint16(1 + rand.Intn(65535)),
		Flags:    layers.IPv4DontFragment,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    r.SrcIP.AsSlice(),
		DstIP:    r.DstIP.AsSlice(),
	}
	tcp := &layers.TCP{
		// emulate Linux default ephemeral ports range: 32768 60999
		// cat /proc/sys/net/ipv4/ip_local_port_range
		SrcPort: layers.TCPPort(32768 + rand.Intn(61000-32768)),
		DstPort: layers.TCPPort(r.DstPort),
		Seq:     rand.Uint32(),
		SYN:     f.SYN,
		ACK:     f.ACK,
		FIN:     f.FIN,
		RST:     f.RST,
		PSH:     f.PSH,
		URG:     f.URG,
		ECE:     f.ECE,
		CWR:     f.CWR,
		NS:      f.NS,
		Window:  64240,
		// emulate typical Linux TCP options
		Options: []layers.TCPOption{
			{
				OptionType:   layers.TCPOptionKindMSS,
				OptionLength: 4,
				OptionData:   []byte{0x05, 0xb4}, // 1460
			},
			{
				OptionType:   layers.TCPOptionKindSACKPermitted,
				OptionLength: 2,
			},
			{
				OptionType:   layers.TCPOptionKindWindowScale,
				OptionLength: 3,
				OptionData:   []byte{7},
			},
		},
	}
	if err = tcp.SetNetworkLayerForChecksum(ip); err != nil {
		return
	}
	opt := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if f.vpnMode {
		return gopacket.SerializeLayers(packet, opt, ip, tcp)
	}
	eth := &layers.Ethernet{
		SrcMAC:       r.SrcMAC,
		DstMAC:       r.DstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	return gopacket.SerializeLayers(packet, opt, eth, ip, tcp)
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
	tcp := f.newTCPLayer(r)
	if err := tcp.SetNetworkLayerForChecksum(ipv6); err != nil {
		return err
	}
	options := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: f.payloadLength == 0}
	layersToSerialize := []gopacket.SerializableLayer{ipv6, tcp}
	if !f.vpnMode {
		layersToSerialize = append([]gopacket.SerializableLayer{&layers.Ethernet{
			SrcMAC: r.SrcMAC, DstMAC: r.DstMAC, EthernetType: layers.EthernetTypeIPv6,
		}}, layersToSerialize...)
	}
	return gopacket.SerializeLayers(packet, options, layersToSerialize...)
}

func (f *PacketFiller) newTCPLayer(r *scan.Request) *layers.TCP {
	return &layers.TCP{
		SrcPort: layers.TCPPort(32768 + rand.Intn(61000-32768)),
		DstPort: layers.TCPPort(r.DstPort),
		Seq:     rand.Uint32(), SYN: f.SYN, ACK: f.ACK, FIN: f.FIN, RST: f.RST,
		PSH: f.PSH, URG: f.URG, ECE: f.ECE, CWR: f.CWR, NS: f.NS, Window: 64240,
		Options: []layers.TCPOption{
			{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}},
			{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
			{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{7}},
		},
	}
}
