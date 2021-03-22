//go:generate easyjson -output_filename result_easyjson.go tcp.go

package tcp

import (
	"fmt"
	"math/rand"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/v-byte-cpu/sx/pkg/scan"
)

const (
	SYNScanType  = "tcpsyn"
	FINScanType  = "tcpfin"
	NULLScanType = "tcpnull"
)

//easyjson:json
type ScanResult struct {
	ScanType string `json:"scan"`
	IP       string `json:"ip"`
	Port     uint16 `json:"port"`
	Flags    string `json:"flags,omitempty"`
}

func (r *ScanResult) String() string {
	return fmt.Sprintf("%-20s %d", r.IP, r.Port)
}

func (r *ScanResult) ID() string {
	return fmt.Sprintf("%s:%d", r.IP, r.Port)
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

	rcvDecoded []gopacket.LayerType
	rcvEth     layers.Ethernet
	rcvIP      layers.IPv4
	rcvTCP     layers.TCP
}

// Assert that tcp.ScanMethod conforms to the scan.Method interface
var _ scan.Method = (*ScanMethod)(nil)

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

func NewScanMethod(scanType string, psrc scan.PacketSource,
	results scan.ResultChan, opts ...ScanMethodOption) *ScanMethod {
	sm := &ScanMethod{
		PacketSource: psrc,
		scanType:     scanType,
		results:      results,
		pktFilter:    TrueFilter,
		pktFlags:     AllFlags,
	}
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &sm.rcvEth, &sm.rcvIP, &sm.rcvTCP)
	parser.IgnoreUnsupported = true
	sm.parser = parser

	// options pattern
	for _, o := range opts {
		o(sm)
	}
	return sm
}

func (s *ScanMethod) Results() <-chan scan.Result {
	return s.results.Chan()
}

func (s *ScanMethod) ProcessPacketData(data []byte, _ *gopacket.CaptureInfo) error {
	if err := s.parser.DecodeLayers(data, &s.rcvDecoded); err != nil {
		return err
	}
	if len(s.rcvDecoded) != 3 {
		return nil
	}

	if s.pktFilter(&s.rcvTCP) {
		s.results.Put(&ScanResult{
			ScanType: s.scanType,
			IP:       s.rcvIP.SrcIP.String(),
			Port:     uint16(s.rcvTCP.SrcPort),
			Flags:    s.pktFlags(&s.rcvTCP),
		})
	}
	return nil
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

func NewPacketFiller(opts ...PacketFillerOption) *PacketFiller {
	f := &PacketFiller{}
	for _, o := range opts {
		o(f)
	}
	return f
}

func (f *PacketFiller) Fill(packet gopacket.SerializeBuffer, pair *scan.Request) (err error) {
	eth := &layers.Ethernet{
		SrcMAC:       pair.SrcMAC,
		DstMAC:       pair.DstMAC,
		EthernetType: layers.EthernetTypeIPv4,
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
		SrcIP:    pair.SrcIP,
		DstIP:    pair.DstIP,
	}

	tcp := &layers.TCP{
		// emulate Linux default ephemeral ports range: 32768 60999
		// cat /proc/sys/net/ipv4/ip_local_port_range
		SrcPort: layers.TCPPort(32768 + rand.Intn(61000-32768)),
		DstPort: layers.TCPPort(pair.DstPort),
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
		return err
	}

	opt := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	return gopacket.SerializeLayers(packet, opt, eth, ip, tcp)
}
