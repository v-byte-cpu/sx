//go:generate easyjson -output_filename result_easyjson.go udp.go

package udp

import (
	"fmt"
	"math/rand"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/v-byte-cpu/sx/pkg/scan"
	"github.com/v-byte-cpu/sx/pkg/scan/icmp"
)

const ScanType = "udp"

//easyjson:json
type ScanResult struct {
	ScanType string         `json:"scan"`
	IP       string         `json:"ip"`
	ICMP     *icmp.Response `json:"icmp"`
}

func (r *ScanResult) String() string {
	return fmt.Sprintf("%-20s %-5d %-5d", r.IP, r.ICMP.Type, r.ICMP.Code)
}

func (r *ScanResult) ID() string {
	return r.IP
}

// ScanMethod exploits RFC1122 Section 4.1.3.1:
// If a datagram arrives addressed to a UDP port for which
// there is no pending LISTEN call, UDP SHOULD send an ICMP
// Port Unreachable message.
type ScanMethod struct {
	scan.PacketSource
	parser  *gopacket.DecodingLayerParser
	results scan.ResultChan

	rcvDecoded []gopacket.LayerType
	rcvEth     layers.Ethernet
	rcvIP      layers.IPv4
	rcvICMP    layers.ICMPv4
}

// Assert that tcp.ScanMethod conforms to the scan.PacketMethod interface
var _ scan.PacketMethod = (*ScanMethod)(nil)

func NewScanMethod(psrc scan.PacketSource, results scan.ResultChan) *ScanMethod {
	sm := &ScanMethod{
		PacketSource: psrc,
		results:      results,
	}
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &sm.rcvEth, &sm.rcvIP, &sm.rcvICMP)
	parser.IgnoreUnsupported = true
	sm.parser = parser
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

	s.results.Put(&ScanResult{
		ScanType: ScanType,
		IP:       s.rcvIP.SrcIP.String(),
		ICMP: &icmp.Response{
			Type: s.rcvICMP.TypeCode.Type(),
			Code: s.rcvICMP.TypeCode.Code(),
		},
	})
	return nil
}

type PacketFiller struct{}

// Assert that udp.PacketFiller conforms to the scan.PacketFiller interface
var _ scan.PacketFiller = (*PacketFiller)(nil)

func NewPacketFiller() *PacketFiller {
	return &PacketFiller{}
}

func (*PacketFiller) Fill(packet gopacket.SerializeBuffer, pair *scan.Request) (err error) {
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
		Protocol: layers.IPProtocolUDP,
		SrcIP:    pair.SrcIP,
		DstIP:    pair.DstIP,
	}

	udp := &layers.UDP{
		// emulate Linux default ephemeral ports range: 32768 60999
		// cat /proc/sys/net/ipv4/ip_local_port_range
		SrcPort: layers.UDPPort(32768 + rand.Intn(61000-32768)),
		DstPort: layers.UDPPort(pair.DstPort),
	}

	if err = udp.SetNetworkLayerForChecksum(ip); err != nil {
		return err
	}

	opt := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	return gopacket.SerializeLayers(packet, opt, eth, ip, udp)
}
