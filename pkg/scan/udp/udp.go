package udp

import (
	"math/rand"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/v-byte-cpu/sx/pkg/packet"
	"github.com/v-byte-cpu/sx/pkg/scan"
	"github.com/v-byte-cpu/sx/pkg/scan/icmp"
)

const ScanType = "udp"

// ScanMethod exploits RFC1122 Section 4.1.3.1:
// If a datagram arrives addressed to a UDP port for which
// there is no pending LISTEN call, UDP SHOULD send an ICMP
// Port Unreachable message.
type ScanMethod struct {
	scan.PacketSource
	packet.Processor
	scan.Resulter
}

// Assert that udp.ScanMethod conforms to the scan.PacketMethod interface
var _ scan.PacketMethod = (*ScanMethod)(nil)

func NewScanMethod(psrc scan.PacketSource, results scan.ResultChan, vpnMode bool, ipv6 ...bool) *ScanMethod {
	pp := icmp.NewPacketProcessor(ScanType, results, vpnMode, ipv6...)
	return newScanMethod(psrc, pp)
}

func NewScanMethodForFamily(psrc scan.PacketSource, results scan.ResultChan, vpnMode, ipv6 bool, zone string) *ScanMethod {
	return newScanMethod(psrc, icmp.NewPacketProcessorForFamily(ScanType, results, vpnMode, ipv6, zone))
}

func newScanMethod(psrc scan.PacketSource, pp *icmp.PacketProcessor) *ScanMethod {
	return &ScanMethod{
		PacketSource: psrc,
		Processor:    pp,
		Resulter:     pp,
	}
}

type PacketFiller struct {
	ttl     uint8
	length  uint16
	proto   layers.IPProtocol
	flags   layers.IPv4Flag
	payload []byte
	vpnMode bool

	hopLimit      uint8
	nextHeader    layers.IPProtocol
	payloadLength uint16
}

// Assert that udp.PacketFiller conforms to the scan.PacketFiller interface
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

func NewPacketFiller(opts ...PacketFillerOption) *PacketFiller {
	f := &PacketFiller{
		// typical TTL value for Linux
		ttl:        64,
		proto:      layers.IPProtocolUDP,
		flags:      layers.IPv4DontFragment,
		hopLimit:   64,
		nextHeader: layers.IPProtocolUDP,
	}
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
		Id:    uint16(1 + rand.Intn(65535)),
		Flags: f.flags,
		// Typical 20 bytes IP header length
		IHL:      5,
		TTL:      f.ttl,
		Length:   f.length,
		Protocol: f.proto,
		SrcIP:    r.SrcIP.AsSlice(),
		DstIP:    r.DstIP.AsSlice(),
	}

	udp := &layers.UDP{
		// emulate Linux default ephemeral ports range: 32768 60999
		// cat /proc/sys/net/ipv4/ip_local_port_range
		SrcPort: layers.UDPPort(32768 + rand.Intn(61000-32768)),
		DstPort: layers.UDPPort(r.DstPort),
	}

	if err = udp.SetNetworkLayerForChecksum(ip); err != nil {
		return err
	}

	opt := gopacket.SerializeOptions{ComputeChecksums: true}
	if ip.Length == 0 {
		opt.FixLengths = true
	}
	if f.vpnMode {
		return gopacket.SerializeLayers(packet, opt, ip, udp, gopacket.Payload(f.payload))
	}
	eth := &layers.Ethernet{
		SrcMAC:       r.SrcMAC,
		DstMAC:       r.DstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	return gopacket.SerializeLayers(packet, opt, eth, ip, udp, gopacket.Payload(f.payload))
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
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(32768 + rand.Intn(61000-32768)),
		DstPort: layers.UDPPort(r.DstPort),
	}
	if err := udp.SetNetworkLayerForChecksum(ipv6); err != nil {
		return err
	}
	options := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: f.payloadLength == 0}
	layersToSerialize := []gopacket.SerializableLayer{ipv6, udp, gopacket.Payload(f.payload)}
	if !f.vpnMode {
		layersToSerialize = append([]gopacket.SerializableLayer{&layers.Ethernet{
			SrcMAC: r.SrcMAC, DstMAC: r.DstMAC, EthernetType: layers.EthernetTypeIPv6,
		}}, layersToSerialize...)
	}
	return gopacket.SerializeLayers(packet, options, layersToSerialize...)
}
