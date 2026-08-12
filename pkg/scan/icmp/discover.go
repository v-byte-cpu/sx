package icmp

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/macs"
	"github.com/v-byte-cpu/sx/pkg/scan"
	"github.com/v-byte-cpu/sx/pkg/scan/neighbor"
)

const DiscoveryScanType = "icmpdiscover"

const discoveryNonceSize = 16

var (
	errDiscoveryIPv6Addresses = errors.New("ICMPv6 discovery requires a link-local source and link-local multicast destination")
	errDiscoverySourceMAC     = errors.New("ICMPv6 discovery requires a unicast Ethernet source MAC")
)

// DiscoveryProbe identifies one multicast echo request and correlates its replies.
type DiscoveryProbe struct {
	Identifier uint16
	Sequence   uint16
	Nonce      [discoveryNonceSize]byte
}

// NewDiscoveryProbe creates the correlation values for one discovery request.
func NewDiscoveryProbe() (DiscoveryProbe, error) {
	var random [2 + discoveryNonceSize]byte
	if _, err := cryptorand.Read(random[:]); err != nil {
		return DiscoveryProbe{}, err
	}
	return DiscoveryProbe{
		Identifier: binary.BigEndian.Uint16(random[:2]),
		Sequence:   1,
		Nonce:      [discoveryNonceSize]byte(random[2:]),
	}, nil
}

// DiscoveryPacketFiller builds the single ICMPv6 multicast echo request.
type DiscoveryPacketFiller struct {
	probe DiscoveryProbe
}

var _ scan.PacketFiller = (*DiscoveryPacketFiller)(nil)

func NewDiscoveryPacketFiller(probe DiscoveryProbe) *DiscoveryPacketFiller {
	return &DiscoveryPacketFiller{probe: probe}
}

func (f *DiscoveryPacketFiller) Fill(packet gopacket.SerializeBuffer, request *scan.Request) error {
	if !request.SrcIP.Is6() || !request.SrcIP.IsLinkLocalUnicast() ||
		!request.DstIP.Is6() || !request.DstIP.IsLinkLocalMulticast() {
		return errDiscoveryIPv6Addresses
	}
	if !validUnicastMAC(request.SrcMAC) {
		return errDiscoverySourceMAC
	}

	destination := request.DstIP.WithZone("").As16()
	ethernet := &layers.Ethernet{
		SrcMAC:       request.SrcMAC,
		DstMAC:       net.HardwareAddr{0x33, 0x33, destination[12], destination[13], destination[14], destination[15]},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ipv6 := &layers.IPv6{
		Version:    6,
		HopLimit:   1,
		NextHeader: layers.IPProtocolICMPv6,
		SrcIP:      net.IP(request.SrcIP.WithZone("").AsSlice()),
		DstIP:      net.IP(destination[:]),
	}
	icmpv6 := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0),
	}
	if err := icmpv6.SetNetworkLayerForChecksum(ipv6); err != nil {
		return err
	}
	echo := &layers.ICMPv6Echo{
		Identifier: f.probe.Identifier,
		SeqNumber:  f.probe.Sequence,
	}
	return gopacket.SerializeLayers(
		packet,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ethernet,
		ipv6,
		icmpv6,
		echo,
		gopacket.Payload(f.probe.Nonce[:]),
	)
}

func validUnicastMAC(mac net.HardwareAddr) bool {
	if len(mac) != 6 || mac[0]&1 != 0 {
		return false
	}
	for _, b := range mac {
		if b != 0 {
			return true
		}
	}
	return false
}

// DiscoveryScanMethod sends a discovery request and emits correlated IPv6 neighbors.
type DiscoveryScanMethod struct {
	scan.PacketSource
	parser  *gopacket.DecodingLayerParser
	results scan.ResultChan
	probe   DiscoveryProbe
	localIP netip.Addr
	zone    string

	decoded []gopacket.LayerType
	eth     layers.Ethernet
	ipv6    layers.IPv6
	icmpv6  layers.ICMPv6
	echo    layers.ICMPv6Echo
}

var _ scan.PacketMethod = (*DiscoveryScanMethod)(nil)

func NewDiscoveryScanMethod(
	source scan.PacketSource,
	results scan.ResultChan,
	probe DiscoveryProbe,
	localIP netip.Addr,
	zone string,
) *DiscoveryScanMethod {
	method := &DiscoveryScanMethod{
		PacketSource: source,
		results:      results,
		probe:        probe,
		localIP:      localIP.WithZone(""),
		zone:         zone,
	}
	method.parser = gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&method.eth,
		&method.ipv6,
		&method.icmpv6,
		&method.echo,
	)
	method.parser.IgnoreUnsupported = true
	return method
}

func (m *DiscoveryScanMethod) Results() <-chan scan.Result {
	return m.results.Chan()
}

func (m *DiscoveryScanMethod) ProcessPacketData(data []byte, _ *gopacket.CaptureInfo) error {
	if err := m.parser.DecodeLayers(data, &m.decoded); err != nil {
		return err
	}
	if !m.correlatedReply() {
		return nil
	}

	address, _ := netip.AddrFromSlice(m.ipv6.SrcIP)
	if address.IsLinkLocalUnicast() && m.zone != "" {
		address = address.WithZone(m.zone)
	}
	mac := m.eth.SrcMAC
	var prefix [3]byte
	copy(prefix[:], mac)
	m.results.Put(&neighbor.ScanResult{
		IP:     address.String(),
		MAC:    mac.String(),
		Vendor: macs.ValidMACPrefixMap[prefix],
	})
	return nil
}

func (m *DiscoveryScanMethod) correlatedReply() bool {
	if len(m.decoded) != 4 ||
		m.icmpv6.TypeCode.Type() != layers.ICMPv6TypeEchoReply ||
		m.icmpv6.TypeCode.Code() != 0 ||
		m.echo.Identifier != m.probe.Identifier ||
		m.echo.SeqNumber != m.probe.Sequence ||
		len(m.icmpv6.Payload) != 4+discoveryNonceSize ||
		!bytes.Equal(m.icmpv6.Payload[4:], m.probe.Nonce[:]) ||
		!validUnicastMAC(m.eth.SrcMAC) {
		return false
	}

	destination, ok := netip.AddrFromSlice(m.ipv6.DstIP)
	if !ok || destination != m.localIP {
		return false
	}
	source, ok := netip.AddrFromSlice(m.ipv6.SrcIP)
	return ok && source.Is6() && !source.IsMulticast() && !source.IsUnspecified()
}
