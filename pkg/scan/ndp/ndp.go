package ndp

import (
	"errors"
	"net"
	"net/netip"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/macs"
	"github.com/v-byte-cpu/sx/pkg/scan"
	"github.com/v-byte-cpu/sx/pkg/scan/neighbor"
)

const ScanType = "ndp"

var errIPv6Required = errors.New("NDP requires IPv6 source and destination addresses")

type ScanMethod struct {
	scan.PacketSource
	parser  *gopacket.DecodingLayerParser
	results scan.ResultChan

	decoded []gopacket.LayerType
	eth     layers.Ethernet
	ipv6    layers.IPv6
	icmpv6  layers.ICMPv6
	na      layers.ICMPv6NeighborAdvertisement
	zone    string
}

var _ scan.PacketMethod = (*ScanMethod)(nil)

func NewScanMethod(source scan.PacketSource, results scan.ResultChan, zone ...string) *ScanMethod {
	method := &ScanMethod{PacketSource: source, results: results}
	if len(zone) > 0 {
		method.zone = zone[0]
	}
	method.parser = gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&method.eth,
		&method.ipv6,
		&method.icmpv6,
		&method.na,
	)
	method.parser.IgnoreUnsupported = true
	return method
}

func (m *ScanMethod) Results() <-chan scan.Result {
	return m.results.Chan()
}

func (m *ScanMethod) ProcessPacketData(data []byte, _ *gopacket.CaptureInfo) error {
	if err := m.parser.DecodeLayers(data, &m.decoded); err != nil {
		return err
	}
	if len(m.decoded) != 4 || m.ipv6.HopLimit != 255 ||
		m.icmpv6.TypeCode.Type() != layers.ICMPv6TypeNeighborAdvertisement || m.icmpv6.TypeCode.Code() != 0 {
		return nil
	}

	mac := m.eth.SrcMAC
	for _, option := range m.na.Options {
		if option.Type == layers.ICMPv6OptTargetAddress && len(option.Data) >= 6 {
			mac = net.HardwareAddr(option.Data[:6])
			break
		}
	}
	var prefix [3]byte
	copy(prefix[:], mac)
	address, _ := netip.AddrFromSlice(m.na.TargetAddress)
	if address.IsLinkLocalUnicast() && m.zone != "" {
		address = address.WithZone(m.zone)
	}
	m.results.Put(&neighbor.ScanResult{
		IP:     address.String(),
		MAC:    mac.String(),
		Vendor: macs.ValidMACPrefixMap[prefix],
	})
	return nil
}

type PacketFiller struct{}

func NewPacketFiller() *PacketFiller {
	return &PacketFiller{}
}

func (*PacketFiller) Fill(packet gopacket.SerializeBuffer, request *scan.Request) error {
	if !request.SrcIP.Is6() || !request.DstIP.Is6() {
		return errIPv6Required
	}
	target := request.DstIP.WithZone("").As16()
	multicastIP := [16]byte{0xff, 0x02}
	multicastIP[11] = 0x01
	multicastIP[12] = 0xff
	copy(multicastIP[13:], target[13:])
	multicastMAC := net.HardwareAddr{0x33, 0x33, 0xff, target[13], target[14], target[15]}

	eth := &layers.Ethernet{
		SrcMAC:       request.SrcMAC,
		DstMAC:       multicastMAC,
		EthernetType: layers.EthernetTypeIPv6,
	}
	ipv6 := &layers.IPv6{
		Version:    6,
		HopLimit:   255,
		NextHeader: layers.IPProtocolICMPv6,
		SrcIP:      net.IP(request.SrcIP.WithZone("").AsSlice()),
		DstIP:      net.IP(multicastIP[:]),
	}
	icmpv6 := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborSolicitation, 0),
	}
	if err := icmpv6.SetNetworkLayerForChecksum(ipv6); err != nil {
		return err
	}
	ns := &layers.ICMPv6NeighborSolicitation{
		TargetAddress: net.IP(target[:]),
		Options: layers.ICMPv6Options{{
			Type: layers.ICMPv6OptSourceAddress,
			Data: request.SrcMAC,
		}},
	}
	return gopacket.SerializeLayers(
		packet,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth,
		ipv6,
		icmpv6,
		ns,
	)
}
