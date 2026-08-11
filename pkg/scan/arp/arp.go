package arp

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/macs"
	"github.com/v-byte-cpu/sx/pkg/scan"
	"github.com/v-byte-cpu/sx/pkg/scan/neighbor"
)

type ScanMethod struct {
	scan.PacketSource
	parser  *gopacket.DecodingLayerParser
	results scan.ResultChan

	rcvDecoded   []gopacket.LayerType
	rcvEth       layers.Ethernet
	rcvARP       layers.ARP
	rcvMacPrefix [3]byte
}

// Assert that arp.ScanMethod conforms to the scan.Method interface
var _ scan.PacketMethod = (*ScanMethod)(nil)

func NewScanMethod(psrc scan.PacketSource, results scan.ResultChan) *ScanMethod {
	sm := &ScanMethod{
		PacketSource: psrc,
		results:      results,
	}
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &sm.rcvEth, &sm.rcvARP)
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
	if len(s.rcvDecoded) != 2 {
		return nil
	}

	copy(s.rcvMacPrefix[:], s.rcvARP.SourceHwAddress[:3])
	hwVendor := macs.ValidMACPrefixMap[s.rcvMacPrefix]

	s.results.Put(&neighbor.ScanResult{
		IP:     net.IP(s.rcvARP.SourceProtAddress).String(),
		MAC:    net.HardwareAddr(s.rcvARP.SourceHwAddress).String(),
		Vendor: hwVendor,
	})
	return nil
}

type PacketFiller struct{}

func NewPacketFiller() *PacketFiller {
	return &PacketFiller{}
}

func (*PacketFiller) Fill(packet gopacket.SerializeBuffer, r *scan.Request) error {
	eth := &layers.Ethernet{
		SrcMAC:       r.SrcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	a := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     uint8(6),
		ProtAddressSize:   uint8(4),
		Operation:         layers.ARPRequest,
		SourceHwAddress:   r.SrcMAC,
		SourceProtAddress: net.IP(r.SrcIP.AsSlice()),
		DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    net.IP(r.DstIP.AsSlice()),
	}

	var opt gopacket.SerializeOptions
	return gopacket.SerializeLayers(packet, opt, eth, a)
}
