//go:generate easyjson -output_filename result_easyjson.go arp.go

package arp

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/macs"
	"github.com/v-byte-cpu/sx/pkg/scan"
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
var _ scan.Method = (*ScanMethod)(nil)

//easyjson:json
type ScanResult struct {
	IP     string `json:"ip"`
	MAC    string `json:"mac"`
	Vendor string `json:"vendor"`
}

func (r *ScanResult) String() string {
	return fmt.Sprintf("%-20s %-20s %s", r.IP, r.MAC, r.Vendor)
}

func (r *ScanResult) ID() string {
	return r.IP
}

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

	s.results.Put(&ScanResult{
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

func (*PacketFiller) Fill(packet gopacket.SerializeBuffer, pair *scan.Request) error {
	eth := &layers.Ethernet{
		SrcMAC:       pair.SrcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	a := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     uint8(6),
		ProtAddressSize:   uint8(4),
		Operation:         layers.ARPRequest,
		SourceHwAddress:   pair.SrcMAC,
		SourceProtAddress: pair.SrcIP,
		DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    pair.DstIP.To4(),
	}

	var opt gopacket.SerializeOptions
	return gopacket.SerializeLayers(packet, opt, eth, a)
}
