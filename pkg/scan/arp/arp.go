//go:generate easyjson -output_filename result_easyjson.go arp.go

package arp

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/macs"
	"github.com/v-byte-cpu/sx/pkg/packet"
	"github.com/v-byte-cpu/sx/pkg/scan"
)

type ScanMethod struct {
	reqgen          scan.RequestGenerator
	pktgen          *scan.PacketMultiGenerator
	parser          *gopacket.DecodingLayerParser
	results         chan *ScanResult
	internalResults chan *ScanResult
	ctx             context.Context

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

type ScanMethodOption func(sm *ScanMethod)

func LiveMode(rescanTimeout time.Duration) ScanMethodOption {
	return func(sm *ScanMethod) {
		sm.reqgen = scan.NewLiveRequestGenerator(rescanTimeout)
	}
}

func NewScanMethod(ctx context.Context, opts ...ScanMethodOption) *ScanMethod {
	results := make(chan *ScanResult, 1000)
	internalResults := make(chan *ScanResult, 1000)

	copyChans := func() {
		defer close(results)
		for {
			select {
			case <-ctx.Done():
				return
			case v := <-internalResults:
				select {
				case <-ctx.Done():
					return
				case results <- v:
				}
			}
		}
	}
	go copyChans()

	sm := &ScanMethod{
		ctx:             ctx,
		results:         results,
		internalResults: internalResults,
		reqgen:          scan.RequestGeneratorFunc(scan.Requests),
		pktgen:          scan.NewPacketMultiGenerator(newPacketFiller(), runtime.NumCPU()),
	}
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &sm.rcvEth, &sm.rcvARP)
	parser.IgnoreUnsupported = true
	sm.parser = parser

	for _, o := range opts {
		o(sm)
	}
	return sm
}

func (s *ScanMethod) Results() <-chan *ScanResult {
	return s.results
}

func (s *ScanMethod) Packets(ctx context.Context, r *scan.Range) <-chan *packet.BufferData {
	requests, err := s.reqgen.GenerateRequests(ctx, r)
	if err != nil {
		out := make(chan *packet.BufferData, 1)
		out <- &packet.BufferData{Err: err}
		close(out)
		return out
	}
	return s.pktgen.Packets(ctx, requests)
}

func (s *ScanMethod) ProcessPacketData(data []byte, _ *gopacket.CaptureInfo) error {
	// try to exit as early as possible
	select {
	case <-s.ctx.Done():
		return nil
	default:
	}

	err := s.parser.DecodeLayers(data, &s.rcvDecoded)
	if err != nil {
		return err
	}
	for _, layerType := range s.rcvDecoded {
		if layerType == layers.LayerTypeARP {
			copy(s.rcvMacPrefix[:], s.rcvARP.SourceHwAddress[:3])
			hwVendor := macs.ValidMACPrefixMap[s.rcvMacPrefix]

			select {
			case <-s.ctx.Done():
			case s.internalResults <- &ScanResult{
				IP:     net.IP(s.rcvARP.SourceProtAddress).String(),
				MAC:    net.HardwareAddr(s.rcvARP.SourceHwAddress).String(),
				Vendor: hwVendor,
			}:
			}
			return nil
		}
	}
	return nil
}

type packetFiller struct{}

func newPacketFiller() *packetFiller {
	return &packetFiller{}
}

func (*packetFiller) Fill(packet gopacket.SerializeBuffer, pair *scan.Request) error {
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
