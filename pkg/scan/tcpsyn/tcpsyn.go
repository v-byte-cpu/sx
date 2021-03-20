//go:generate easyjson -output_filename result_easyjson.go tcpsyn.go

package tcpsyn

import (
	"context"
	"fmt"
	"math/rand"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/v-byte-cpu/sx/pkg/scan"
)

const ScanType = "syn"

//easyjson:json
type ScanResult struct {
	ScanType string `json:"scan"`
	IP       string `json:"ip"`
	Port     uint16 `json:"port"`
}

func (r *ScanResult) String() string {
	return fmt.Sprintf("%-20s %d", r.IP, r.Port)
}

func (r *ScanResult) ID() string {
	return fmt.Sprintf("%s:%d", r.IP, r.Port)
}

type ScanMethod struct {
	scan.PacketSource
	parser  *gopacket.DecodingLayerParser
	results *scan.ResultChan
	ctx     context.Context

	rcvDecoded []gopacket.LayerType
	rcvEth     layers.Ethernet
	rcvIP      layers.IPv4
	rcvTCP     layers.TCP
}

// Assert that tcpsyn.ScanMethod conforms to the scan.Method interface
var _ scan.Method = (*ScanMethod)(nil)

func NewScanMethod(ctx context.Context, psrc scan.PacketSource) *ScanMethod {
	sm := &ScanMethod{
		PacketSource: psrc,
		ctx:          ctx,
		results:      scan.NewResultChan(ctx, 1000),
	}
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &sm.rcvEth, &sm.rcvIP, &sm.rcvTCP)
	parser.IgnoreUnsupported = true
	sm.parser = parser
	return sm
}

func (s *ScanMethod) Results() <-chan scan.Result {
	return s.results.Chan()
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

	var srcIP net.IP
	var port uint16
	for _, layerType := range s.rcvDecoded {
		switch layerType {
		case layers.LayerTypeIPv4:
			srcIP = s.rcvIP.SrcIP
		case layers.LayerTypeTCP:
			if s.rcvTCP.SYN && s.rcvTCP.ACK {
				// port is open
				port = uint16(s.rcvTCP.SrcPort)
			}
		}
	}

	if port > 0 {
		s.results.Put(&ScanResult{
			ScanType: ScanType,
			IP:       srcIP.String(),
			Port:     port,
		})
	}
	return nil
}

type PacketFiller struct{}

// Assert that tcpsyn.PacketFiller conforms to the scan.PacketFiller interface
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
		SYN:     true,
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

	opt := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	return gopacket.SerializeLayers(packet, opt, eth, ip, tcp)
}
