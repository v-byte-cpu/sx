package tcp

import (
	"context"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/v-byte-cpu/sx/pkg/scan"
	"github.com/v-byte-cpu/sx/pkg/scan/arp"
)

func TestPacketFiller(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		filler *PacketFiller
		SYN    bool
		ACK    bool
		FIN    bool
		RST    bool
		PSH    bool
		URG    bool
		ECE    bool
		CWR    bool
		NS     bool
	}{
		{
			name:   "SYN",
			filler: NewPacketFiller(WithSYN()),
			SYN:    true,
		},
		{
			name:   "ACK",
			filler: NewPacketFiller(WithACK()),
			ACK:    true,
		},
		{
			name:   "FIN",
			filler: NewPacketFiller(WithFIN()),
			FIN:    true,
		},
		{
			name:   "RST",
			filler: NewPacketFiller(WithRST()),
			RST:    true,
		},
		{
			name:   "PSH",
			filler: NewPacketFiller(WithPSH()),
			PSH:    true,
		},
		{
			name:   "URG",
			filler: NewPacketFiller(WithURG()),
			URG:    true,
		},
		{
			name:   "ECE",
			filler: NewPacketFiller(WithECE()),
			ECE:    true,
		},
		{
			name:   "CWR",
			filler: NewPacketFiller(WithCWR()),
			CWR:    true,
		},
		{
			name:   "NS",
			filler: NewPacketFiller(WithNS()),
			NS:     true,
		},
	}

	for _, vtt := range tests {
		tt := vtt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			packet := gopacket.NewSerializeBuffer()
			err := tt.filler.Fill(packet, &scan.Request{
				SrcIP:   net.IPv4(192, 168, 0, 3).To4(),
				DstIP:   net.IPv4(192, 168, 0, 2).To4(),
				SrcMAC:  net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
				DstMAC:  net.HardwareAddr{0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
				DstPort: 4567,
			})
			require.NoError(t, err)

			resultPacket := gopacket.NewPacket(packet.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

			ethLayer := resultPacket.Layer(layers.LayerTypeEthernet)
			require.NotNil(t, ethLayer, "ethernet layer is empty")
			eth := ethLayer.(*layers.Ethernet)
			require.Equal(t, net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6}, eth.SrcMAC)
			require.Equal(t, net.HardwareAddr{0x10, 0x11, 0x12, 0x13, 0x14, 0x15}, eth.DstMAC)

			ipLayer := resultPacket.Layer(layers.LayerTypeIPv4)
			require.NotNil(t, ipLayer, "ip layer is empty")
			ip := ipLayer.(*layers.IPv4)
			require.Equal(t, net.IPv4(192, 168, 0, 3).To4(), ip.SrcIP.To4())
			require.Equal(t, net.IPv4(192, 168, 0, 2).To4(), ip.DstIP.To4())

			tcpLayer := resultPacket.Layer(layers.LayerTypeTCP)
			require.NotNil(t, tcpLayer, "tcp layer is empty")
			tcp := tcpLayer.(*layers.TCP)
			require.GreaterOrEqual(t, tcp.SrcPort, uint16(32768))
			require.LessOrEqual(t, tcp.SrcPort, uint16(60999))
			require.Equal(t, uint16(4567), uint16(tcp.DstPort))

			require.Equal(t, tt.SYN, tcp.SYN)
			require.Equal(t, tt.ACK, tcp.ACK)
			require.Equal(t, tt.FIN, tcp.FIN)
			require.Equal(t, tt.RST, tcp.RST)
			require.Equal(t, tt.PSH, tcp.PSH)
			require.Equal(t, tt.URG, tcp.URG)
			require.Equal(t, tt.ECE, tcp.ECE)
			require.Equal(t, tt.CWR, tcp.CWR)
			require.Equal(t, tt.NS, tcp.NS)
		})
	}
}

func TestProcessPacketData(t *testing.T) {
	t.Parallel()

	done := make(chan interface{})

	go func() {
		defer close(done)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		results := scan.NewResultChan(ctx, 1000)
		sm := NewScanMethod(SYNScanType, nil, results)

		// generate packet data
		packet := gopacket.NewSerializeBuffer()
		eth := &layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
			DstMAC:       net.HardwareAddr{0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
			EthernetType: layers.EthernetTypeIPv4,
		}

		ip := &layers.IPv4{
			Version:  4,
			Id:       12345,
			Flags:    layers.IPv4DontFragment,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
			SrcIP:    net.IPv4(192, 168, 0, 2).To4(),
			DstIP:    net.IPv4(192, 168, 0, 3).To4(),
		}

		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(22),
			DstPort: layers.TCPPort(45678),
			Seq:     1234567,
			SYN:     true,
			ACK:     true,
		}
		err := tcp.SetNetworkLayerForChecksum(ip)
		require.NoError(t, err)

		opt := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}
		err = gopacket.SerializeLayers(packet, opt, eth, ip, tcp)
		require.NoError(t, err)

		err = sm.ProcessPacketData(packet.Bytes(), &gopacket.CaptureInfo{})
		require.NoError(t, err)

		result, ok := <-sm.Results()
		if !ok {
			require.FailNow(t, "results chan is empty")
		}
		tcpResult := result.(*ScanResult)
		assert.Equal(t, SYNScanType, tcpResult.ScanType)
		assert.Equal(t, net.IPv4(192, 168, 0, 2).To4().String(), tcpResult.IP)
		assert.Equal(t, uint16(22), tcpResult.Port)

		cancel()
		_, ok = <-sm.Results()
		require.False(t, ok, "results chan is not closed")
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("test timeout")
	}
}

func TestAllFlags(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		packet   *layers.TCP
		expected string
	}{
		{
			name:     "EmptyFlags",
			packet:   &layers.TCP{},
			expected: "",
		},
		{
			name:     "SynFlag",
			packet:   &layers.TCP{SYN: true},
			expected: "s",
		},
		{
			name:     "AckFlag",
			packet:   &layers.TCP{ACK: true},
			expected: "a",
		},
		{
			name:     "FinFlag",
			packet:   &layers.TCP{FIN: true},
			expected: "f",
		},
		{
			name:     "RstFlag",
			packet:   &layers.TCP{RST: true},
			expected: "r",
		},
		{
			name:     "PshFlag",
			packet:   &layers.TCP{PSH: true},
			expected: "p",
		},
		{
			name:     "UrgFlag",
			packet:   &layers.TCP{URG: true},
			expected: "u",
		},
		{
			name:     "EceFlag",
			packet:   &layers.TCP{ECE: true},
			expected: "e",
		},
		{
			name:     "CwrFlag",
			packet:   &layers.TCP{CWR: true},
			expected: "c",
		},
		{
			name:     "NsFlag",
			packet:   &layers.TCP{NS: true},
			expected: "n",
		},
		{
			name:     "SynAckFlag",
			packet:   &layers.TCP{SYN: true, ACK: true},
			expected: "sa",
		},
		{
			name:     "AckFinFlag",
			packet:   &layers.TCP{ACK: true, FIN: true},
			expected: "af",
		},
		{
			name:     "CwrNsFlag",
			packet:   &layers.TCP{CWR: true, NS: true},
			expected: "cn",
		},
		{
			name: "AllFlags",
			packet: &layers.TCP{
				SYN: true, ACK: true, FIN: true,
				RST: true, PSH: true, URG: true,
				ECE: true, CWR: true, NS: true},
			expected: "safrpuecn",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := AllFlags(tt.packet)
			require.Equal(t, tt.expected, flags)
		})
	}
}

type mockIPGeneratorFunc func(ctx context.Context, r *scan.Range) (<-chan scan.IPGetter, error)

func (f mockIPGeneratorFunc) IPs(ctx context.Context, r *scan.Range) (<-chan scan.IPGetter, error) {
	return f(ctx, r)
}

type nullPacketReadWriter struct{}

func (*nullPacketReadWriter) ReadPacketData() (data []byte, ci *gopacket.CaptureInfo, err error) {
	return
}

func (*nullPacketReadWriter) WritePacketData(_ []byte) error {
	return nil
}

func BenchmarkTCPScanEngine(b *testing.B) {
	b.ReportAllocs()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dstIP := net.IPv4(192, 168, 0, 3).To4()
	ipgen := mockIPGeneratorFunc(func(ctx context.Context, r *scan.Range) (<-chan scan.IPGetter, error) {
		out := make(chan scan.IPGetter, 100)
		go func() {
			defer close(out)
			for i := 0; i < b.N; i++ {
				select {
				case <-ctx.Done():
					return
				case out <- scan.WrapIP(dstIP):
				}
			}
		}()
		return out, nil
	})
	reqgen := arp.NewCacheRequestGenerator(
		scan.NewIPPortGenerator(ipgen, scan.NewPortGenerator()),
		net.HardwareAddr{0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
		arp.NewCache())
	pktgen := scan.NewPacketMultiGenerator(NewPacketFiller(), runtime.NumCPU())
	psrc := scan.NewPacketSource(reqgen, pktgen)
	results := scan.NewResultChan(ctx, 1000)
	sm := NewScanMethod("tcpbench", psrc, results)
	engine := scan.SetupPacketEngine(&nullPacketReadWriter{}, sm)

	done, _ := engine.Start(ctx, &scan.Range{
		SrcIP:  net.IPv4(192, 168, 0, 2).To4(),
		SrcMAC: net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
		Ports: []*scan.PortRange{
			{
				StartPort: 22,
				EndPort:   22,
			},
		},
	})
	<-done
}
