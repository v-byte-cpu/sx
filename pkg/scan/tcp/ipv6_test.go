package tcp

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"github.com/v-byte-cpu/sx/pkg/scan"
)

func TestPacketFillerIPv6(t *testing.T) {
	t.Parallel()

	packet := gopacket.NewSerializeBuffer()
	err := NewPacketFiller(WithSYN(), WithHopLimit(33)).Fill(packet, &scan.Request{
		SrcIP: netip.MustParseAddr("2001:db8::1"), DstIP: netip.MustParseAddr("2001:db8::2"), DstPort: 443,
		SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2},
	})
	require.NoError(t, err)

	decoded := gopacket.NewPacket(packet.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	ipv6 := decoded.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	require.Equal(t, uint8(33), ipv6.HopLimit)
	require.Equal(t, layers.IPProtocolTCP, ipv6.NextHeader)
	tcp := decoded.Layer(layers.LayerTypeTCP).(*layers.TCP)
	require.True(t, tcp.SYN)
	require.Equal(t, layers.TCPPort(443), tcp.DstPort)
}

func TestBPFFilterIPv6(t *testing.T) {
	t.Parallel()
	filter, _ := BPFFilter(&scan.Range{DstPrefix: netip.MustParsePrefix("2001:db8::/120")})
	require.Equal(t, "tcp and ip6 src net 2001:db8::/120", filter)
}

func TestSYNACKBPFFilterIPv6(t *testing.T) {
	t.Parallel()
	filter, _ := SYNACKBPFFilter(&scan.Range{DstPrefix: netip.MustParsePrefix("2001:db8::/120")})
	require.Equal(t, "tcp and ip6 src net 2001:db8::/120", filter)
}

func TestSYNACKBPFFilterIPv6Source(t *testing.T) {
	t.Parallel()
	filter, _ := SYNACKBPFFilter(&scan.Range{SrcIP: netip.MustParseAddr("2001:db8::1")})
	require.Equal(t, "tcp", filter)
}

func TestScanMethodProcessesScopedIPv6Response(t *testing.T) {
	t.Parallel()

	packet := gopacket.NewSerializeBuffer()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, EthernetType: layers.EthernetTypeIPv6}
	ipv6 := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolTCP, SrcIP: net.ParseIP("fe80::2"), DstIP: net.ParseIP("fe80::1")}
	tcpLayer := &layers.TCP{SrcPort: 443, DstPort: 40000, SYN: true, ACK: true}
	require.NoError(t, tcpLayer.SetNetworkLayerForChecksum(ipv6))
	require.NoError(t, gopacket.SerializeLayers(packet, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ipv6, tcpLayer))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := scan.NewResultChan(ctx, 1)
	method := NewScanMethod(SYNScanType, nil, results, WithScanIPv6(true), WithScanZone("en0"))
	require.NoError(t, method.ProcessPacketData(packet.Bytes(), &gopacket.CaptureInfo{}))
	result := (<-method.Results()).(*ScanResult)
	require.Equal(t, "fe80::2%en0", result.IP)
	require.Equal(t, uint16(443), result.Port)
}
