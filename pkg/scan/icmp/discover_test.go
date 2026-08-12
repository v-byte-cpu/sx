package icmp

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"github.com/v-byte-cpu/sx/pkg/scan"
	"github.com/v-byte-cpu/sx/pkg/scan/neighbor"
)

func TestDiscoveryPacketFillerBuildsMulticastEchoRequest(t *testing.T) {
	t.Parallel()

	probe := DiscoveryProbe{
		Identifier: 0x1234,
		Sequence:   1,
		Nonce:      [discoveryNonceSize]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	}
	packet := gopacket.NewSerializeBuffer()
	err := NewDiscoveryPacketFiller(probe).Fill(packet, &scan.Request{
		SrcIP:  netip.MustParseAddr("fe80::2"),
		DstIP:  netip.MustParseAddr("ff02::1234:5678"),
		SrcMAC: net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
	})
	require.NoError(t, err)

	decoded := gopacket.NewPacket(packet.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	eth, ok := decoded.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	require.True(t, ok)
	require.Equal(t, net.HardwareAddr{0x33, 0x33, 0x12, 0x34, 0x56, 0x78}, eth.DstMAC)
	require.Equal(t, layers.EthernetTypeIPv6, eth.EthernetType)

	ipv6, ok := decoded.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	require.True(t, ok)
	require.Equal(t, uint8(1), ipv6.HopLimit)
	require.Equal(t, layers.IPProtocolICMPv6, ipv6.NextHeader)
	require.Equal(t, net.ParseIP("fe80::2"), ipv6.SrcIP)
	require.Equal(t, net.ParseIP("ff02::1234:5678"), ipv6.DstIP)

	icmpv6, ok := decoded.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	require.True(t, ok)
	require.Equal(t, uint8(layers.ICMPv6TypeEchoRequest), icmpv6.TypeCode.Type())
	require.Zero(t, icmpv6.TypeCode.Code())

	echo, ok := decoded.Layer(layers.LayerTypeICMPv6Echo).(*layers.ICMPv6Echo)
	require.True(t, ok)
	require.Equal(t, probe.Identifier, echo.Identifier)
	require.Equal(t, probe.Sequence, echo.SeqNumber)
	require.Equal(t, probe.Nonce[:], icmpv6.Payload[4:])
}

func TestDiscoveryPacketFillerRejectsInvalidLinkData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		request *scan.Request
		err     error
	}{
		{
			name: "GlobalSourceIP",
			request: &scan.Request{
				SrcIP: netip.MustParseAddr("2001:db8::2"), DstIP: netip.MustParseAddr("ff02::1"),
				SrcMAC: net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
			},
			err: errDiscoveryIPv6Addresses,
		},
		{
			name: "UnicastDestinationIP",
			request: &scan.Request{
				SrcIP: netip.MustParseAddr("fe80::2"), DstIP: netip.MustParseAddr("fe80::1"),
				SrcMAC: net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
			},
			err: errDiscoveryIPv6Addresses,
		},
		{
			name: "MulticastSourceMAC",
			request: &scan.Request{
				SrcIP: netip.MustParseAddr("fe80::2"), DstIP: netip.MustParseAddr("ff02::1"),
				SrcMAC: net.HardwareAddr{0x33, 0x33, 0, 0, 0, 2},
			},
			err: errDiscoverySourceMAC,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := NewDiscoveryPacketFiller(testDiscoveryProbe()).Fill(gopacket.NewSerializeBuffer(), tt.request)

			require.ErrorIs(t, err, tt.err)
		})
	}
}

func TestDiscoveryScanMethodEmitsCorrelatedNeighbor(t *testing.T) {
	t.Parallel()

	probe := testDiscoveryProbe()
	packet := serializeDiscoveryReply(t, probe, "fe80::1", "fe80::2", net.HardwareAddr{0x02, 0, 0, 0, 0, 1})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	method := NewDiscoveryScanMethod(nil, scan.NewResultChan(ctx, 1), probe, netip.MustParseAddr("fe80::2"), "en0")

	require.NoError(t, method.ProcessPacketData(packet, &gopacket.CaptureInfo{}))

	result := (<-method.Results()).(*neighbor.ScanResult)
	require.Equal(t, "fe80::1%en0", result.IP)
	require.Equal(t, "02:00:00:00:00:01", result.MAC)
}

func TestDiscoveryScanMethodRejectsUncorrelatedReplies(t *testing.T) {
	t.Parallel()

	probe := testDiscoveryProbe()
	tests := []struct {
		name      string
		probe     DiscoveryProbe
		sourceIP  string
		destIP    string
		sourceMAC net.HardwareAddr
	}{
		{
			name:      "WrongIdentifier",
			probe:     DiscoveryProbe{Identifier: probe.Identifier + 1, Sequence: probe.Sequence, Nonce: probe.Nonce},
			sourceIP:  "fe80::1",
			destIP:    "fe80::2",
			sourceMAC: net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		},
		{
			name:      "WrongNonce",
			probe:     DiscoveryProbe{Identifier: probe.Identifier, Sequence: probe.Sequence, Nonce: [discoveryNonceSize]byte{0xff}},
			sourceIP:  "fe80::1",
			destIP:    "fe80::2",
			sourceMAC: net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		},
		{
			name:      "WrongDestination",
			probe:     probe,
			sourceIP:  "fe80::1",
			destIP:    "fe80::3",
			sourceMAC: net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		},
		{
			name:      "MulticastSourceIP",
			probe:     probe,
			sourceIP:  "ff02::1",
			destIP:    "fe80::2",
			sourceMAC: net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		},
		{
			name:      "MulticastSourceMAC",
			probe:     probe,
			sourceIP:  "fe80::1",
			destIP:    "fe80::2",
			sourceMAC: net.HardwareAddr{0x33, 0x33, 0, 0, 0, 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			packet := serializeDiscoveryReply(t, tt.probe, tt.sourceIP, tt.destIP, tt.sourceMAC)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			method := NewDiscoveryScanMethod(nil, scan.NewResultChan(ctx, 1), probe, netip.MustParseAddr("fe80::2"), "en0")

			require.NoError(t, method.ProcessPacketData(packet, &gopacket.CaptureInfo{}))
			select {
			case result := <-method.Results():
				require.Fail(t, "unexpected result", "%v", result)
			default:
			}
		})
	}
}

func testDiscoveryProbe() DiscoveryProbe {
	return DiscoveryProbe{
		Identifier: 0x1234,
		Sequence:   1,
		Nonce:      [discoveryNonceSize]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	}
}

func serializeDiscoveryReply(
	t *testing.T,
	probe DiscoveryProbe,
	sourceIP string,
	destinationIP string,
	sourceMAC net.HardwareAddr,
) []byte {
	t.Helper()

	packet := gopacket.NewSerializeBuffer()
	ethernet := &layers.Ethernet{
		SrcMAC:       sourceMAC,
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ipv6 := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		NextHeader: layers.IPProtocolICMPv6,
		SrcIP:      net.ParseIP(sourceIP),
		DstIP:      net.ParseIP(destinationIP),
	}
	icmpv6 := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoReply, 0)}
	require.NoError(t, icmpv6.SetNetworkLayerForChecksum(ipv6))
	echo := &layers.ICMPv6Echo{Identifier: probe.Identifier, SeqNumber: probe.Sequence}
	require.NoError(t, gopacket.SerializeLayers(
		packet,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ethernet,
		ipv6,
		icmpv6,
		echo,
		gopacket.Payload(probe.Nonce[:]),
	))
	return packet.Bytes()
}
