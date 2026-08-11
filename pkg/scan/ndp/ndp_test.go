package ndp

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

func TestPacketFillerBuildsNeighborSolicitation(t *testing.T) {
	t.Parallel()

	packet := gopacket.NewSerializeBuffer()
	filler := NewPacketFiller()
	err := filler.Fill(packet, &scan.Request{
		SrcIP:  netip.MustParseAddr("fe80::2"),
		DstIP:  netip.MustParseAddr("fe80::1"),
		SrcMAC: net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
	})
	require.NoError(t, err)

	decoded := gopacket.NewPacket(packet.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	eth := decoded.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	require.Equal(t, net.HardwareAddr{0x33, 0x33, 0xff, 0, 0, 1}, eth.DstMAC)
	require.Equal(t, layers.EthernetTypeIPv6, eth.EthernetType)

	ipv6 := decoded.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	require.Equal(t, uint8(255), ipv6.HopLimit)
	require.Equal(t, layers.IPProtocolICMPv6, ipv6.NextHeader)
	require.Equal(t, net.ParseIP("ff02::1:ff00:1"), ipv6.DstIP)

	icmp := decoded.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	require.Equal(t, uint8(layers.ICMPv6TypeNeighborSolicitation), icmp.TypeCode.Type())

	ns := decoded.Layer(layers.LayerTypeICMPv6NeighborSolicitation).(*layers.ICMPv6NeighborSolicitation)
	require.Equal(t, net.ParseIP("fe80::1"), ns.TargetAddress)
	require.Len(t, ns.Options, 1)
	require.Equal(t, layers.ICMPv6OptSourceAddress, ns.Options[0].Type)
	require.Equal(t, []byte{0x02, 0, 0, 0, 0, 2}, ns.Options[0].Data)
}

func TestProcessPacketDataEmitsNeighbor(t *testing.T) {
	t.Parallel()

	packet := gopacket.NewSerializeBuffer()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ipv6 := &layers.IPv6{
		Version:    6,
		HopLimit:   255,
		NextHeader: layers.IPProtocolICMPv6,
		SrcIP:      net.ParseIP("fe80::1"),
		DstIP:      net.ParseIP("fe80::2"),
	}
	icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborAdvertisement, 0)}
	require.NoError(t, icmp.SetNetworkLayerForChecksum(ipv6))
	na := &layers.ICMPv6NeighborAdvertisement{
		Flags:         0x60,
		TargetAddress: net.ParseIP("fe80::1"),
		Options: layers.ICMPv6Options{{
			Type: layers.ICMPv6OptTargetAddress,
			Data: []byte{0x02, 0, 0, 0, 0, 1},
		}},
	}
	require.NoError(t, gopacket.SerializeLayers(packet, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ipv6, icmp, na))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := scan.NewResultChan(ctx, 1)
	method := NewScanMethod(nil, results, "en0")
	require.NoError(t, method.ProcessPacketData(packet.Bytes(), &gopacket.CaptureInfo{}))

	result := (<-method.Results()).(*neighbor.ScanResult)
	require.Equal(t, "fe80::1%en0", result.IP)
	require.Equal(t, "02:00:00:00:00:01", result.MAC)
}
