package icmp

import (
	"context"
	"encoding/json"
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
	err := NewPacketFiller(WithHopLimit(37), WithICMPv6Type(layers.ICMPv6TypeEchoRequest)).Fill(packet, &scan.Request{
		SrcIP: netip.MustParseAddr("2001:db8::1"), DstIP: netip.MustParseAddr("2001:db8::2"),
		SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2},
	})
	require.NoError(t, err)

	decoded := gopacket.NewPacket(packet.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	ipv6 := decoded.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	require.Equal(t, uint8(37), ipv6.HopLimit)
	require.Equal(t, layers.IPProtocolICMPv6, ipv6.NextHeader)
	require.Equal(t, net.ParseIP("2001:db8::2"), ipv6.DstIP)
	icmpv6 := decoded.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	require.Equal(t, uint8(layers.ICMPv6TypeEchoRequest), icmpv6.TypeCode.Type())
}

func TestPacketProcessorIPv6ReportsHopLimit(t *testing.T) {
	t.Parallel()

	packet := gopacket.NewSerializeBuffer()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, EthernetType: layers.EthernetTypeIPv6}
	ipv6 := &layers.IPv6{Version: 6, HopLimit: 51, NextHeader: layers.IPProtocolICMPv6, SrcIP: net.ParseIP("2001:db8::2"), DstIP: net.ParseIP("2001:db8::1")}
	icmpv6 := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoReply, 0)}
	require.NoError(t, icmpv6.SetNetworkLayerForChecksum(ipv6))
	require.NoError(t, gopacket.SerializeLayers(packet, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ipv6, icmpv6, gopacket.Payload([]byte{0, 1, 0, 1})))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	processor := NewPacketProcessor(ScanType, scan.NewResultChan(ctx, 1), false, true)
	require.NoError(t, processor.ProcessPacketData(packet.Bytes(), &gopacket.CaptureInfo{}))
	result := (<-processor.Results()).(*ScanResult)
	require.Equal(t, "2001:db8::2", result.IP)
	require.Equal(t, uint8(51), result.HopLimit)
	require.Zero(t, result.TTL)
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	require.JSONEq(t, `{"scan":"icmp","ip":"2001:db8::2","hop_limit":51,"icmp":{"type":129,"code":0}}`, string(encoded))
}
