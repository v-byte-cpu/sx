package udp

import (
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
	err := NewPacketFiller(WithHopLimit(42), WithPayload([]byte("dns"))).Fill(packet, &scan.Request{
		SrcIP: netip.MustParseAddr("2001:db8::1"), DstIP: netip.MustParseAddr("2001:db8::2"), DstPort: 53,
		SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2},
	})
	require.NoError(t, err)

	decoded := gopacket.NewPacket(packet.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	ipv6 := decoded.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	require.Equal(t, uint8(42), ipv6.HopLimit)
	require.Equal(t, layers.IPProtocolUDP, ipv6.NextHeader)
	udp := decoded.Layer(layers.LayerTypeUDP).(*layers.UDP)
	require.Equal(t, layers.UDPPort(53), udp.DstPort)
	require.Equal(t, []byte("dns"), udp.Payload)
}
