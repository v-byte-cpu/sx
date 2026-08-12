package icmp

import (
	"net/netip"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/stretchr/testify/require"
	"github.com/v-byte-cpu/sx/pkg/scan"
)

func TestDiscoveryBPFFilter(t *testing.T) {
	t.Parallel()

	filter, maxPacketLength := DiscoveryBPFFilter(&scan.Range{
		SrcIP: netip.MustParseAddr("fe80::2"),
	})

	require.Equal(t, "icmp6 and icmp6[0] == 129 and icmp6[1] == 0 and ip6 dst host fe80::2", filter)
	require.Equal(t, MaxPacketLength, maxPacketLength)
	_, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, maxPacketLength, filter)
	require.NoError(t, err)
}
