package ndp

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/v-byte-cpu/sx/pkg/scan"
)

func TestBPFFilter(t *testing.T) {
	t.Parallel()

	filter, maxPacketLength := BPFFilter(&scan.Range{DstPrefix: netip.MustParsePrefix("2001:db8::/120")})
	require.Equal(t, "icmp6 and icmp6[0] == 136 and src net 2001:db8::/120", filter)
	require.Equal(t, 1518, maxPacketLength)
}
