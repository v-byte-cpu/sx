package socks5

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/v-byte-cpu/sx/pkg/scan"
)

func TestDestinationIPv6(t *testing.T) {
	t.Parallel()
	require.Equal(t, "[2001:db8::1]:1080", destination(&scan.Request{
		DstIP: netip.MustParseAddr("2001:db8::1"), DstPort: 1080,
	}))
	require.Equal(t, "[fe80::1%en0]:1080", destination(&scan.Request{
		DstIP: netip.MustParseAddr("fe80::1%en0"), DstPort: 1080,
	}))
}
