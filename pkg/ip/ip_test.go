package ip

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParsePrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		input          string
		expectedPrefix netip.Prefix
		expectedZone   string
	}{
		{
			name:           "IPv4Host",
			input:          "192.0.2.1",
			expectedPrefix: netip.MustParsePrefix("192.0.2.1/32"),
		},
		{
			name:           "ScopedIPv6Prefix",
			input:          "fe80::1%en0/64",
			expectedPrefix: netip.MustParsePrefix("fe80::/64"),
			expectedZone:   "en0",
		},
		{
			name:           "IPv6Prefix",
			input:          "2001:db8::1/64",
			expectedPrefix: netip.MustParsePrefix("2001:db8::/64"),
		},
		{
			name:           "ScopedIPv6Host",
			input:          "fe80::1%en0",
			expectedPrefix: netip.MustParsePrefix("fe80::1/128"),
			expectedZone:   "en0",
		},
		{
			name:           "IPv4MappedHost",
			input:          "::ffff:192.0.2.1",
			expectedPrefix: netip.MustParsePrefix("192.0.2.1/32"),
		},
		{
			name:           "IPv4MappedPrefix",
			input:          "::ffff:192.0.2.1/128",
			expectedPrefix: netip.MustParsePrefix("192.0.2.1/32"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			prefix, zone, err := ParsePrefix(tt.input)

			require.NoError(t, err)
			require.Equal(t, tt.expectedPrefix, prefix)
			require.Equal(t, tt.expectedZone, zone)
		})
	}
}

func TestSelectInterfaceIPByAddressFamilyAndScope(t *testing.T) {
	t.Parallel()

	addresses := []netip.Prefix{
		netip.MustParsePrefix("fe80::2/64"),
		netip.MustParsePrefix("2001:db8::2/64"),
		netip.MustParsePrefix("192.0.2.2/24"),
	}

	tests := []struct {
		name     string
		target   netip.Addr
		expected netip.Addr
	}{
		{name: "IPv4", target: netip.MustParseAddr("198.51.100.1"), expected: netip.MustParseAddr("192.0.2.2")},
		{name: "IPv6Global", target: netip.MustParseAddr("2001:db8:1::1"), expected: netip.MustParseAddr("2001:db8::2")},
		{name: "IPv6LinkLocal", target: netip.MustParseAddr("fe80::1"), expected: netip.MustParseAddr("fe80::2")},
		{name: "IPv6LinkLocalMulticast", target: netip.MustParseAddr("ff02::1"), expected: netip.MustParseAddr("fe80::2")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.expected, selectInterfaceIP(addresses, tt.target))
		})
	}
}
