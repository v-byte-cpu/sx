package command

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRootRegistersICMPDiscover(t *testing.T) {
	t.Parallel()

	cmd, _, err := newRootCmd("test").Find([]string{"icmp", "discover"})

	require.NoError(t, err)
	require.Equal(t, "discover", cmd.Name())
}

func TestParseICMPDiscoveryGroup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		input          string
		expectedPrefix netip.Prefix
		expectedZone   string
	}{
		{
			name:           "DefaultAllNodes",
			expectedPrefix: netip.MustParsePrefix("ff02::1/128"),
		},
		{
			name:           "ScopedGroup",
			input:          "ff02::fb%en0",
			expectedPrefix: netip.MustParsePrefix("ff02::fb/128"),
			expectedZone:   "en0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			prefix, zone, err := parseICMPDiscoveryGroup(tt.input)

			require.NoError(t, err)
			require.Equal(t, tt.expectedPrefix, prefix)
			require.Equal(t, tt.expectedZone, zone)
		})
	}
}

func TestParseICMPDiscoveryGroupRejectsInvalidTargets(t *testing.T) {
	t.Parallel()

	for _, target := range []string{
		"192.0.2.1",
		"fe80::1",
		"ff05::1",
		"ff02::1/128",
	} {
		t.Run(target, func(t *testing.T) {
			t.Parallel()

			_, _, err := parseICMPDiscoveryGroup(target)

			require.ErrorIs(t, err, errICMPDiscoveryGroup)
		})
	}
}

func TestICMPDiscoverCmdFlags(t *testing.T) {
	t.Parallel()

	c := newICMPDiscoverCmd()

	require.NotNil(t, c.cmd.Flags().Lookup("iface"))
	require.NotNil(t, c.cmd.Flags().Lookup("json"))
	require.NotNil(t, c.cmd.Flags().Lookup("exit-delay"))
	require.NotNil(t, c.cmd.Flags().Lookup("srcip"))
	require.Nil(t, c.cmd.Flags().Lookup("srcmac"))
	require.Nil(t, c.cmd.Flags().Lookup("rate"))
	require.Equal(t, time.Second, c.opts.exitDelay)

	require.NoError(t, c.cmd.ParseFlags([]string{"--srcip", "fe80::1234%en0"}))
	require.Equal(t, "fe80::1234%en0", c.opts.rawSrcIP)
}

func TestICMPDiscoverCmdRequiresInterface(t *testing.T) {
	t.Parallel()

	c := newICMPDiscoverCmd()
	err := c.cmd.RunE(c.cmd, nil)

	require.ErrorIs(t, err, errICMPDiscoveryInterfaceRequired)
}

func TestValidateICMPDiscoveryZone(t *testing.T) {
	t.Parallel()

	require.NoError(t, validateICMPDiscoveryZone("", "en0"))
	require.NoError(t, validateICMPDiscoveryZone("en0", "en0"))
	require.ErrorIs(t, validateICMPDiscoveryZone("en1", "en0"), errSrcInterface)
}

func TestICMPDiscoverCmdRejectsMismatchedScope(t *testing.T) {
	t.Parallel()

	c := newICMPDiscoverCmd()
	require.NoError(t, c.cmd.ParseFlags([]string{"--iface", "en0"}))

	err := c.cmd.RunE(c.cmd, []string{"ff02::1%en1"})

	require.ErrorIs(t, err, errSrcInterface)
}

func TestValidateICMPDiscoverySourceIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		source  string
		wantErr bool
	}{
		{name: "LinkLocal", source: "fe80::1234"},
		{name: "ScopedLinkLocal", source: "fe80::1234%en0"},
		{name: "IPv4", source: "192.0.2.1", wantErr: true},
		{name: "GlobalIPv6", source: "2001:db8::1", wantErr: true},
		{name: "UnspecifiedIPv6", source: "::", wantErr: true},
		{name: "MulticastIPv6", source: "ff02::1", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateICMPDiscoverySourceIP(netip.MustParseAddr(tt.source))

			if tt.wantErr {
				require.ErrorIs(t, err, errSrcIP)
				return
			}
			require.NoError(t, err)
		})
	}
}
