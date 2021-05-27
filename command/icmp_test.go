package command

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestICMPCmdDstSubnetError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "RequiredArg",
			args: nil,
		},
		{
			name: "InvalidDstSubnet",
			args: []string{"invalid_ip_address"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newICMPCmd().cmd
			err := cmd.RunE(cmd, tt.args)
			require.Error(t, err)
		})
	}
}

func TestICMPCmdOptsInitCliFlags(t *testing.T) {
	t.Parallel()
	var opts icmpCmdOpts
	cmd := &cobra.Command{}

	opts.initCliFlags(cmd)
	err := cmd.ParseFlags(strings.Split(
		strings.Join([]string{
			"--json -i eth0 --srcip 192.168.0.1 --srcmac 00:11:22:33:44:55 -r 500/7s --exit-delay 10s",
			"--gwmac 11:22:33:44:55:66 -f ip_file.jsonl -a arp.cache",
			`--ttl 128 --ipproto 6 --iplen 11 --ipflags df,mf --type 3 --code 5 --payload \x01\x02\x03`,
		}, " "), " "))

	require.NoError(t, err)
	require.Equal(t, true, opts.json)
	require.Equal(t, "eth0", opts.rawInterface)
	require.Equal(t, net.IPv4(192, 168, 0, 1), opts.srcIP)
	require.Equal(t, "00:11:22:33:44:55", opts.rawSrcMAC)
	require.Equal(t, "500/7s", opts.rawRateLimit)
	require.Equal(t, 10*time.Second, opts.exitDelay)

	require.Equal(t, "11:22:33:44:55:66", opts.rawGatewayMAC)
	require.Equal(t, "ip_file.jsonl", opts.ipFile)
	require.Equal(t, "arp.cache", opts.arpCacheFile)

	require.Equal(t, uint8(128), opts.ipTTL)
	require.Equal(t, uint8(6), opts.ipProtocol)
	require.Equal(t, uint16(11), opts.ipTotalLen)
	require.Equal(t, "df,mf", opts.rawIPFlags)
	require.Equal(t, uint8(3), opts.icmpType)
	require.Equal(t, uint8(5), opts.icmpCode)
	require.Equal(t, `\x01\x02\x03`, opts.rawICMPPayload)
}

func TestICMPCmdOptsParseRawOptions(t *testing.T) {
	t.Parallel()
	opts := &icmpCmdOpts{
		ipScanCmdOpts: ipScanCmdOpts{
			packetScanCmdOpts: packetScanCmdOpts{
				rawSrcMAC:    "00:11:22:33:44:55",
				rawRateLimit: "500/7s",
			},
			rawGatewayMAC: "11:22:33:44:55:66",
		},
		rawIPFlags:     "df,mf",
		rawICMPPayload: `\x01\x02\x03`,
	}

	err := opts.parseRawOptions()

	require.NoError(t, err)
	require.Equal(t, net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, opts.srcMAC)
	require.Equal(t, 500, opts.rateCount)
	require.Equal(t, 7*time.Second, opts.rateWindow)

	require.Equal(t, net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}, opts.gatewayMAC)

	require.Equal(t, uint8(layers.IPv4DontFragment)|uint8(layers.IPv4MoreFragments), opts.ipFlags)
	require.Equal(t, []byte{1, 2, 3}, opts.icmpPayload)
}
