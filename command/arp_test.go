package command

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestArpCmdDstSubnetError(t *testing.T) {
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
			cmd := newARPCmd().cmd
			err := cmd.RunE(cmd, tt.args)
			require.Error(t, err)
		})
	}
}

func TestARPCmdOptsInitCliFlags(t *testing.T) {
	t.Parallel()
	var opts arpCmdOpts
	cmd := &cobra.Command{}

	opts.initCliFlags(cmd)
	err := cmd.ParseFlags(strings.Split(
		strings.Join([]string{
			"--json -i eth0 --srcip 192.168.0.1 --srcmac 00:11:22:33:44:55 -r 500/7s --exit-delay 10s",
			"--live 5s",
		}, " "), " "))

	require.NoError(t, err)
	require.Equal(t, true, opts.json)
	require.Equal(t, "eth0", opts.rawInterface)
	require.Equal(t, net.IPv4(192, 168, 0, 1), opts.srcIP)
	require.Equal(t, "00:11:22:33:44:55", opts.rawSrcMAC)
	require.Equal(t, "500/7s", opts.rawRateLimit)
	require.Equal(t, 10*time.Second, opts.exitDelay)
	require.Equal(t, 5*time.Second, opts.liveTimeout)
}
