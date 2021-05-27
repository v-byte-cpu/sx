package command

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestSocksCmdDstSubnetError(t *testing.T) {
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
			cmd := newSocksCmd().cmd
			err := cmd.RunE(cmd, tt.args)
			require.Error(t, err)
		})
	}
}

func TestSocksCmdOptsInitCliFlags(t *testing.T) {
	t.Parallel()
	var opts socksCmdOpts
	cmd := &cobra.Command{}

	opts.initCliFlags(cmd)
	err := cmd.ParseFlags(strings.Split(
		"--json -p 23-57,71-2733 -f ip_file.jsonl -w 300 --exit-delay 10s --timeout 2s", " "))

	require.NoError(t, err)
	require.Equal(t, true, opts.json)
	require.Equal(t, "23-57,71-2733", opts.rawPortRanges)
	require.Equal(t, "ip_file.jsonl", opts.ipFile)
	require.Equal(t, 300, opts.workers)
	require.Equal(t, 10*time.Second, opts.exitDelay)

	require.Equal(t, 2*time.Second, opts.timeout)
}
