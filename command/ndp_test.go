package command

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestNDPCmdRejectsIPv4(t *testing.T) {
	t.Parallel()

	cmd := newNDPCmd().cmd
	err := cmd.RunE(cmd, []string{"192.0.2.1"})
	require.EqualError(t, err, "NDP supports IPv6 only")
}

func TestNDPCmdOptsInitCliFlags(t *testing.T) {
	t.Parallel()

	var opts ndpCmdOpts
	cmd := &cobra.Command{}
	opts.initCliFlags(cmd)
	require.NoError(t, cmd.ParseFlags(strings.Fields("--file ips.jsonl --live 5s --srcip fe80::1%en0")))
	require.Equal(t, "ips.jsonl", opts.ipFile)
	require.Equal(t, "fe80::1%en0", opts.rawSrcIP)
}
