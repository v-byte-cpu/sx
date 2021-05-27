package command

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestArpCmdDstSubnetRequiredArg(t *testing.T) {
	t.Parallel()
	cmd := newARPCmd().cmd
	err := cmd.RunE(cmd, nil)
	require.Error(t, err)
	require.Equal(t, "requires one ip subnet argument", err.Error())
}

func TestArpCmdInvalidDstSubnet(t *testing.T) {
	t.Parallel()
	cmd := newARPCmd().cmd
	err := cmd.RunE(cmd, []string{"invalid_ip_address"})
	require.Error(t, err)
}
