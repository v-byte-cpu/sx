package command

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestArpCmdDstSubnetRequiredArg(t *testing.T) {
	cmd := newARPCmd().cmd
	err := cmd.Execute()
	require.Error(t, err)
	require.Equal(t, "requires one ip subnet argument", err.Error())
}

func TestArpCmdInvalidDstSubnet(t *testing.T) {
	cmd := newARPCmd().cmd
	cmd.SetArgs([]string{"invalid_ip_address"})
	err := cmd.Execute()
	require.Error(t, err)
}
