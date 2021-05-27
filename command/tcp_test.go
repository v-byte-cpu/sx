package command

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"github.com/v-byte-cpu/sx/pkg/scan"
)

func TestTCPCmdDstSubnetError(t *testing.T) {
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
			f := func(cmd *cobra.Command) {
				err := cmd.RunE(cmd, tt.args)
				require.Error(t, err)
			}
			f(newTCPFlagsCmd().cmd)
			f(newTCPSYNCmd().cmd)
			f(newTCPFINCmd().cmd)
			f(newTCPNULLCmd().cmd)
			f(newTCPXmasCmd().cmd)
		})
	}
}

func TestTCPCmdOptsInitCliFlags(t *testing.T) {
	t.Parallel()
	var opts tcpFlagsCmdOpts
	cmd := &cobra.Command{}

	opts.initCliFlags(cmd)
	err := cmd.ParseFlags(strings.Split(
		strings.Join([]string{
			"--json -i eth0 --srcip 192.168.0.1 --srcmac 00:11:22:33:44:55 -r 500/7s --exit-delay 10s",
			"--gwmac 11:22:33:44:55:66 -f ip_file.jsonl -a arp.cache",
			"-p 23-57,71-2733",
			"--flags syn,fin",
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

	require.Equal(t, "23-57,71-2733", opts.rawPortRanges)

	require.Equal(t, "syn,fin", opts.rawTCPFlags)
}

func TestTCPCmdOptsParseRawOptions(t *testing.T) {
	t.Parallel()
	opts := &tcpFlagsCmdOpts{
		tcpCmdOpts: tcpCmdOpts{
			ipPortScanCmdOpts: ipPortScanCmdOpts{
				ipScanCmdOpts: ipScanCmdOpts{
					packetScanCmdOpts: packetScanCmdOpts{
						rawSrcMAC:    "00:11:22:33:44:55",
						rawRateLimit: "500/7s",
					},
					rawGatewayMAC: "11:22:33:44:55:66",
				},
				rawPortRanges: "23-57,71-2733",
			},
		},
		rawTCPFlags: "syn,fin",
	}

	err := opts.parseRawOptions()

	require.NoError(t, err)
	require.Equal(t, net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, opts.srcMAC)
	require.Equal(t, 500, opts.rateCount)
	require.Equal(t, 7*time.Second, opts.rateWindow)

	require.Equal(t, net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}, opts.gatewayMAC)
	require.Equal(t, []*scan.PortRange{
		{StartPort: 23, EndPort: 57},
		{StartPort: 71, EndPort: 2733}}, opts.portRanges)

	require.Equal(t, []string{"syn", "fin"}, opts.tcpFlags)
}

func TestParseTCPFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "EmptyFlags",
			input:    "",
			expected: []string{},
		},
		{
			name:     "SynFlag",
			input:    "syn",
			expected: []string{"syn"},
		},
		{
			name:     "AckFlag",
			input:    "ack",
			expected: []string{"ack"},
		},
		{
			name:     "FinFlag",
			input:    "fin",
			expected: []string{"fin"},
		},
		{
			name:     "RstFlag",
			input:    "rst",
			expected: []string{"rst"},
		},
		{
			name:     "PshFlag",
			input:    "psh",
			expected: []string{"psh"},
		},
		{
			name:     "UrgFlag",
			input:    "urg",
			expected: []string{"urg"},
		},
		{
			name:     "EceFlag",
			input:    "ece",
			expected: []string{"ece"},
		},
		{
			name:     "CwrFlag",
			input:    "cwr",
			expected: []string{"cwr"},
		},
		{
			name:     "NsFlag",
			input:    "ns",
			expected: []string{"ns"},
		},
		{
			name:     "SynAckFlag",
			input:    "syn,ack",
			expected: []string{"syn", "ack"},
		},
		{
			name:     "AckFinFlag",
			input:    "ack,fin",
			expected: []string{"ack", "fin"},
		},
		{
			name:     "CwrNsFlag",
			input:    "cwr,ns",
			expected: []string{"cwr", "ns"},
		},
		{
			name:     "AllFlags",
			input:    "syn,ack,fin,rst,psh,urg,ece,cwr,ns",
			expected: []string{"syn", "ack", "fin", "rst", "psh", "urg", "ece", "cwr", "ns"},
		},
		{
			name:     "UpperAndLowerCase",
			input:    "SyN,ACK",
			expected: []string{"syn", "ack"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseTCPFlags(tt.input)
			require.NoError(t, err)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestParseTCPFlagsError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "OneInvalidFlag",
			input: "abc",
		},
		{
			name:  "OneValidAndInvalidFlag",
			input: "syn,abc",
		},
		{
			name:  "TwoValidAndInvalidFlag",
			input: "syn,abc,ack",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseTCPFlags(tt.input)
			require.Error(t, err)
		})
	}
}
