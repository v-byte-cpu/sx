package command

import (
	"errors"
	"io"
	"io/ioutil"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"github.com/v-byte-cpu/sx/pkg/scan"
)

func TestPacketScanCmdOptsInitCliFlags(t *testing.T) {
	t.Parallel()
	var opts packetScanCmdOpts
	cmd := &cobra.Command{}

	opts.initCliFlags(cmd)
	err := cmd.ParseFlags(strings.Split(
		"--json -i eth0 --srcip 192.168.0.1 --srcmac 00:11:22:33:44:55 -r 500/7s --exit-delay 10s --exclude ips.txt", " "))

	require.NoError(t, err)
	require.Equal(t, true, opts.json)
	require.Equal(t, "eth0", opts.rawInterface)
	require.Equal(t, net.IPv4(192, 168, 0, 1), opts.srcIP)
	require.Equal(t, "00:11:22:33:44:55", opts.rawSrcMAC)
	require.Equal(t, "500/7s", opts.rawRateLimit)
	require.Equal(t, 10*time.Second, opts.exitDelay)
	require.Equal(t, "ips.txt", opts.rawExcludeFile)
}

func TestPacketScanCmdOptsParseRawOptions(t *testing.T) {
	t.Parallel()
	opts := &packetScanCmdOpts{
		rawSrcMAC:    "00:11:22:33:44:55",
		rawRateLimit: "500/7s",
	}

	err := opts.parseRawOptions()

	require.NoError(t, err)
	require.Equal(t, net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, opts.srcMAC)
	require.Equal(t, 500, opts.rateCount)
	require.Equal(t, 7*time.Second, opts.rateWindow)
}

func TestIPScanCmdOptsInitCliFlags(t *testing.T) {
	t.Parallel()
	var opts ipScanCmdOpts
	cmd := &cobra.Command{}

	opts.initCliFlags(cmd)
	err := cmd.ParseFlags(strings.Split(
		strings.Join([]string{
			"--json -i eth0 --srcip 192.168.0.1 --srcmac 00:11:22:33:44:55 -r 500/7s --exit-delay 10s --exclude ips.txt",
			"--gwmac 11:22:33:44:55:66 -f ip_file.jsonl -a arp.cache",
		}, " "), " "))

	require.NoError(t, err)
	require.Equal(t, true, opts.json)
	require.Equal(t, "eth0", opts.rawInterface)
	require.Equal(t, net.IPv4(192, 168, 0, 1), opts.srcIP)
	require.Equal(t, "00:11:22:33:44:55", opts.rawSrcMAC)
	require.Equal(t, "500/7s", opts.rawRateLimit)
	require.Equal(t, 10*time.Second, opts.exitDelay)
	require.Equal(t, "ips.txt", opts.rawExcludeFile)

	require.Equal(t, "11:22:33:44:55:66", opts.rawGatewayMAC)
	require.Equal(t, "ip_file.jsonl", opts.ipFile)
	require.Equal(t, "arp.cache", opts.arpCacheFile)
}

func TestIPScanCmdOptsParseRawOptions(t *testing.T) {
	t.Parallel()
	opts := &ipScanCmdOpts{
		packetScanCmdOpts: packetScanCmdOpts{
			rawSrcMAC:    "00:11:22:33:44:55",
			rawRateLimit: "500/7s",
		},
		rawGatewayMAC: "11:22:33:44:55:66",
	}

	err := opts.parseRawOptions()

	require.NoError(t, err)
	require.Equal(t, net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, opts.srcMAC)
	require.Equal(t, 500, opts.rateCount)
	require.Equal(t, 7*time.Second, opts.rateWindow)

	require.Equal(t, net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}, opts.gatewayMAC)
}

func TestIPPortScanCmdOptsInitCliFlags(t *testing.T) {
	t.Parallel()
	var opts ipPortScanCmdOpts
	cmd := &cobra.Command{}

	opts.initCliFlags(cmd)
	err := cmd.ParseFlags(strings.Split(
		strings.Join([]string{
			"--json -i eth0 --srcip 192.168.0.1 --srcmac 00:11:22:33:44:55 -r 500/7s --exit-delay 10s --exclude ips.txt",
			"--gwmac 11:22:33:44:55:66 -f ip_file.jsonl -a arp.cache",
			"-p 23-57,71-2733",
		}, " "), " "))

	require.NoError(t, err)
	require.Equal(t, true, opts.json)
	require.Equal(t, "eth0", opts.rawInterface)
	require.Equal(t, net.IPv4(192, 168, 0, 1), opts.srcIP)
	require.Equal(t, "00:11:22:33:44:55", opts.rawSrcMAC)
	require.Equal(t, "500/7s", opts.rawRateLimit)
	require.Equal(t, 10*time.Second, opts.exitDelay)
	require.Equal(t, "ips.txt", opts.rawExcludeFile)

	require.Equal(t, "11:22:33:44:55:66", opts.rawGatewayMAC)
	require.Equal(t, "ip_file.jsonl", opts.ipFile)
	require.Equal(t, "arp.cache", opts.arpCacheFile)

	require.Equal(t, "23-57,71-2733", opts.rawPortRanges)
}

func TestIPPortScanCmdOptsParseRawOptions(t *testing.T) {
	t.Parallel()
	opts := ipPortScanCmdOpts{
		ipScanCmdOpts: ipScanCmdOpts{
			packetScanCmdOpts: packetScanCmdOpts{
				rawSrcMAC:    "00:11:22:33:44:55",
				rawRateLimit: "500/7s",
			},
			rawGatewayMAC: "11:22:33:44:55:66",
		},
		rawPortRanges: "23-57,71-2733",
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
}

func TestGenericScanCmdOptsInitCliFlags(t *testing.T) {
	t.Parallel()
	var opts genericScanCmdOpts
	cmd := &cobra.Command{}

	opts.initCliFlags(cmd)
	err := cmd.ParseFlags(strings.Split(
		"--json -p 23-57,71-2733 -f ip_file.jsonl -w 300 -r 500/7s --exit-delay 10s --exclude ips.txt", " "))

	require.NoError(t, err)
	require.Equal(t, true, opts.json)
	require.Equal(t, "23-57,71-2733", opts.rawPortRanges)
	require.Equal(t, "ip_file.jsonl", opts.ipFile)
	require.Equal(t, 300, opts.workers)
	require.Equal(t, "500/7s", opts.rawRateLimit)
	require.Equal(t, 10*time.Second, opts.exitDelay)
	require.Equal(t, "ips.txt", opts.rawExcludeFile)
}

func TestGenericScanCmdOptsParseRawOptions(t *testing.T) {
	t.Parallel()
	opts := genericScanCmdOpts{
		rawPortRanges: "23-57,71-2733",
		rawRateLimit:  "500/7s",
		workers:       300,
	}

	err := opts.parseRawOptions()

	require.NoError(t, err)
	require.Equal(t, []*scan.PortRange{
		{StartPort: 23, EndPort: 57},
		{StartPort: 71, EndPort: 2733}}, opts.portRanges)
	require.Equal(t, 500, opts.rateCount)
	require.Equal(t, 7*time.Second, opts.rateWindow)
}

func TestIPScanCmdOptsIsARPCacheFromStdin(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		opts     ipScanCmdOpts
		expected bool
	}{
		{
			name:     "CacheFromFile",
			opts:     ipScanCmdOpts{arpCacheFile: "arp.cache"},
			expected: false,
		},
		{
			name:     "CacheFromStdin",
			opts:     ipScanCmdOpts{arpCacheFile: ""},
			expected: true,
		},
		{
			name:     "CacheFromStdinExplicit",
			opts:     ipScanCmdOpts{arpCacheFile: "-"},
			expected: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, tt.opts.isARPCacheFromStdin())
		})
	}
}

func TestIPScanCmdOptsValidateStdin(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		opts      ipScanCmdOpts
		shouldErr bool
	}{
		{
			name: "CacheFromStdinAndNoIPFile",
			opts: ipScanCmdOpts{arpCacheFile: "", ipFile: ""},
		},
		{
			name: "CacheFromStdinAndIPFile",
			opts: ipScanCmdOpts{arpCacheFile: "", ipFile: "ip_file"},
		},
		{
			name:      "CacheFromStdinAndIPFileFromStdin",
			opts:      ipScanCmdOpts{arpCacheFile: "", ipFile: "-"},
			shouldErr: true,
		},
		{
			name: "CacheFromStdinExplicitAndNoIPFile",
			opts: ipScanCmdOpts{arpCacheFile: "-", ipFile: ""},
		},
		{
			name: "CacheFromStdinExplicitAndIPFile",
			opts: ipScanCmdOpts{arpCacheFile: "-", ipFile: "ip_file"},
		},
		{
			name:      "CacheFromStdinExplicitAndIPFileFromStdin",
			opts:      ipScanCmdOpts{arpCacheFile: "-", ipFile: "-"},
			shouldErr: true,
		},
		{
			name: "CacheFromFileAndNoIPFile",
			opts: ipScanCmdOpts{arpCacheFile: "arp.cache", ipFile: ""},
		},
		{
			name: "CacheFromFileAndIPFile",
			opts: ipScanCmdOpts{arpCacheFile: "arp.cache", ipFile: "ip_file"},
		},
		{
			name: "CacheFromFileAndIPFileFromStdin",
			opts: ipScanCmdOpts{arpCacheFile: "arp.cache", ipFile: "-"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.opts.validateStdin()
			if tt.shouldErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestIPScanCmdOptsParseDstSubnet(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		opts      ipScanCmdOpts
		args      []string
		expected  *net.IPNet
		shouldErr bool
	}{
		{
			name:     "ValidDstHost",
			opts:     ipScanCmdOpts{},
			args:     []string{"192.168.0.1"},
			expected: &net.IPNet{IP: net.IPv4(192, 168, 0, 1).To4(), Mask: net.IPv4Mask(255, 255, 255, 255)},
		},
		{
			name:     "ValidDstSubnet",
			opts:     ipScanCmdOpts{},
			args:     []string{"10.0.0.1/16"},
			expected: &net.IPNet{IP: net.IPv4(10, 0, 0, 0).To4(), Mask: net.IPv4Mask(255, 255, 0, 0)},
		},
		{
			name:     "IPFile",
			opts:     ipScanCmdOpts{ipFile: "ip_file"},
			args:     []string{},
			expected: nil,
		},
		{
			name:      "NoIPHosts",
			opts:      ipScanCmdOpts{ipFile: ""},
			args:      []string{},
			shouldErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.opts.parseDstSubnet(tt.args)
			if tt.shouldErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestGenericScanCmdOptsParseDstSubnet(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		opts      genericScanCmdOpts
		args      []string
		expected  *net.IPNet
		shouldErr bool
	}{
		{
			name:     "ValidDstHost",
			opts:     genericScanCmdOpts{},
			args:     []string{"192.168.0.1"},
			expected: &net.IPNet{IP: net.IPv4(192, 168, 0, 1).To4(), Mask: net.IPv4Mask(255, 255, 255, 255)},
		},
		{
			name:     "ValidDstSubnet",
			opts:     genericScanCmdOpts{},
			args:     []string{"10.0.0.1/16"},
			expected: &net.IPNet{IP: net.IPv4(10, 0, 0, 0).To4(), Mask: net.IPv4Mask(255, 255, 0, 0)},
		},
		{
			name:     "IPFile",
			opts:     genericScanCmdOpts{ipFile: "ip_file"},
			args:     []string{},
			expected: nil,
		},
		{
			name:      "NoIPHosts",
			opts:      genericScanCmdOpts{ipFile: ""},
			args:      []string{},
			shouldErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.opts.parseDstSubnet(tt.args)
			if tt.shouldErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestGenericScanCmdOptsParseScanRange(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		opts      genericScanCmdOpts
		args      []string
		expected  *scan.Range
		shouldErr bool
	}{
		{
			name: "ValidDstHost",
			opts: genericScanCmdOpts{portRanges: []*scan.PortRange{{StartPort: 22, EndPort: 100}}},
			args: []string{"192.168.0.1"},
			expected: &scan.Range{
				Ports:     []*scan.PortRange{{StartPort: 22, EndPort: 100}},
				DstSubnet: &net.IPNet{IP: net.IPv4(192, 168, 0, 1).To4(), Mask: net.IPv4Mask(255, 255, 255, 255)},
			},
		},
		{
			name: "ValidDstSubnet",
			opts: genericScanCmdOpts{portRanges: []*scan.PortRange{{StartPort: 22, EndPort: 100}}},
			args: []string{"10.0.0.1/16"},
			expected: &scan.Range{
				Ports:     []*scan.PortRange{{StartPort: 22, EndPort: 100}},
				DstSubnet: &net.IPNet{IP: net.IPv4(10, 0, 0, 0).To4(), Mask: net.IPv4Mask(255, 255, 0, 0)},
			},
		},
		{
			name: "IPFile",
			opts: genericScanCmdOpts{ipFile: "ip_file", portRanges: []*scan.PortRange{{StartPort: 22, EndPort: 100}}},
			args: []string{},
			expected: &scan.Range{
				Ports: []*scan.PortRange{{StartPort: 22, EndPort: 100}},
			},
		},
		{
			name:      "NoIPHosts",
			opts:      genericScanCmdOpts{ipFile: ""},
			args:      []string{},
			shouldErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.opts.parseScanRange(tt.args)
			if tt.shouldErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestParsePortRangeError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		portsRange string
	}{
		{
			name:       "EmptyPortRange",
			portsRange: "",
		},
		{
			name:       "EmptyStartPort",
			portsRange: "-22",
		},
		{
			name:       "EmptyEndPort",
			portsRange: "22-",
		},
		{
			name:       "InvalidLargePort",
			portsRange: "65536",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parsePortRange(tt.portsRange)
			require.Error(t, err)
		})
	}
}

func TestParsePortRange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		portsRange string
		expected   *scan.PortRange
	}{
		{
			name:       "OnePort",
			portsRange: "22",
			expected: &scan.PortRange{
				StartPort: 22,
				EndPort:   22,
			},
		},
		{
			name:       "TwoPorts",
			portsRange: "22-23",
			expected: &scan.PortRange{
				StartPort: 22,
				EndPort:   23,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ports, err := parsePortRange(tt.portsRange)
			require.NoError(t, err)
			require.Equal(t, tt.expected, ports)
		})
	}
}

func TestParsePortRanges(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		portsRange string
		expected   []*scan.PortRange
	}{
		{
			name:       "OneRangeOnePort",
			portsRange: "22",
			expected: []*scan.PortRange{
				{
					StartPort: 22,
					EndPort:   22,
				},
			},
		},
		{
			name:       "OneRangeTwoPorts",
			portsRange: "22-23",
			expected: []*scan.PortRange{
				{
					StartPort: 22,
					EndPort:   23,
				},
			},
		},
		{
			name:       "TwoRangesOnePort",
			portsRange: "22,23",
			expected: []*scan.PortRange{
				{
					StartPort: 22,
					EndPort:   22,
				},
				{
					StartPort: 23,
					EndPort:   23,
				},
			},
		},
		{
			name:       "TwoRangesTwoPorts",
			portsRange: "22-23,26-27",
			expected: []*scan.PortRange{
				{
					StartPort: 22,
					EndPort:   23,
				},
				{
					StartPort: 26,
					EndPort:   27,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ports, err := parsePortRanges(tt.portsRange)
			require.NoError(t, err)
			require.Equal(t, tt.expected, ports)
		})
	}
}

func TestParseRateLimitError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		rateLimit string
	}{
		{
			name:      "InvalidRateLimit",
			rateLimit: "abc",
		},
		{
			name:      "NegativeRateCount",
			rateLimit: "-1000",
		},
		{
			name:      "InvalidRateWindow",
			rateLimit: "1000/f",
		},
		{
			name:      "EmptySlashRateWindow",
			rateLimit: "1000/",
		},
		{
			name:      "MultipleSlashes",
			rateLimit: "1000//s",
		},
		{
			name:      "NegativeRateWindowDuration",
			rateLimit: "1000/-1s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := parseRateLimit(tt.rateLimit)
			require.Error(t, err)
		})
	}
}

func TestParseRateLimit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		rateLimit          string
		expectedRateCount  int
		expectedRateWindow time.Duration
	}{
		{
			name:               "ZeroRateCount",
			rateLimit:          "0",
			expectedRateCount:  0,
			expectedRateWindow: 1 * time.Second,
		},
		{
			name:               "EmptyRateWindow",
			rateLimit:          "1000",
			expectedRateCount:  1000,
			expectedRateWindow: 1 * time.Second,
		},
		{
			name:               "OneSecondRate",
			rateLimit:          "1000/1s",
			expectedRateCount:  1000,
			expectedRateWindow: 1 * time.Second,
		},
		{
			name:               "SevenMinureRate",
			rateLimit:          "5000/7m",
			expectedRateCount:  5000,
			expectedRateWindow: 7 * time.Minute,
		},
		{
			name:               "OneSecondRate2",
			rateLimit:          "1000/s",
			expectedRateCount:  1000,
			expectedRateWindow: 1 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rate, rateWindow, err := parseRateLimit(tt.rateLimit)
			require.NoError(t, err)
			require.Equal(t, tt.expectedRateCount, rate)
			require.Equal(t, tt.expectedRateWindow, rateWindow)
		})
	}
}

func TestParsePacketPayload(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected []byte
	}{
		{
			name:     "EmptyString",
			input:    "",
			expected: []byte{},
		},
		{
			name:     "ASCIIOnly",
			input:    "abc",
			expected: []byte("abc"),
		},
		{
			name:     "HexOnly",
			input:    "\\x01\\x02\\x03\\x04",
			expected: []byte{1, 2, 3, 4},
		},
		{
			name:     "HexAndASCII",
			input:    "\\x01\\x02\\x03\\x04abcd",
			expected: []byte{1, 2, 3, 4, 'a', 'b', 'c', 'd'},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parsePacketPayload(tt.input)
			require.NoError(t, err)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestParseIPFlagsError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		flags string
	}{
		{
			name:  "InvalidFlag",
			flags: "abc",
		},
		{
			name:  "InvalidFlagAfterValid",
			flags: "df,abc",
		},
		{
			name:  "EmptySecondFlag",
			flags: "df,",
		},
		{
			name:  "InvalidSeparator",
			flags: "df|mf",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseIPFlags(tt.flags)
			require.Error(t, err)
		})
	}
}

func TestParseIPFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		flags    string
		expected uint8
	}{
		{
			name:     "NoFlags",
			flags:    "",
			expected: 0,
		},
		{
			name:     "EvilFlag",
			flags:    "evil",
			expected: uint8(layers.IPv4EvilBit),
		},
		{
			name:     "DFFlag",
			flags:    "df",
			expected: uint8(layers.IPv4DontFragment),
		},
		{
			name:     "MFFlag",
			flags:    "mf",
			expected: uint8(layers.IPv4MoreFragments),
		},
		{
			name:     "UppercaseEvilFlag",
			flags:    "Evil",
			expected: uint8(layers.IPv4EvilBit),
		},
		{
			name:     "UppercaseDFFlag",
			flags:    "DF",
			expected: uint8(layers.IPv4DontFragment),
		},
		{
			name:     "UppercaseMFFlag",
			flags:    "MF",
			expected: uint8(layers.IPv4MoreFragments),
		},
		{
			name:     "DFandMFFlags",
			flags:    "df,mf",
			expected: uint8(layers.IPv4DontFragment | layers.IPv4MoreFragments),
		},
		{
			name:     "MFandDFFlags",
			flags:    "mf,df",
			expected: uint8(layers.IPv4DontFragment | layers.IPv4MoreFragments),
		},
		{
			name:     "EvilAndMFFlags",
			flags:    "evil,mf",
			expected: uint8(layers.IPv4EvilBit | layers.IPv4MoreFragments),
		},
		{
			name:     "AllFlags",
			flags:    "evil,df,mf",
			expected: uint8(layers.IPv4EvilBit | layers.IPv4DontFragment | layers.IPv4MoreFragments),
		},
		{
			name:     "DFandUppercaseMFFlags",
			flags:    "df,MF",
			expected: uint8(layers.IPv4DontFragment | layers.IPv4MoreFragments),
		},
		{
			name:     "AllUppercaseFlags",
			flags:    "EVIL,DF,MF",
			expected: uint8(layers.IPv4EvilBit | layers.IPv4DontFragment | layers.IPv4MoreFragments),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseIPFlags(tt.flags)
			require.NoError(t, err)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestParseExcludeFileWithInvalidFile(t *testing.T) {
	t.Parallel()
	_, err := parseExcludeFile(func() (io.ReadCloser, error) {
		return nil, errors.New("open file error")
	})
	require.Error(t, err)
}

func TestParseExcludeFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		contains []net.IP
		excludes []net.IP
		err      bool
	}{
		{
			name:     "OneIP",
			input:    "10.0.1.1",
			contains: []net.IP{net.IPv4(10, 0, 1, 1)},
			excludes: []net.IP{net.IPv4(10, 0, 1, 2)},
		},
		{
			name:  "OneIPSubnet",
			input: "10.0.1.1/30",
			contains: []net.IP{
				net.IPv4(10, 0, 1, 1),
				net.IPv4(10, 0, 1, 2),
				net.IPv4(10, 0, 1, 3),
			},
			excludes: []net.IP{net.IPv4(10, 0, 1, 4)},
		},
		{
			name:     "TwoIPs",
			input:    "10.0.1.1\n10.0.2.2",
			contains: []net.IP{net.IPv4(10, 0, 1, 1), net.IPv4(10, 0, 2, 2)},
			excludes: []net.IP{net.IPv4(10, 0, 1, 2), net.IPv4(10, 0, 2, 3)},
		},
		{
			name:  "TwoIPSubnets",
			input: "10.1.0.0/16\n10.3.0.0/16",
			contains: []net.IP{
				net.IPv4(10, 1, 1, 1),
				net.IPv4(10, 1, 2, 2),
				net.IPv4(10, 3, 3, 3),
				net.IPv4(10, 3, 5, 5),
			},
			excludes: []net.IP{net.IPv4(10, 2, 2, 2), net.IPv4(10, 5, 5, 5)},
		},
		{
			name:  "ParseError",
			input: "abc",
			err:   true,
		},
		{
			name:  "ParseErrorAfterOneIP",
			input: "10.1.0.1/16\nabc",
			err:   true,
		},
		{
			name:     "WithNewLines",
			input:    "\n\n10.0.1.1\n\n",
			contains: []net.IP{net.IPv4(10, 0, 1, 1)},
		},
		{
			name:     "WithSpaces",
			input:    "  10.0.1.1  ",
			contains: []net.IP{net.IPv4(10, 0, 1, 1)},
		},
		{
			name:     "WithNewLinesAndSpaces",
			input:    "\n    \n  10.0.1.1\n\n",
			contains: []net.IP{net.IPv4(10, 0, 1, 1)},
		},
		{
			name:     "WithComment",
			input:    "# comment\n10.0.1.1",
			contains: []net.IP{net.IPv4(10, 0, 1, 1)},
		},
		{
			name:     "WithSpaceAndComment",
			input:    " # comment\n10.0.1.1",
			contains: []net.IP{net.IPv4(10, 0, 1, 1)},
		},
		{
			name:     "WithCommentOnLine",
			input:    "10.0.1.1 # comment",
			contains: []net.IP{net.IPv4(10, 0, 1, 1)},
		},
	}

	for _, vtt := range tests {
		tt := vtt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			done := make(chan interface{})
			go func() {
				defer close(done)

				ips, err := parseExcludeFile(func() (io.ReadCloser, error) {
					return ioutil.NopCloser(strings.NewReader(tt.input)), nil
				})
				if tt.err {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
				for _, ip := range tt.contains {
					ok, err := ips.Contains(ip)
					require.NoError(t, err)
					require.True(t, ok, "ip set does not contain ip %s", ip)
				}
			}()
			waitDone(t, done)
		})
	}
}

func waitDone(t *testing.T, done <-chan interface{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		require.Fail(t, "test timeout")
	}
}
