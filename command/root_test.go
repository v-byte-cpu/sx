package command

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/v-byte-cpu/sx/pkg/scan"
)

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
