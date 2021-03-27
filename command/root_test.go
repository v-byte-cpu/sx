package command

import (
	"testing"
	"time"

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
