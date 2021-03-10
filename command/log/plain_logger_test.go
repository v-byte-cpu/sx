package log

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/v-byte-cpu/sx/pkg/scan/arp"
)

func newScanResult(ip net.IP) *arp.ScanResult {
	return &arp.ScanResult{
		IP:     ip.String(),
		MAC:    net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}.String(),
		Vendor: "Sunny Industries",
	}
}

func TestPlainLoggerResults(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		expected []byte
		results  []*arp.ScanResult
	}{
		{
			name:     "emptyResults",
			expected: nil,
			results:  nil,
		},
		{
			name:     "oneResult",
			expected: []byte(newScanResult(net.IPv4(192, 168, 0, 3).To4()).String() + "\n"),
			results: []*arp.ScanResult{
				newScanResult(net.IPv4(192, 168, 0, 3).To4()),
			},
		},
		{
			name: "twoResults",
			expected: []byte(strings.Join([]string{
				newScanResult(net.IPv4(192, 168, 0, 3).To4()).String(),
				newScanResult(net.IPv4(192, 168, 0, 5).To4()).String(),
			}, "\n") + "\n"),
			results: []*arp.ScanResult{
				newScanResult(net.IPv4(192, 168, 0, 3).To4()),
				newScanResult(net.IPv4(192, 168, 0, 5).To4()),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			var buf bytes.Buffer
			logger, err := NewPlainLogger(&buf, "arp")
			require.NoError(t, err)

			resultCh := make(chan *arp.ScanResult, len(tt.results))
			for _, result := range tt.results {
				resultCh <- result
			}
			close(resultCh)
			logger.LogResults(resultCh)

			assert.Equal(t, tt.expected, buf.Bytes())
		})
	}
}
