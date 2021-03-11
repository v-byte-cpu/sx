package log

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/v-byte-cpu/sx/pkg/scan/arp"
)

func TestUniqueLoggerResults(t *testing.T) {
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
			name: "twoDifferentResults",
			expected: []byte(strings.Join([]string{
				newScanResult(net.IPv4(192, 168, 0, 3).To4()).String(),
				newScanResult(net.IPv4(192, 168, 0, 5).To4()).String(),
			}, "\n") + "\n"),
			results: []*arp.ScanResult{
				newScanResult(net.IPv4(192, 168, 0, 3).To4()),
				newScanResult(net.IPv4(192, 168, 0, 5).To4()),
			},
		},
		{
			name:     "twoEqualResults",
			expected: []byte(newScanResult(net.IPv4(192, 168, 0, 3).To4()).String() + "\n"),
			results: []*arp.ScanResult{
				newScanResult(net.IPv4(192, 168, 0, 3).To4()),
				newScanResult(net.IPv4(192, 168, 0, 3).To4()),
			},
		},
		{
			name: "twoEqualResultsWithOneBetween",
			expected: []byte(strings.Join([]string{
				newScanResult(net.IPv4(192, 168, 0, 3).To4()).String(),
				newScanResult(net.IPv4(192, 168, 0, 5).To4()).String(),
			}, "\n") + "\n"),
			results: []*arp.ScanResult{
				newScanResult(net.IPv4(192, 168, 0, 3).To4()),
				newScanResult(net.IPv4(192, 168, 0, 5).To4()),
				newScanResult(net.IPv4(192, 168, 0, 3).To4()),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			var buf bytes.Buffer
			plainLogger, err := NewLogger(&buf, "arp")
			require.NoError(t, err)
			logger := NewUniqueLogger(context.Background(), plainLogger)

			resultCh := make(chan *arp.ScanResult, len(tt.results))
			for _, result := range tt.results {
				resultCh <- result
			}
			close(resultCh)
			logger.LogResults(resultCh)

			assert.Equal(t, string(tt.expected), buf.String())
		})
	}
}
