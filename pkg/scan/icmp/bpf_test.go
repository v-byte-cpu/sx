package icmp

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/v-byte-cpu/sx/pkg/scan"
)

func TestBPFFilter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		scanRange      *scan.Range
		expectedFilter string
	}{
		{
			name:           "EmptySubnet",
			expectedFilter: "icmp and icmp[0]!=8",
			scanRange:      &scan.Range{},
		},
		{
			name: "OneSubnet",
			scanRange: &scan.Range{
				DstSubnet: &net.IPNet{
					IP:   net.IPv4(192, 168, 0, 0),
					Mask: net.CIDRMask(24, 32),
				},
			},
			expectedFilter: "icmp and icmp[0]!=8 and ip src net 192.168.0.0/24",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter, maxPacketLength := BPFFilter(tt.scanRange)
			assert.Equal(t, tt.expectedFilter, filter)
			assert.Equal(t, maxPacketLength, MaxPacketLength)
		})
	}
}
