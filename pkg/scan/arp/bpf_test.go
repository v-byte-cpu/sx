package arp

import (
	"net/netip"
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
			expectedFilter: "arp",
			scanRange:      &scan.Range{},
		},
		{
			name:           "OneSubnet",
			scanRange:      &scan.Range{DstPrefix: netip.MustParsePrefix("192.168.0.0/24")},
			expectedFilter: "arp src net 192.168.0.0/24",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			filter, maxPacketLength := BPFFilter(tt.scanRange)
			assert.Equal(t, tt.expectedFilter, filter)
			assert.Equal(t, MaxPacketLength, maxPacketLength)
		})
	}
}
