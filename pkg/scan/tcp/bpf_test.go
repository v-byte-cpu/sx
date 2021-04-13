package tcp

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
			expectedFilter: "tcp",
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
			expectedFilter: "tcp and ip src net 192.168.0.0/24",
		},
		{
			name:           "EmptySubnetWithOnePort",
			expectedFilter: "tcp and (src portrange 111-111)",
			scanRange: &scan.Range{
				Ports: []*scan.PortRange{
					{
						StartPort: 111,
						EndPort:   111,
					},
				},
			},
		},
		{
			name:           "EmptySubnetWithOnePortRange",
			expectedFilter: "tcp and (src portrange 111-123)",
			scanRange: &scan.Range{
				Ports: []*scan.PortRange{
					{
						StartPort: 111,
						EndPort:   123,
					},
				},
			},
		},
		{
			name:           "EmptySubnetWithTwoPortRanges",
			expectedFilter: "tcp and (src portrange 111-123 or src portrange 222-333)",
			scanRange: &scan.Range{
				Ports: []*scan.PortRange{
					{
						StartPort: 111,
						EndPort:   123,
					},
					{
						StartPort: 222,
						EndPort:   333,
					},
				},
			},
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

func TestSYNACKBPFFilter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		scanRange      *scan.Range
		expectedFilter string
	}{
		{
			name:           "EmptySubnet",
			expectedFilter: "tcp and tcp[13] == 18",
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
			expectedFilter: "tcp and ip src net 192.168.0.0/24 and tcp[13] == 18",
		},
		{
			name:           "EmptySubnetWithOnePort",
			expectedFilter: "tcp and (src portrange 111-111) and tcp[13] == 18",
			scanRange: &scan.Range{
				Ports: []*scan.PortRange{
					{
						StartPort: 111,
						EndPort:   111,
					},
				},
			},
		},
		{
			name:           "EmptySubnetWithOnePortRange",
			expectedFilter: "tcp and (src portrange 111-123) and tcp[13] == 18",
			scanRange: &scan.Range{
				Ports: []*scan.PortRange{
					{
						StartPort: 111,
						EndPort:   123,
					},
				},
			},
		},
		{
			name:           "EmptySubnetWithTwoPortRanges",
			expectedFilter: "tcp and (src portrange 111-123 or src portrange 222-333) and tcp[13] == 18",
			scanRange: &scan.Range{
				Ports: []*scan.PortRange{
					{
						StartPort: 111,
						EndPort:   123,
					},
					{
						StartPort: 222,
						EndPort:   333,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter, maxPacketLength := SYNACKBPFFilter(tt.scanRange)
			assert.Equal(t, tt.expectedFilter, filter)
			assert.Equal(t, maxPacketLength, MaxPacketLength)
		})
	}
}
