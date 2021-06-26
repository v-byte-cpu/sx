package ip

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseIPNetWithError(t *testing.T) {
	t.Parallel()
	_, err := ParseIPNet("")
	assert.Error(t, err)
}

func TestParseIPNet(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		in       string
		expected *net.IPNet
	}{
		{
			name: "subnet",
			in:   "192.168.0.1/24",
			expected: &net.IPNet{
				IP:   net.IPv4(192, 168, 0, 0).To4(),
				Mask: net.CIDRMask(24, 32),
			},
		},
		{
			name: "host",
			in:   "10.0.0.1",
			expected: &net.IPNet{
				IP:   net.IPv4(10, 0, 0, 1).To4(),
				Mask: net.CIDRMask(32, 32),
			},
		},
	}
	for _, vtt := range tests {
		tt := vtt
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseIPNet(tt.in)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result)

		})
	}
}
