package ip

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInc(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		input    net.IP
		expected net.IP
	}{
		{
			name:     "ZeroNet",
			input:    net.IPv4(0, 0, 0, 0),
			expected: net.IPv4(0, 0, 0, 1),
		},
		{
			name:     "Inc3rd",
			input:    net.IPv4(1, 1, 0, 255),
			expected: net.IPv4(1, 1, 1, 0),
		},
		{
			name:     "Inc2nd",
			input:    net.IPv4(1, 1, 255, 255),
			expected: net.IPv4(1, 2, 0, 0),
		},
		{
			name:     "Inc1st",
			input:    net.IPv4(1, 255, 255, 255),
			expected: net.IPv4(2, 0, 0, 0),
		},
	}

	for _, vtt := range tests {
		tt := vtt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			Inc(tt.input)
			assert.Equal(t, tt.expected, tt.input)
		})
	}
}

func TestDupIP(t *testing.T) {
	t.Parallel()
	ipAddr := net.IPv4(192, 168, 0, 1).To4()

	dupAddr := DupIP(ipAddr)
	assert.Equal(t, ipAddr, dupAddr)

	dupAddr[3]++
	assert.Equal(t, net.IPv4(192, 168, 0, 1).To4(), ipAddr)
}

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
