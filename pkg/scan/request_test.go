package scan

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newScanRange(opts ...scanRangeOption) *Range {
	sr := &Range{
		SrcIP:  net.IPv4(192, 168, 0, 3),
		SrcMAC: net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
		DstSubnet: &net.IPNet{
			IP:   net.IPv4(192, 168, 0, 0),
			Mask: net.CIDRMask(24, 32),
		},
		Ports: []*PortRange{
			{
				StartPort: 22,
				EndPort:   888,
			},
		},
	}
	for _, o := range opts {
		o(sr)
	}
	return sr
}

type scanRangeOption func(sr *Range)

func withPorts(ports []*PortRange) scanRangeOption {
	return func(sr *Range) {
		sr.Ports = ports
	}
}

func withSubnet(subnet *net.IPNet) scanRangeOption {
	return func(sr *Range) {
		sr.DstSubnet = subnet
	}
}

func newScanRequest(opts ...scanRequestOption) *Request {
	r := &Request{
		SrcIP:  net.IPv4(192, 168, 0, 3),
		SrcMAC: net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

type scanRequestOption func(sr *Request)

func withDstIP(dstIP net.IP) scanRequestOption {
	return func(sr *Request) {
		sr.DstIP = dstIP
	}
}

func withDstPort(dstPort uint16) scanRequestOption {
	return func(sr *Request) {
		sr.DstPort = dstPort
	}
}

func TestPortGeneratorWithInvalidInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		scanRange *Range
	}{
		{
			name:      "NilPorts",
			scanRange: newScanRange(withPorts(nil)),
		},
		{
			name: "InvalidPortRange",
			scanRange: newScanRange(withPorts([]*PortRange{
				{
					StartPort: 5000,
					EndPort:   2000,
				},
			})),
		},
		{
			name: "InvalidPortRangeAfterValid",
			scanRange: newScanRange(withPorts([]*PortRange{
				{
					StartPort: 1000,
					EndPort:   1000,
				},
				{
					StartPort: 7000,
					EndPort:   5000,
				},
			})),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			portgen := NewPortGenerator()
			_, err := portgen.Ports(context.Background(), tt.scanRange)
			require.Error(t, err)
		})
	}
}

func chanPortToGeneric(in <-chan uint16) <-chan interface{} {
	out := make(chan interface{}, cap(in))
	go func() {
		defer close(out)
		for i := range in {
			out <- i
		}
	}()
	return out
}

func TestPortGenerator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		scanRange *Range
		expected  []interface{}
	}{
		{
			name: "OnePort",
			scanRange: newScanRange(withPorts([]*PortRange{
				{
					StartPort: 22,
					EndPort:   22,
				},
			})),
			expected: []interface{}{uint16(22)},
		},
		{
			name: "TwoPorts",
			scanRange: newScanRange(withPorts([]*PortRange{
				{
					StartPort: 22,
					EndPort:   23,
				},
			})),
			expected: []interface{}{uint16(22), uint16(23)},
		},
		{
			name: "ThreePorts",
			scanRange: newScanRange(withPorts([]*PortRange{
				{
					StartPort: 25,
					EndPort:   27,
				},
			})),
			expected: []interface{}{uint16(25), uint16(26), uint16(27)},
		},
		{
			name: "OnePortOverflow",
			scanRange: newScanRange(withPorts([]*PortRange{
				{
					StartPort: 65535,
					EndPort:   65535,
				},
			})),
			expected: []interface{}{uint16(65535)},
		},
		{
			name: "TwoRangesOnePort",
			scanRange: newScanRange(withPorts([]*PortRange{
				{
					StartPort: 25,
					EndPort:   25,
				},
				{
					StartPort: 27,
					EndPort:   27,
				},
			})),
			expected: []interface{}{uint16(25), uint16(27)},
		},
		{
			name: "TwoRangesTwoPorts",
			scanRange: newScanRange(withPorts([]*PortRange{
				{
					StartPort: 21,
					EndPort:   22,
				},
				{
					StartPort: 26,
					EndPort:   27,
				},
			})),
			expected: []interface{}{uint16(21), uint16(22), uint16(26), uint16(27)},
		},
	}

	for _, vtt := range tests {
		tt := vtt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			done := make(chan interface{})
			go func() {
				defer close(done)
				portgen := NewPortGenerator()
				ports, err := portgen.Ports(context.Background(), tt.scanRange)
				require.NoError(t, err)
				result := chanToSlice(t, chanPortToGeneric(ports), len(tt.expected))
				require.Equal(t, tt.expected, result)
			}()
			select {
			case <-done:
			case <-time.After(waitTimeout):
				require.Fail(t, "test timeout")
			}
		})
	}
}

func TestIPGeneratorWithInvalidInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		scanRange *Range
	}{
		{
			name:      "NilSubnet",
			scanRange: newScanRange(withSubnet(nil)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipgen := NewIPGenerator()
			_, err := ipgen.IPs(context.Background(), tt.scanRange)
			require.Error(t, err)
		})
	}
}

func chanIPToGeneric(in <-chan net.IP) <-chan interface{} {
	out := make(chan interface{}, cap(in))
	go func() {
		defer close(out)
		for i := range in {
			out <- i
		}
	}()
	return out
}

func TestIPGenerator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		scanRange *Range
		expected  []interface{}
	}{
		{
			name: "OneIP",
			scanRange: newScanRange(
				withSubnet(&net.IPNet{IP: net.IPv4(192, 168, 0, 1), Mask: net.CIDRMask(32, 32)}),
			),
			expected: []interface{}{net.IPv4(192, 168, 0, 1).To4()},
		},
		{
			name: "TwoIPs",
			scanRange: newScanRange(
				withSubnet(&net.IPNet{IP: net.IPv4(1, 0, 0, 1), Mask: net.CIDRMask(31, 32)}),
			),
			expected: []interface{}{
				net.IPv4(1, 0, 0, 0).To4(),
				net.IPv4(1, 0, 0, 1).To4(),
			},
		},
		{
			name: "FourIPs",
			scanRange: newScanRange(
				withSubnet(&net.IPNet{IP: net.IPv4(10, 0, 0, 1), Mask: net.CIDRMask(30, 32)}),
			),
			expected: []interface{}{
				net.IPv4(10, 0, 0, 0).To4(),
				net.IPv4(10, 0, 0, 1).To4(),
				net.IPv4(10, 0, 0, 2).To4(),
				net.IPv4(10, 0, 0, 3).To4(),
			},
		},
	}

	for _, vtt := range tests {
		tt := vtt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			done := make(chan interface{})
			go func() {
				defer close(done)
				ipgen := NewIPGenerator()
				ips, err := ipgen.IPs(context.Background(), tt.scanRange)
				require.NoError(t, err)
				result := chanToSlice(t, chanIPToGeneric(ips), len(tt.expected))
				require.Equal(t, tt.expected, result)
			}()
			select {
			case <-done:
			case <-time.After(waitTimeout):
				require.Fail(t, "test timeout")
			}
		})
	}
}

func TestIPPortRequestGeneratorWithInvalidInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		startPort uint16
		endPort   uint16
		subnets   []net.IPNet
		scanRange *Range
	}{
		{
			name: "InvalidPortRange",
			scanRange: newScanRange(
				withPorts([]*PortRange{
					{
						StartPort: 5000,
						EndPort:   2000,
					},
				}),
			),
		},
		{
			name:      "NilSubnet",
			scanRange: newScanRange(withSubnet(nil)),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqgen := NewIPPortRequestGenerator(NewIPGenerator(), NewPortGenerator())
			_, err := reqgen.GenerateRequests(context.Background(), tt.scanRange)
			assert.Error(t, err)
		})
	}
}

func chanPairToGeneric(in <-chan *Request) <-chan interface{} {
	out := make(chan interface{}, cap(in))
	go func() {
		defer close(out)
		for i := range in {
			out <- i
		}
	}()
	return out
}

func TestIPPortRequestRegenerator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    *Range
		expected []interface{}
	}{
		{
			name: "OneIpOnePort",
			input: newScanRange(
				withSubnet(&net.IPNet{IP: net.IPv4(192, 168, 0, 1), Mask: net.CIDRMask(32, 32)}),
				withPorts([]*PortRange{
					{
						StartPort: 888,
						EndPort:   888,
					},
				}),
			),
			expected: []interface{}{
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 1).To4()), withDstPort(888)),
			},
		},
		{
			name: "OneIpTwoPorts",
			input: newScanRange(
				withSubnet(&net.IPNet{IP: net.IPv4(192, 168, 0, 1), Mask: net.CIDRMask(32, 32)}),
				withPorts([]*PortRange{
					{
						StartPort: 888,
						EndPort:   889,
					},
				}),
			),
			expected: []interface{}{
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 1).To4()), withDstPort(888)),
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 1).To4()), withDstPort(889)),
			},
		},
		{
			name: "TwoIpsOnePort",
			input: newScanRange(
				withSubnet(&net.IPNet{IP: net.IPv4(192, 168, 0, 1), Mask: net.CIDRMask(31, 32)}),
				withPorts([]*PortRange{
					{
						StartPort: 888,
						EndPort:   888,
					},
				}),
			),
			expected: []interface{}{
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 0).To4()), withDstPort(888)),
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 1).To4()), withDstPort(888)),
			},
		},
		{
			name: "FourIpsOnePort",
			input: newScanRange(
				withSubnet(&net.IPNet{IP: net.IPv4(192, 168, 0, 1), Mask: net.CIDRMask(30, 32)}),
				withPorts([]*PortRange{
					{
						StartPort: 888,
						EndPort:   888,
					},
				}),
			),
			expected: []interface{}{
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 0).To4()), withDstPort(888)),
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 1).To4()), withDstPort(888)),
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 2).To4()), withDstPort(888)),
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 3).To4()), withDstPort(888)),
			},
		},
		{
			name: "TwoIpsTwoPorts",
			input: newScanRange(
				withSubnet(&net.IPNet{IP: net.IPv4(192, 168, 0, 1), Mask: net.CIDRMask(31, 32)}),
				withPorts([]*PortRange{
					{
						StartPort: 888,
						EndPort:   889,
					},
				}),
			),
			expected: []interface{}{
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 0).To4()), withDstPort(888)),
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 1).To4()), withDstPort(888)),
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 0).To4()), withDstPort(889)),
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 1).To4()), withDstPort(889)),
			},
		},
		{
			name: "OneIpPortOverflow",
			input: newScanRange(
				withSubnet(&net.IPNet{IP: net.IPv4(192, 168, 0, 1), Mask: net.CIDRMask(32, 32)}),
				withPorts([]*PortRange{
					{
						StartPort: 65535,
						EndPort:   65535,
					},
				}),
			),
			expected: []interface{}{
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 1).To4()), withDstPort(65535)),
			},
		},
	}

	for _, vtt := range tests {
		tt := vtt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			done := make(chan interface{})
			go func() {
				defer close(done)

				reqgen := NewIPPortRequestGenerator(NewIPGenerator(), NewPortGenerator())
				pairs, err := reqgen.GenerateRequests(context.Background(), tt.input)
				require.NoError(t, err)
				result := chanToSlice(t, chanPairToGeneric(pairs), len(tt.expected))
				require.Equal(t, tt.expected, result)
			}()
			select {
			case <-done:
			case <-time.After(waitTimeout):
				require.Fail(t, "test timeout")
			}
		})
	}
}

func TestIPRequestGeneratorWithInvalidInput(t *testing.T) {
	t.Parallel()

	reqgen := NewIPRequestGenerator(NewIPGenerator())
	_, err := reqgen.GenerateRequests(context.Background(), newScanRange(withSubnet(nil)))
	assert.Error(t, err)
}

func TestIPRequestRegenerator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    *Range
		expected []interface{}
	}{
		{
			name: "OneIP",
			input: newScanRange(
				withSubnet(&net.IPNet{IP: net.IPv4(192, 168, 0, 1), Mask: net.CIDRMask(32, 32)}),
			),
			expected: []interface{}{
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 1).To4())),
			},
		},
		{
			name: "TwoIPs",
			input: newScanRange(
				withSubnet(&net.IPNet{IP: net.IPv4(192, 168, 0, 1), Mask: net.CIDRMask(31, 32)}),
			),
			expected: []interface{}{
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 0).To4())),
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 1).To4())),
			},
		},
		{
			name: "FourIPs",
			input: newScanRange(
				withSubnet(&net.IPNet{IP: net.IPv4(192, 168, 0, 1), Mask: net.CIDRMask(30, 32)}),
			),
			expected: []interface{}{
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 0).To4())),
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 1).To4())),
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 2).To4())),
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 3).To4())),
			},
		},
	}

	for _, vtt := range tests {
		tt := vtt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			done := make(chan interface{})
			go func() {
				defer close(done)

				reqgen := NewIPRequestGenerator(NewIPGenerator())
				pairs, err := reqgen.GenerateRequests(context.Background(), tt.input)
				require.NoError(t, err)
				result := chanToSlice(t, chanPairToGeneric(pairs), len(tt.expected))
				require.Equal(t, tt.expected, result)
			}()
			select {
			case <-done:
			case <-time.After(waitTimeout):
				require.Fail(t, "test timeout")
			}
		})
	}
}

func TestLiveRequestGeneratorContextExit(t *testing.T) {
	t.Parallel()

	reqgen := NewIPPortRequestGenerator(NewIPGenerator(), NewPortGenerator())
	rg := NewLiveRequestGenerator(reqgen, 5*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	requests, err := rg.GenerateRequests(ctx, newScanRange())
	require.NoError(t, err)
	// consume all requests
loop:
	for {
		select {
		case _, ok := <-requests:
			if !ok {
				break loop
			}
		case <-time.After(waitTimeout):
			require.Fail(t, "test timeout")
		}
	}
}
