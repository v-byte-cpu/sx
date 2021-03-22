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
		SrcIP:     net.IPv4(192, 168, 0, 3),
		SrcMAC:    net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
		StartPort: 22,
		EndPort:   888,
		DstSubnet: &net.IPNet{
			IP:   net.IPv4(192, 168, 0, 0),
			Mask: net.CIDRMask(24, 32),
		},
	}
	for _, o := range opts {
		o(sr)
	}
	return sr
}

type scanRangeOption func(sr *Range)

func withStartPort(startPort uint16) scanRangeOption {
	return func(sr *Range) {
		sr.StartPort = startPort
	}
}

func withEndPort(endPort uint16) scanRangeOption {
	return func(sr *Range) {
		sr.EndPort = endPort
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

func TestScanRequestsWithInvalidInput(t *testing.T) {
	tests := []struct {
		name      string
		startPort uint16
		endPort   uint16
		subnets   []net.IPNet
		scanRange *Range
	}{
		{
			name:      "InvalidPortRange",
			scanRange: newScanRange(withStartPort(5000), withEndPort(2000)),
		},
		{
			name:      "NilSubnet",
			scanRange: newScanRange(withSubnet(nil)),
		},
	}
	for _, vtt := range tests {
		tt := vtt
		t.Run(tt.name, func(t *testing.T) {
			_, err := Requests(context.Background(), tt.scanRange)
			assert.Error(t, err)
		})
	}
}

func comparePairChanToSlice(t *testing.T, expected []interface{}, in <-chan *Request) {
	t.Helper()
	result := chanToSlice(t, chanPairToGeneric(in), len(expected))
	require.Equal(t, expected, result)
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

func TestScanRequests(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		in       *Range
		expected []interface{}
	}{
		{
			name: "OneIpOnePort",
			in: newScanRange(
				withSubnet(&net.IPNet{IP: net.IPv4(192, 168, 0, 1), Mask: net.CIDRMask(32, 32)}),
				withStartPort(888),
				withEndPort(888),
			),
			expected: []interface{}{
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 1).To4()), withDstPort(888)),
			},
		},
		{
			name: "OneIpTwoPorts",
			in: newScanRange(
				withSubnet(&net.IPNet{IP: net.IPv4(192, 168, 0, 1), Mask: net.CIDRMask(32, 32)}),
				withStartPort(888),
				withEndPort(889),
			),
			expected: []interface{}{
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 1).To4()), withDstPort(888)),
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 1).To4()), withDstPort(889)),
			},
		},
		{
			name: "TwoIpsOnePort",
			in: newScanRange(
				withSubnet(&net.IPNet{IP: net.IPv4(192, 168, 0, 1), Mask: net.CIDRMask(31, 32)}),
				withStartPort(888),
				withEndPort(888),
			),
			expected: []interface{}{
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 0).To4()), withDstPort(888)),
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 1).To4()), withDstPort(888)),
			},
		},
		{
			name: "FourIpsOnePort",
			in: newScanRange(
				withSubnet(&net.IPNet{IP: net.IPv4(192, 168, 0, 1), Mask: net.CIDRMask(30, 32)}),
				withStartPort(888),
				withEndPort(888),
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
			in: newScanRange(
				withSubnet(&net.IPNet{IP: net.IPv4(192, 168, 0, 1), Mask: net.CIDRMask(31, 32)}),
				withStartPort(888),
				withEndPort(889),
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
			in: newScanRange(
				withSubnet(&net.IPNet{IP: net.IPv4(192, 168, 0, 1), Mask: net.CIDRMask(32, 32)}),
				withStartPort(65535),
				withEndPort(65535),
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

				pairs, err := Requests(context.Background(), tt.in)
				require.NoError(t, err)
				comparePairChanToSlice(t, tt.expected, pairs)
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

	rg := NewLiveRequestGenerator(5 * time.Second)
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
