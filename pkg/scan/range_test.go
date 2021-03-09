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
		Subnet: &net.IPNet{
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
		sr.Subnet = subnet
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

func TestIPPortPairsWithInvalidInput(t *testing.T) {
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
			_, err := IPPortPairs(context.Background(), tt.scanRange)
			assert.Error(t, err)
		})
	}
}

func comparePairChanToSlice(t *testing.T, expected []*Request, in <-chan *Request, timeout time.Duration) {
	t.Helper()
	result := pairChanToSlice(t, in, len(expected), timeout)
	require.Equal(t, expected, result)
}

func pairChanToSlice(t *testing.T, in <-chan *Request, expectedLen int, timeout time.Duration) []*Request {
	t.Helper()
	result := []*Request{}
loop:
	for {
		select {
		case data, ok := <-in:
			if !ok {
				break loop
			}
			if len(result) == expectedLen {
				require.FailNow(t, "chan size is greater than expected, data:", data)
			}
			result = append(result, data)
		case <-time.After(timeout):
			t.Fatal("read timeout")
		}
	}
	return result
}

func TestIPPortPairsWithOneIpOnePort(t *testing.T) {
	t.Parallel()
	port := uint16(888)
	pairs, err := IPPortPairs(context.Background(),
		newScanRange(
			withSubnet(&net.IPNet{IP: net.IPv4(192, 168, 0, 1), Mask: net.CIDRMask(32, 32)}),
			withStartPort(port),
			withEndPort(port),
		))
	assert.NoError(t, err)

	expected := []*Request{
		newScanRequest(withDstIP(net.IPv4(192, 168, 0, 1).To4()), withDstPort(port)),
	}
	comparePairChanToSlice(t, expected, pairs, 5*time.Second)
}

func TestIPPortPairsWithOneIpTwoPorts(t *testing.T) {
	t.Parallel()
	port := uint16(888)
	pairs, err := IPPortPairs(context.Background(),
		newScanRange(
			withSubnet(&net.IPNet{IP: net.IPv4(192, 168, 0, 1), Mask: net.CIDRMask(32, 32)}),
			withStartPort(port),
			withEndPort(port+1),
		))
	assert.NoError(t, err)

	expected := []*Request{
		newScanRequest(withDstIP(net.IPv4(192, 168, 0, 1).To4()), withDstPort(port)),
		newScanRequest(withDstIP(net.IPv4(192, 168, 0, 1).To4()), withDstPort(port+1)),
	}
	comparePairChanToSlice(t, expected, pairs, 5*time.Second)
}

func TestIPPortPairsWithTwoIpsOnePort(t *testing.T) {
	t.Parallel()
	port := uint16(888)
	pairs, err := IPPortPairs(context.Background(),
		newScanRange(
			withSubnet(&net.IPNet{IP: net.IPv4(192, 168, 0, 1), Mask: net.CIDRMask(31, 32)}),
			withStartPort(port),
			withEndPort(port),
		))
	assert.NoError(t, err)

	expected := []*Request{
		newScanRequest(withDstIP(net.IPv4(192, 168, 0, 0).To4()), withDstPort(port)),
		newScanRequest(withDstIP(net.IPv4(192, 168, 0, 1).To4()), withDstPort(port)),
	}
	comparePairChanToSlice(t, expected, pairs, 5*time.Second)
}

func TestIPPortPairsWithFourIpsOnePort(t *testing.T) {
	t.Parallel()
	port := uint16(888)
	pairs, err := IPPortPairs(context.Background(),
		newScanRange(
			withSubnet(&net.IPNet{IP: net.IPv4(192, 168, 0, 1), Mask: net.CIDRMask(30, 32)}),
			withStartPort(port),
			withEndPort(port),
		))
	assert.NoError(t, err)

	expected := []*Request{
		newScanRequest(withDstIP(net.IPv4(192, 168, 0, 0).To4()), withDstPort(port)),
		newScanRequest(withDstIP(net.IPv4(192, 168, 0, 1).To4()), withDstPort(port)),
		newScanRequest(withDstIP(net.IPv4(192, 168, 0, 2).To4()), withDstPort(port)),
		newScanRequest(withDstIP(net.IPv4(192, 168, 0, 3).To4()), withDstPort(port)),
	}
	comparePairChanToSlice(t, expected, pairs, 5*time.Second)
}

func TestIPPortPairsWithTwoIpsTwoPorts(t *testing.T) {
	t.Parallel()
	port := uint16(888)
	pairs, err := IPPortPairs(context.Background(),
		newScanRange(
			withSubnet(&net.IPNet{IP: net.IPv4(192, 168, 0, 1), Mask: net.CIDRMask(31, 32)}),
			withStartPort(port),
			withEndPort(port+1),
		))
	assert.NoError(t, err)

	expected := []*Request{
		newScanRequest(withDstIP(net.IPv4(192, 168, 0, 0).To4()), withDstPort(port)),
		newScanRequest(withDstIP(net.IPv4(192, 168, 0, 1).To4()), withDstPort(port)),
		newScanRequest(withDstIP(net.IPv4(192, 168, 0, 0).To4()), withDstPort(port+1)),
		newScanRequest(withDstIP(net.IPv4(192, 168, 0, 1).To4()), withDstPort(port+1)),
	}
	comparePairChanToSlice(t, expected, pairs, 5*time.Second)
}
