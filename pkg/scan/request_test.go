package scan

import (
	"context"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func newScanRange(opts ...scanRangeOption) *Range {
	sr := &Range{
		SrcIP:     ip4(192, 168, 0, 3),
		SrcMAC:    net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
		DstPrefix: netip.PrefixFrom(ip4(192, 168, 0, 0), 24),
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

func withPrefix(subnet netip.Prefix) scanRangeOption {
	return func(sr *Range) {
		sr.DstPrefix = subnet
	}
}

func newScanRequest(opts ...scanRequestOption) *Request {
	r := &Request{
		SrcIP:  ip4(192, 168, 0, 3),
		SrcMAC: net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

type scanRequestOption func(sr *Request)

func withDstIP(dstIP netip.Addr) scanRequestOption {
	return func(sr *Request) {
		sr.DstIP = dstIP
	}
}

func withDstPort(dstPort uint16) scanRequestOption {
	return func(sr *Request) {
		sr.DstPort = dstPort
	}
}

func withError(err error) scanRequestOption {
	return func(sr *Request) {
		sr.Err = err
	}
}

func TestGeneratorResult(t *testing.T) {
	t.Parallel()

	err := errors.New("generated value error")
	result := GeneratorResult[int]{Value: 42, Err: err}

	require.Equal(t, 42, result.Value)
	require.ErrorIs(t, result.Err, err)
}

func generatedPort(value uint16) GeneratorResult[uint16] {
	return GeneratorResult[uint16]{Value: value}
}

func generatedIP(value netip.Addr) GeneratorResult[netip.Addr] {
	return GeneratorResult[netip.Addr]{Value: value}
}

func generationError[T any](err error) GeneratorResult[T] {
	return GeneratorResult[T]{Err: err}
}

func TestPortGenerator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		scanRange *Range
		expected  []GeneratorResult[uint16]
		err       bool
	}{
		{
			name:      "NilPorts",
			scanRange: newScanRange(withPorts(nil)),
			err:       true,
		},
		{
			name: "InvalidPortRange",
			scanRange: newScanRange(withPorts([]*PortRange{
				{
					StartPort: 5000,
					EndPort:   2000,
				},
			})),
			err: true,
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
			err: true,
		},
		{
			name: "OnePort",
			scanRange: newScanRange(withPorts([]*PortRange{
				{
					StartPort: 22,
					EndPort:   22,
				},
			})),
			expected: []GeneratorResult[uint16]{generatedPort(22)},
		},
		{
			name: "TwoPorts",
			scanRange: newScanRange(withPorts([]*PortRange{
				{
					StartPort: 22,
					EndPort:   23,
				},
			})),
			expected: []GeneratorResult[uint16]{generatedPort(22), generatedPort(23)},
		},
		{
			name: "ThreePorts",
			scanRange: newScanRange(withPorts([]*PortRange{
				{
					StartPort: 25,
					EndPort:   27,
				},
			})),
			expected: []GeneratorResult[uint16]{generatedPort(25), generatedPort(26), generatedPort(27)},
		},
		{
			name: "OnePortOverflow",
			scanRange: newScanRange(withPorts([]*PortRange{
				{
					StartPort: 65535,
					EndPort:   65535,
				},
			})),
			expected: []GeneratorResult[uint16]{generatedPort(65535)},
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
			expected: []GeneratorResult[uint16]{generatedPort(25), generatedPort(27)},
		},
		{
			name: "TwoRangesTwoPorts",
			scanRange: newScanRange(withPorts([]*PortRange{
				{
					StartPort: 20,
					EndPort:   21,
				},
				{
					StartPort: 23,
					EndPort:   27,
				},
			})),
			expected: []GeneratorResult[uint16]{generatedPort(20), generatedPort(21), generatedPort(23),
				generatedPort(24), generatedPort(25), generatedPort(26), generatedPort(27)},
		},
		{
			name: "ZeroPort",
			scanRange: newScanRange(withPorts([]*PortRange{
				{
					StartPort: 0,
					EndPort:   1,
				},
			})),
			expected: []GeneratorResult[uint16]{generatedPort(0), generatedPort(1)},
		},
	}

	for _, vtt := range tests {
		tt := vtt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			portgen := NewPortGenerator()
			ports, err := portgen.Ports(context.Background(), tt.scanRange)
			if tt.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			result := collectChannel(ports)
			sort.Slice(result, func(i, j int) bool {
				return result[i].Value < result[j].Value
			})
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestPortGeneratorFullRange(t *testing.T) {
	t.Parallel()
	portgen := NewPortGenerator()
	ports, err := portgen.Ports(context.Background(), newScanRange(withPorts([]*PortRange{
		{
			StartPort: 1,
			EndPort:   65535,
		},
	})))
	require.NoError(t, err)

	bitset := big.NewInt(0)
	cnt := 0
	for p := range ports {
		cnt++
		require.NoError(t, p.Err)
		i := int(p.Value)
		if bitset.Bit(i) == 1 {
			require.Fail(t, "number has already been visited", "number %d", i)
		}
		bitset.SetBit(bitset, i, 1)
	}
	for i := 1; i <= 65535; i++ {
		require.Equal(t, uint(1), bitset.Bit(i),
			"number %d is not visited", i)
	}
	require.Equal(t, 65535, cnt, "count is not valid")
}

func TestIPGenerator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		scanRange *Range
		expected  []GeneratorResult[netip.Addr]
		err       bool
	}{
		{
			name:      "NilSubnet",
			scanRange: newScanRange(withPrefix(netip.Prefix{})),
			err:       true,
		},
		{
			name: "OneIP",
			scanRange: newScanRange(
				withPrefix(netip.PrefixFrom(ip4(192, 168, 0, 1), 32)),
			),
			expected: []GeneratorResult[netip.Addr]{
				generatedIP(ip4(192, 168, 0, 1)),
			},
		},
		{
			name: "TwoIPs",
			scanRange: newScanRange(
				withPrefix(netip.PrefixFrom(ip4(1, 0, 0, 1), 31)),
			),
			expected: []GeneratorResult[netip.Addr]{
				generatedIP(ip4(1, 0, 0, 0)),
				generatedIP(ip4(1, 0, 0, 1)),
			},
		},
		{
			name: "FourIPs",
			scanRange: newScanRange(
				withPrefix(netip.PrefixFrom(ip4(10, 0, 0, 1), 30)),
			),
			expected: []GeneratorResult[netip.Addr]{
				generatedIP(ip4(10, 0, 0, 0)),
				generatedIP(ip4(10, 0, 0, 1)),
				generatedIP(ip4(10, 0, 0, 2)),
				generatedIP(ip4(10, 0, 0, 3)),
			},
		},
	}

	for _, vtt := range tests {
		tt := vtt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ipgen := NewIPGenerator()
			ips, err := ipgen.IPs(context.Background(), tt.scanRange)
			if tt.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			result := collectChannel(ips)
			sort.Slice(result, func(i, j int) bool {
				return result[i].Value.Less(result[j].Value)
			})
			require.Equal(t, tt.expected, result)
		})
	}
}

func collectChannel[T any](in <-chan T) []T {
	var out []T
	for v := range in {
		out = append(out, v)
	}
	return out
}

func TestIPPortGenerator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		ips      []GeneratorResult[netip.Addr]
		ports    []GeneratorResult[uint16]
		expected []*Request
	}{
		{
			name:  "OneIpOnePort",
			ips:   []GeneratorResult[netip.Addr]{generatedIP(ip4(192, 168, 0, 1))},
			ports: []GeneratorResult[uint16]{generatedPort(888)},
			expected: []*Request{
				newScanRequest(withDstIP(ip4(192, 168, 0, 1)), withDstPort(888)),
			},
		},
		{
			name:  "OneIpTwoPorts",
			ips:   []GeneratorResult[netip.Addr]{generatedIP(ip4(192, 168, 0, 1))},
			ports: []GeneratorResult[uint16]{generatedPort(888), generatedPort(889)},
			expected: []*Request{
				newScanRequest(withDstIP(ip4(192, 168, 0, 1)), withDstPort(888)),
				newScanRequest(withDstIP(ip4(192, 168, 0, 1)), withDstPort(889)),
			},
		},
		{
			name: "ThreeIpsOnePort",
			ips: []GeneratorResult[netip.Addr]{
				generatedIP(ip4(192, 168, 0, 1)),
				generatedIP(ip4(192, 168, 0, 2)),
				generatedIP(ip4(192, 168, 0, 3)),
			},
			ports: []GeneratorResult[uint16]{generatedPort(888)},
			expected: []*Request{
				newScanRequest(withDstIP(ip4(192, 168, 0, 1)), withDstPort(888)),
				newScanRequest(withDstIP(ip4(192, 168, 0, 2)), withDstPort(888)),
				newScanRequest(withDstIP(ip4(192, 168, 0, 3)), withDstPort(888)),
			},
		},
		{
			name: "TwoIpsTwoPorts",
			ips: []GeneratorResult[netip.Addr]{
				generatedIP(ip4(192, 168, 0, 1)),
				generatedIP(ip4(192, 168, 0, 2)),
			},
			ports: []GeneratorResult[uint16]{generatedPort(888), generatedPort(889)},
			expected: []*Request{
				newScanRequest(withDstIP(ip4(192, 168, 0, 1)), withDstPort(888)),
				newScanRequest(withDstIP(ip4(192, 168, 0, 2)), withDstPort(888)),
				newScanRequest(withDstIP(ip4(192, 168, 0, 1)), withDstPort(889)),
				newScanRequest(withDstIP(ip4(192, 168, 0, 2)), withDstPort(889)),
			},
		},
		{
			name: "IPError",
			ips: []GeneratorResult[netip.Addr]{
				generationError[netip.Addr](errors.New("ip error")),
			},
			ports: []GeneratorResult[uint16]{generatedPort(888)},
			expected: []*Request{
				newScanRequest(withDstIP(netip.Addr{}), withDstPort(888), withError(errors.New("ip error"))),
			},
		},
		{
			name: "PortError",
			ips:  []GeneratorResult[netip.Addr]{generatedIP(ip4(192, 168, 0, 1))},
			ports: []GeneratorResult[uint16]{
				generationError[uint16](errors.New("port error")),
			},
			expected: []*Request{
				{Err: errors.New("port error")},
			},
		},
		{
			name: "ValidPortAfterPortError",
			ips:  []GeneratorResult[netip.Addr]{generatedIP(ip4(192, 168, 0, 1))},
			ports: []GeneratorResult[uint16]{
				generationError[uint16](errors.New("port error")),
				generatedPort(888),
			},
			expected: []*Request{
				{Err: errors.New("port error")},
				newScanRequest(withDstIP(ip4(192, 168, 0, 1)), withDstPort(888)),
			},
		},
	}

	for _, vtt := range tests {
		tt := vtt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			ipgen := NewMockIPGenerator(ctrl)

			ctx := context.Background()
			scanRange := newScanRange()
			ipgen.EXPECT().IPs(ctx, scanRange).
				DoAndReturn(func(ctx context.Context, r *Range) (<-chan GeneratorResult[netip.Addr], error) {
					ips := make(chan GeneratorResult[netip.Addr], len(tt.ips))
					for _, ip := range tt.ips {
						ips <- ip
					}
					close(ips)
					return ips, nil
				}).AnyTimes()

			ports := make(chan GeneratorResult[uint16], len(tt.ports))
			for _, port := range tt.ports {
				ports <- port
			}
			close(ports)

			portgen := NewMockPortGenerator(ctrl)
			portgen.EXPECT().Ports(ctx, scanRange).Return(ports, nil)

			reqgen := NewIPPortGenerator(ipgen, portgen)
			pairs, err := reqgen.GenerateRequests(ctx, scanRange)
			require.NoError(t, err)
			result := collectChannel(pairs)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestIPPortGeneratorError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		ipsError   error
		portsError error
	}{
		{
			name:     "IPGeneratorError",
			ipsError: errors.New("ipgen error"),
		},
		{
			name:     "PortGeneratorError",
			ipsError: errors.New("portgen error"),
		},
	}

	for _, vtt := range tests {
		tt := vtt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			ipgen := NewMockIPGenerator(ctrl)

			ctx := context.Background()
			scanRange := newScanRange()
			ipgen.EXPECT().IPs(ctx, scanRange).Return(nil, tt.ipsError).AnyTimes()

			portgen := NewMockPortGenerator(ctrl)
			portgen.EXPECT().Ports(ctx, scanRange).Return(nil, tt.portsError).AnyTimes()

			reqgen := NewIPPortGenerator(ipgen, portgen)
			_, err := reqgen.GenerateRequests(ctx, scanRange)
			require.Error(t, err)
		})
	}
}

func TestIPRequestGenerator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    *Range
		expected []*Request
		err      bool
	}{
		{
			name:  "NilSubnet",
			input: newScanRange(withPrefix(netip.Prefix{})),
			err:   true,
		},
		{
			name: "OneIP",
			input: newScanRange(
				withPrefix(netip.PrefixFrom(ip4(192, 168, 0, 1), 32)),
			),
			expected: []*Request{
				newScanRequest(withDstIP(ip4(192, 168, 0, 1))),
			},
		},
		{
			name: "OneIPv6",
			input: newScanRange(
				withPrefix(netip.MustParsePrefix("2001:db8::1/128")),
			),
			expected: []*Request{
				newScanRequest(withDstIP(netip.MustParseAddr("2001:db8::1"))),
			},
		},
		{
			name: "ScopedIPv6",
			input: func() *Range {
				r := newScanRange(withPrefix(netip.MustParsePrefix("fe80::1/128")))
				r.DstZone = "en0"
				return r
			}(),
			expected: []*Request{
				newScanRequest(withDstIP(netip.MustParseAddr("fe80::1%en0"))),
			},
		},
		{
			name:  "IPv6RangeTooLarge",
			input: newScanRange(withPrefix(netip.MustParsePrefix("2001:db8::/95"))),
			err:   true,
		},
		{
			name: "TwoIPs",
			input: newScanRange(
				withPrefix(netip.PrefixFrom(ip4(192, 168, 0, 1), 31)),
			),
			expected: []*Request{
				newScanRequest(withDstIP(ip4(192, 168, 0, 0))),
				newScanRequest(withDstIP(ip4(192, 168, 0, 1))),
			},
		},
		{
			name: "FourIPs",
			input: newScanRange(
				withPrefix(netip.PrefixFrom(ip4(192, 168, 0, 1), 30)),
			),
			expected: []*Request{
				newScanRequest(withDstIP(ip4(192, 168, 0, 0))),
				newScanRequest(withDstIP(ip4(192, 168, 0, 1))),
				newScanRequest(withDstIP(ip4(192, 168, 0, 2))),
				newScanRequest(withDstIP(ip4(192, 168, 0, 3))),
			},
		},
	}

	for _, vtt := range tests {
		tt := vtt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reqgen := NewIPRequestGenerator(NewIPGenerator())
			pairs, err := reqgen.GenerateRequests(context.Background(), tt.input)
			if tt.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			result := collectChannel(pairs)
			sort.Slice(result, func(i, j int) bool {
				return result[i].DstIP.Less(result[j].DstIP)
			})
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestFileIPPortGeneratorWithInvalidFile(t *testing.T) {
	t.Parallel()

	reqgen := NewFileIPPortGenerator(func() (io.ReadCloser, error) {
		return nil, errors.New("open file error")
	})
	_, err := reqgen.GenerateRequests(context.Background(), &Range{})
	require.Error(t, err)
}

func TestFileIPPortGenerator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		scanRange *Range
		expected  []*Request
	}{
		{
			name:  "OneIPPort",
			input: `{"ip":"192.168.0.1","port":888}`,
			expected: []*Request{
				{DstIP: ip4(192, 168, 0, 1), DstPort: 888},
			},
		},
		{
			name:  "OneIPPortWithUnknownField",
			input: `{"ip":"192.168.0.1","port":888,"abc":"field"}`,
			expected: []*Request{
				{DstIP: ip4(192, 168, 0, 1), DstPort: 888},
			},
		},
		{
			name: "TwoIPPorts",
			input: strings.Join([]string{
				`{"ip":"192.168.0.1","port":888}`,
				`{"ip":"192.168.0.2","port":222}`,
			}, "\n"),
			expected: []*Request{
				{DstIP: ip4(192, 168, 0, 1), DstPort: 888},
				{DstIP: ip4(192, 168, 0, 2), DstPort: 222},
			},
		},
		{
			name:  "InvalidJSON",
			input: `{"ip":"192`,
			expected: []*Request{
				{Err: ErrJSON},
			},
		},
		{
			name: "InvalidJSONAfterValid",
			input: strings.Join([]string{
				`{"ip":"192.168.0.1","port":888}`,
				`{"ip":"192`,
			}, "\n"),
			expected: []*Request{
				{DstIP: ip4(192, 168, 0, 1), DstPort: 888},
				{Err: ErrJSON},
			},
		},
		{
			name: "ValidJSONAfterInvalid",
			input: strings.Join([]string{
				`{"ip":"192.168.0.1","port":888}`,
				`{"ip":"192`,
				`{"ip":"192.168.0.3","port":888}`,
			}, "\n"),
			expected: []*Request{
				{DstIP: ip4(192, 168, 0, 1), DstPort: 888},
				{Err: ErrJSON},
			},
		},
		{
			name:  "InvalidIP",
			input: `{"ip":"192.168.0.1111","port":888}`,
			expected: []*Request{
				{Err: ErrIP},
			},
		},
		{
			name:  "InvalidPort",
			input: `{"ip":"192.168.0.1","port":88888}`,
			expected: []*Request{
				{Err: ErrPort},
			},
		},
		{
			name: "EmptyPortAfterValid",
			input: strings.Join([]string{
				`{"ip":"192.168.0.1","port":888}`,
				`{"ip":"192.168.0.3"}`,
			}, "\n"),
			expected: []*Request{
				{DstIP: ip4(192, 168, 0, 1), DstPort: 888},
				{Err: ErrPort},
			},
		},
		{
			name: "EmptyIPAfterValid",
			input: strings.Join([]string{
				`{"ip":"192.168.0.1","port":888}`,
				`{"port":888}`,
			}, "\n"),
			expected: []*Request{
				{DstIP: ip4(192, 168, 0, 1), DstPort: 888},
				{Err: ErrIP},
			},
		},
		{
			name:  "OneIPPortWithSrcIPandSrcMAC",
			input: `{"ip":"192.168.0.1","port":888}`,
			scanRange: &Range{
				SrcIP:  ip4(192, 168, 0, 3),
				SrcMAC: net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
			},
			expected: []*Request{
				{
					SrcIP:   ip4(192, 168, 0, 3),
					SrcMAC:  net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
					DstIP:   ip4(192, 168, 0, 1),
					DstPort: 888,
				},
			},
		},
	}
	for _, vtt := range tests {
		tt := vtt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reqgen := NewFileIPPortGenerator(func() (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader(tt.input)), nil
			})
			if tt.scanRange == nil {
				tt.scanRange = &Range{}
			}
			pairs, err := reqgen.GenerateRequests(context.Background(), tt.scanRange)
			require.NoError(t, err)
			result := collectChannel(pairs)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestFileIPGeneratorWithInvalidFile(t *testing.T) {
	t.Parallel()

	ipgen := NewFileIPGenerator(func() (io.ReadCloser, error) {
		return nil, errors.New("open file error")
	})
	_, err := ipgen.IPs(context.Background(), &Range{})
	require.Error(t, err)
}

func TestFileIPGenerator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected []GeneratorResult[netip.Addr]
	}{
		{
			name:  "OneIP",
			input: `{"ip":"192.168.0.1"}`,
			expected: []GeneratorResult[netip.Addr]{
				generatedIP(ip4(192, 168, 0, 1)),
			},
		},
		{
			name:  "OneIPWithUnknownField",
			input: `{"ip":"192.168.0.1","abc":"field"}`,
			expected: []GeneratorResult[netip.Addr]{
				generatedIP(ip4(192, 168, 0, 1)),
			},
		},
		{
			name: "TwoIPs",
			input: strings.Join([]string{
				`{"ip":"192.168.0.1"}`,
				`{"ip":"192.168.0.2"}`,
			}, "\n"),
			expected: []GeneratorResult[netip.Addr]{
				generatedIP(ip4(192, 168, 0, 1)),
				generatedIP(ip4(192, 168, 0, 2)),
			},
		},
		{
			name:  "InvalidJSON",
			input: `{"ip":"192`,
			expected: []GeneratorResult[netip.Addr]{
				generationError[netip.Addr](ErrJSON),
			},
		},
		{
			name: "InvalidJSONAfterValid",
			input: strings.Join([]string{
				`{"ip":"192.168.0.1","port":888}`,
				`{"ip":"192`,
			}, "\n"),
			expected: []GeneratorResult[netip.Addr]{
				generatedIP(ip4(192, 168, 0, 1)),
				generationError[netip.Addr](ErrJSON),
			},
		},
		{
			name: "ValidJSONAfterInvalid",
			input: strings.Join([]string{
				`{"ip":"192.168.0.1","port":888}`,
				`{"ip":"192`,
				`{"ip":"192.168.0.3","port":888}`,
			}, "\n"),
			expected: []GeneratorResult[netip.Addr]{
				generatedIP(ip4(192, 168, 0, 1)),
				generationError[netip.Addr](ErrJSON),
			},
		},
		{
			name:  "InvalidIP",
			input: `{"ip":"192.168.0.1111"}`,
			expected: []GeneratorResult[netip.Addr]{
				generationError[netip.Addr](ErrIP),
			},
		},
		{
			name: "EmptyIPAfterValid",
			input: strings.Join([]string{
				`{"ip":"192.168.0.1"}`,
				`{}`,
			}, "\n"),
			expected: []GeneratorResult[netip.Addr]{
				generatedIP(ip4(192, 168, 0, 1)),
				generationError[netip.Addr](ErrIP),
			},
		},
	}
	for _, vtt := range tests {
		tt := vtt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ipgen := NewFileIPGenerator(func() (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader(tt.input)), nil
			})
			ips, err := ipgen.IPs(context.Background(), &Range{})
			require.NoError(t, err)
			result := collectChannel(ips)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestFileIPGeneratorStopsAfterContextCancel(t *testing.T) {
	t.Parallel()

	reader, writer := io.Pipe()
	t.Cleanup(func() {
		require.NoError(t, writer.Close())
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ips, err := NewFileIPGenerator(func() (io.ReadCloser, error) {
		return reader, nil
	}).IPs(ctx, &Range{})
	require.NoError(t, err)
	_, err = writer.Write([]byte(`{"ip":"192.168.0.1"}` + "\n"))
	require.NoError(t, err)

	select {
	case _, ok := <-ips:
		require.False(t, ok, "IP channel is not closed")
	case <-time.After(100 * time.Millisecond):
		require.FailNow(t, "file IP generator did not stop after context cancellation")
	}
}

func TestLiveRequestGeneratorContextExit(t *testing.T) {
	t.Parallel()

	reqgen := NewIPPortGenerator(NewIPGenerator(), NewPortGenerator())
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

func TestLiveRequestGeneratorReportsRescanError(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	delegate := NewMockRequestGenerator(ctrl)
	r := newScanRange()
	initial := make(chan *Request)
	close(initial)
	rescanErr := errors.New("rescan error")
	gomock.InOrder(
		delegate.EXPECT().GenerateRequests(gomock.Any(), r).Return(initial, nil),
		delegate.EXPECT().GenerateRequests(gomock.Any(), r).Return(nil, rescanErr),
	)

	rg := NewLiveRequestGenerator(delegate, time.Millisecond)
	requests, err := rg.GenerateRequests(context.Background(), r)
	require.NoError(t, err)

	select {
	case request := <-requests:
		require.ErrorIs(t, request.Err, rescanErr)
	case <-time.After(waitTimeout):
		require.FailNow(t, "rescan error was not reported")
	}
	select {
	case _, ok := <-requests:
		require.False(t, ok, "request channel is not closed")
	case <-time.After(waitTimeout):
		require.FailNow(t, "request channel was not closed")
	}
}

func TestFilterIPRequestGenerator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []*Request
		filtered []bool
		expected []*Request
	}{
		{
			name: "EmptyFilter",
			input: []*Request{
				newScanRequest(withDstIP(ip4(10, 0, 1, 1))),
				newScanRequest(withDstIP(ip4(10, 0, 2, 2))),
			},
			expected: []*Request{
				newScanRequest(withDstIP(ip4(10, 0, 1, 1))),
				newScanRequest(withDstIP(ip4(10, 0, 2, 2))),
			},
		},
		{
			name: "OneIPFilter",
			input: []*Request{
				newScanRequest(withDstIP(ip4(10, 0, 1, 1))),
				newScanRequest(withDstIP(ip4(10, 0, 2, 2))),
			},
			filtered: []bool{true, false},
			expected: []*Request{
				newScanRequest(withDstIP(ip4(10, 0, 2, 2))),
			},
		},
		{
			name: "OneIPFilterMiddle",
			input: []*Request{
				newScanRequest(withDstIP(ip4(10, 0, 1, 1))),
				newScanRequest(withDstIP(ip4(10, 0, 2, 2))),
				newScanRequest(withDstIP(ip4(10, 0, 3, 3))),
			},
			filtered: []bool{false, true, false},
			expected: []*Request{
				newScanRequest(withDstIP(ip4(10, 0, 1, 1))),
				newScanRequest(withDstIP(ip4(10, 0, 3, 3))),
			},
		},
		{
			name: "TwoIPFilter",
			input: []*Request{
				newScanRequest(withDstIP(ip4(10, 0, 1, 1))),
				newScanRequest(withDstIP(ip4(10, 0, 2, 2))),
				newScanRequest(withDstIP(ip4(10, 0, 3, 3))),
			},
			filtered: []bool{true, false, true},
			expected: []*Request{
				newScanRequest(withDstIP(ip4(10, 0, 2, 2))),
			},
		},
	}

	for _, vtt := range tests {
		tt := vtt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			delegate := NewMockRequestGenerator(ctrl)

			input := make(chan *Request, len(tt.input))
			for _, in := range tt.input {
				input <- in
			}
			close(input)
			r := newScanRange(
				withPrefix(netip.PrefixFrom(ip4(10, 0, 0, 0), 8)),
			)
			delegate.EXPECT().GenerateRequests(gomock.Not(gomock.Nil()), r).
				Return(input, nil)

			excludeIPs := NewMockIPContainer(ctrl)
			var excludeFilters []gomock.Matcher
			for i, filtered := range tt.filtered {
				if filtered {
					excludeIPs.EXPECT().Contains(tt.input[i].DstIP).Return(true, nil)
					excludeFilters = append(excludeFilters, gomock.Not(gomock.Eq(tt.input[i].DstIP)))
				}
			}
			excludeIPs.EXPECT().Contains(gomock.All(excludeFilters...)).Return(false, nil).AnyTimes()

			reqgen := NewFilterIPRequestGenerator(delegate, excludeIPs)
			requests, err := reqgen.GenerateRequests(context.Background(), r)

			require.NoError(t, err)
			result := collectChannel(requests)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestFilterIPRequestGeneratorWithGeneratorError(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	delegate := NewMockRequestGenerator(ctrl)

	r := newScanRange(
		withPrefix(netip.PrefixFrom(ip4(10, 0, 0, 0), 8)),
	)
	delegate.EXPECT().GenerateRequests(gomock.Not(gomock.Nil()), r).
		Return(nil, errors.New("generate error"))

	excludeIPs := NewMockIPContainer(ctrl)
	reqgen := NewFilterIPRequestGenerator(delegate, excludeIPs)
	_, err := reqgen.GenerateRequests(context.Background(), r)

	require.Error(t, err)
}

func TestFilterIPRequestGeneratorWithIPContainerError(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	delegate := NewMockRequestGenerator(ctrl)

	r := newScanRange(
		withPrefix(netip.PrefixFrom(ip4(10, 0, 0, 0), 8)),
	)
	input := make(chan *Request, 1)
	input <- newScanRequest(withDstIP(ip4(10, 0, 1, 1)))
	close(input)
	delegate.EXPECT().GenerateRequests(gomock.Not(gomock.Nil()), r).
		Return(input, nil)

	excludeIPs := NewMockIPContainer(ctrl)
	excludeIPs.EXPECT().Contains(gomock.Any()).Return(false, errors.New("ip container error"))

	reqgen := NewFilterIPRequestGenerator(delegate, excludeIPs)
	requests, err := reqgen.GenerateRequests(context.Background(), r)

	require.NoError(t, err)
	result := collectChannel(requests)
	require.Equal(t, []*Request{
		newScanRequest(
			withDstIP(ip4(10, 0, 1, 1)),
			withError(errors.New("ip container error")))}, result)
}
