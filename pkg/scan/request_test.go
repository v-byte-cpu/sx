package scan

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
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

func withError(err error) scanRequestOption {
	return func(sr *Request) {
		sr.Err = err
	}
}

func chanPortToGeneric(in <-chan PortGetter) <-chan interface{} {
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
			expected: []interface{}{WrapPort(22)},
		},
		{
			name: "TwoPorts",
			scanRange: newScanRange(withPorts([]*PortRange{
				{
					StartPort: 22,
					EndPort:   23,
				},
			})),
			expected: []interface{}{WrapPort(22), WrapPort(23)},
		},
		{
			name: "ThreePorts",
			scanRange: newScanRange(withPorts([]*PortRange{
				{
					StartPort: 25,
					EndPort:   27,
				},
			})),
			expected: []interface{}{WrapPort(25), WrapPort(26), WrapPort(27)},
		},
		{
			name: "OnePortOverflow",
			scanRange: newScanRange(withPorts([]*PortRange{
				{
					StartPort: 65535,
					EndPort:   65535,
				},
			})),
			expected: []interface{}{WrapPort(65535)},
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
			expected: []interface{}{WrapPort(25), WrapPort(27)},
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
			expected: []interface{}{WrapPort(20), WrapPort(21), WrapPort(23),
				WrapPort(24), WrapPort(25), WrapPort(26), WrapPort(27)},
		},
		{
			name: "ZeroPort",
			scanRange: newScanRange(withPorts([]*PortRange{
				{
					StartPort: 0,
					EndPort:   1,
				},
			})),
			expected: []interface{}{WrapPort(0), WrapPort(1)},
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
				if tt.err {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
				result := chanToSlice(t, chanPortToGeneric(ports), len(tt.expected))
				sort.Slice(result, func(i, j int) bool {
					return uint16(result[i].(WrapPort)) < uint16(result[j].(WrapPort))
				})
				require.Equal(t, tt.expected, result)
			}()
			waitDone(t, done)
		})
	}
}

func TestPortGeneratorFullRange(t *testing.T) {
	t.Parallel()
	done := make(chan interface{})
	go func() {
		defer close(done)
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
			port, err := p.GetPort()
			require.NoError(t, err)
			i := int(port)
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
	}()
	waitDone(t, done)
}

func chanIPToGeneric(in <-chan IPGetter) <-chan interface{} {
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
		err       bool
	}{
		{
			name:      "NilSubnet",
			scanRange: newScanRange(withSubnet(nil)),
			err:       true,
		},
		{
			name: "OneIP",
			scanRange: newScanRange(
				withSubnet(&net.IPNet{IP: net.IPv4(192, 168, 0, 1), Mask: net.CIDRMask(32, 32)}),
			),
			expected: []interface{}{
				WrapIP(net.IPv4(192, 168, 0, 1).To4()),
			},
		},
		{
			name: "TwoIPs",
			scanRange: newScanRange(
				withSubnet(&net.IPNet{IP: net.IPv4(1, 0, 0, 1), Mask: net.CIDRMask(31, 32)}),
			),
			expected: []interface{}{
				WrapIP(net.IPv4(1, 0, 0, 0).To4()),
				WrapIP(net.IPv4(1, 0, 0, 1).To4()),
			},
		},
		{
			name: "FourIPs",
			scanRange: newScanRange(
				withSubnet(&net.IPNet{IP: net.IPv4(10, 0, 0, 1), Mask: net.CIDRMask(30, 32)}),
			),
			expected: []interface{}{
				WrapIP(net.IPv4(10, 0, 0, 0).To4()),
				WrapIP(net.IPv4(10, 0, 0, 1).To4()),
				WrapIP(net.IPv4(10, 0, 0, 2).To4()),
				WrapIP(net.IPv4(10, 0, 0, 3).To4()),
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
				if tt.err {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
				result := chanToSlice(t, chanIPToGeneric(ips), len(tt.expected))
				sort.Slice(result, func(i, j int) bool {
					return bytes.Compare([]byte(result[i].(WrapIP)), []byte(result[j].(WrapIP))) < 1
				})
				require.Equal(t, tt.expected, result)
			}()
			waitDone(t, done)
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

func TestIPPortGenerator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		ips      []IPGetter
		ports    []PortGetter
		expected []interface{}
	}{
		{
			name:  "OneIpOnePort",
			ips:   []IPGetter{WrapIP(net.IPv4(192, 168, 0, 1))},
			ports: []PortGetter{WrapPort(888)},
			expected: []interface{}{
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 1)), withDstPort(888)),
			},
		},
		{
			name:  "OneIpTwoPorts",
			ips:   []IPGetter{WrapIP(net.IPv4(192, 168, 0, 1))},
			ports: []PortGetter{WrapPort(888), WrapPort(889)},
			expected: []interface{}{
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 1)), withDstPort(888)),
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 1)), withDstPort(889)),
			},
		},
		{
			name: "ThreeIpsOnePort",
			ips: []IPGetter{
				WrapIP(net.IPv4(192, 168, 0, 1)),
				WrapIP(net.IPv4(192, 168, 0, 2)),
				WrapIP(net.IPv4(192, 168, 0, 3)),
			},
			ports: []PortGetter{WrapPort(888)},
			expected: []interface{}{
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 1)), withDstPort(888)),
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 2)), withDstPort(888)),
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 3)), withDstPort(888)),
			},
		},
		{
			name: "TwoIpsTwoPorts",
			ips: []IPGetter{
				WrapIP(net.IPv4(192, 168, 0, 1)),
				WrapIP(net.IPv4(192, 168, 0, 2)),
			},
			ports: []PortGetter{WrapPort(888), WrapPort(889)},
			expected: []interface{}{
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 1)), withDstPort(888)),
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 2)), withDstPort(888)),
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 1)), withDstPort(889)),
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 2)), withDstPort(889)),
			},
		},
		{
			name: "IPError",
			ips: []IPGetter{
				&ipError{errors.New("ip error")},
			},
			ports: []PortGetter{WrapPort(888)},
			expected: []interface{}{
				newScanRequest(withDstIP(nil), withDstPort(888), withError(&ipError{errors.New("ip error")})),
			},
		},
		{
			name: "PortError",
			ips:  []IPGetter{WrapIP(net.IPv4(192, 168, 0, 1))},
			ports: []PortGetter{
				&portError{errors.New("port error")},
			},
			expected: []interface{}{
				&Request{Err: &portError{errors.New("port error")}},
			},
		},
		{
			name: "ValidPortAfterPortError",
			ips:  []IPGetter{WrapIP(net.IPv4(192, 168, 0, 1))},
			ports: []PortGetter{
				&portError{errors.New("port error")},
				WrapPort(888),
			},
			expected: []interface{}{
				&Request{Err: &portError{errors.New("port error")}},
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 1)), withDstPort(888)),
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

				ctrl := gomock.NewController(t)
				ipgen := NewMockIPGenerator(ctrl)

				ctx := context.Background()
				scanRange := newScanRange()
				ipgen.EXPECT().IPs(ctx, scanRange).
					DoAndReturn(func(ctx context.Context, r *Range) (<-chan IPGetter, error) {
						ips := make(chan IPGetter, len(tt.ips))
						for _, ip := range tt.ips {
							ips <- ip
						}
						close(ips)
						return ips, nil
					}).AnyTimes()

				ports := make(chan PortGetter, len(tt.ports))
				for _, port := range tt.ports {
					ports <- port
				}
				close(ports)

				portgen := NewMockPortGenerator(ctrl)
				portgen.EXPECT().Ports(ctx, scanRange).Return(ports, nil)

				reqgen := NewIPPortGenerator(ipgen, portgen)
				pairs, err := reqgen.GenerateRequests(ctx, scanRange)
				require.NoError(t, err)
				result := chanToSlice(t, chanPairToGeneric(pairs), len(tt.expected))
				require.Equal(t, tt.expected, result)
			}()
			waitDone(t, done)
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

			done := make(chan interface{})
			go func() {
				defer close(done)

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
			}()
			waitDone(t, done)
		})
	}
}

func TestIPRequestGenerator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    *Range
		expected []interface{}
		err      bool
	}{
		{
			name:  "NilSubnet",
			input: newScanRange(withSubnet(nil)),
			err:   true,
		},
		{
			name: "OneIP",
			input: newScanRange(
				withSubnet(&net.IPNet{IP: net.IPv4(192, 168, 0, 1).To4(), Mask: net.CIDRMask(32, 32)}),
			),
			expected: []interface{}{
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 1).To4())),
			},
		},
		{
			name: "TwoIPs",
			input: newScanRange(
				withSubnet(&net.IPNet{IP: net.IPv4(192, 168, 0, 1).To4(), Mask: net.CIDRMask(31, 32)}),
			),
			expected: []interface{}{
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 0).To4())),
				newScanRequest(withDstIP(net.IPv4(192, 168, 0, 1).To4())),
			},
		},
		{
			name: "FourIPs",
			input: newScanRange(
				withSubnet(&net.IPNet{IP: net.IPv4(192, 168, 0, 1).To4(), Mask: net.CIDRMask(30, 32)}),
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
				if tt.err {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
				result := chanToSlice(t, chanPairToGeneric(pairs), len(tt.expected))
				sort.Slice(result, func(i, j int) bool {
					return bytes.Compare(
						[]byte(result[i].(*Request).DstIP),
						[]byte(result[j].(*Request).DstIP)) < 1
				})
				require.Equal(t, tt.expected, result)
			}()
			waitDone(t, done)
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
		expected  []interface{}
	}{
		{
			name:  "OneIPPort",
			input: `{"ip":"192.168.0.1","port":888}`,
			expected: []interface{}{
				&Request{DstIP: net.IPv4(192, 168, 0, 1), DstPort: 888},
			},
		},
		{
			name:  "OneIPPortWithUnknownField",
			input: `{"ip":"192.168.0.1","port":888,"abc":"field"}`,
			expected: []interface{}{
				&Request{DstIP: net.IPv4(192, 168, 0, 1), DstPort: 888},
			},
		},
		{
			name: "TwoIPPorts",
			input: strings.Join([]string{
				`{"ip":"192.168.0.1","port":888}`,
				`{"ip":"192.168.0.2","port":222}`,
			}, "\n"),
			expected: []interface{}{
				&Request{DstIP: net.IPv4(192, 168, 0, 1), DstPort: 888},
				&Request{DstIP: net.IPv4(192, 168, 0, 2), DstPort: 222},
			},
		},
		{
			name:  "InvalidJSON",
			input: `{"ip":"192`,
			expected: []interface{}{
				&Request{Err: ErrJSON},
			},
		},
		{
			name: "InvalidJSONAfterValid",
			input: strings.Join([]string{
				`{"ip":"192.168.0.1","port":888}`,
				`{"ip":"192`,
			}, "\n"),
			expected: []interface{}{
				&Request{DstIP: net.IPv4(192, 168, 0, 1), DstPort: 888},
				&Request{Err: ErrJSON},
			},
		},
		{
			name: "ValidJSONAfterInvalid",
			input: strings.Join([]string{
				`{"ip":"192.168.0.1","port":888}`,
				`{"ip":"192`,
				`{"ip":"192.168.0.3","port":888}`,
			}, "\n"),
			expected: []interface{}{
				&Request{DstIP: net.IPv4(192, 168, 0, 1), DstPort: 888},
				&Request{Err: ErrJSON},
			},
		},
		{
			name:  "InvalidIP",
			input: `{"ip":"192.168.0.1111","port":888}`,
			expected: []interface{}{
				&Request{Err: ErrIP},
			},
		},
		{
			name:  "InvalidPort",
			input: `{"ip":"192.168.0.1","port":88888}`,
			expected: []interface{}{
				&Request{Err: ErrPort},
			},
		},
		{
			name: "EmptyPortAfterValid",
			input: strings.Join([]string{
				`{"ip":"192.168.0.1","port":888}`,
				`{"ip":"192.168.0.3"}`,
			}, "\n"),
			expected: []interface{}{
				&Request{DstIP: net.IPv4(192, 168, 0, 1), DstPort: 888},
				&Request{Err: ErrPort},
			},
		},
		{
			name: "EmptyIPAfterValid",
			input: strings.Join([]string{
				`{"ip":"192.168.0.1","port":888}`,
				`{"port":888}`,
			}, "\n"),
			expected: []interface{}{
				&Request{DstIP: net.IPv4(192, 168, 0, 1), DstPort: 888},
				&Request{Err: ErrIP},
			},
		},
		{
			name:  "OneIPPortWithSrcIPandSrcMAC",
			input: `{"ip":"192.168.0.1","port":888}`,
			scanRange: &Range{
				SrcIP:  net.IPv4(192, 168, 0, 3),
				SrcMAC: net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
			},
			expected: []interface{}{
				&Request{
					SrcIP:   net.IPv4(192, 168, 0, 3),
					SrcMAC:  net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
					DstIP:   net.IPv4(192, 168, 0, 1),
					DstPort: 888,
				},
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

				reqgen := NewFileIPPortGenerator(func() (io.ReadCloser, error) {
					return ioutil.NopCloser(strings.NewReader(tt.input)), nil
				})
				if tt.scanRange == nil {
					tt.scanRange = &Range{}
				}
				pairs, err := reqgen.GenerateRequests(context.Background(), tt.scanRange)
				require.NoError(t, err)
				result := chanToSlice(t, chanPairToGeneric(pairs), len(tt.expected))
				require.Equal(t, tt.expected, result)
			}()
			waitDone(t, done)
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
		expected []interface{}
	}{
		{
			name:  "OneIP",
			input: `{"ip":"192.168.0.1"}`,
			expected: []interface{}{
				WrapIP(net.IPv4(192, 168, 0, 1)),
			},
		},
		{
			name:  "OneIPWithUnknownField",
			input: `{"ip":"192.168.0.1","abc":"field"}`,
			expected: []interface{}{
				WrapIP(net.IPv4(192, 168, 0, 1)),
			},
		},
		{
			name: "TwoIPs",
			input: strings.Join([]string{
				`{"ip":"192.168.0.1"}`,
				`{"ip":"192.168.0.2"}`,
			}, "\n"),
			expected: []interface{}{
				WrapIP(net.IPv4(192, 168, 0, 1)),
				WrapIP(net.IPv4(192, 168, 0, 2)),
			},
		},
		{
			name:  "InvalidJSON",
			input: `{"ip":"192`,
			expected: []interface{}{
				&ipError{error: ErrJSON},
			},
		},
		{
			name: "InvalidJSONAfterValid",
			input: strings.Join([]string{
				`{"ip":"192.168.0.1","port":888}`,
				`{"ip":"192`,
			}, "\n"),
			expected: []interface{}{
				WrapIP(net.IPv4(192, 168, 0, 1)),
				&ipError{error: ErrJSON},
			},
		},
		{
			name: "ValidJSONAfterInvalid",
			input: strings.Join([]string{
				`{"ip":"192.168.0.1","port":888}`,
				`{"ip":"192`,
				`{"ip":"192.168.0.3","port":888}`,
			}, "\n"),
			expected: []interface{}{
				WrapIP(net.IPv4(192, 168, 0, 1)),
				&ipError{error: ErrJSON},
			},
		},
		{
			name:  "InvalidIP",
			input: `{"ip":"192.168.0.1111"}`,
			expected: []interface{}{
				&ipError{error: ErrIP},
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

				ipgen := NewFileIPGenerator(func() (io.ReadCloser, error) {
					return ioutil.NopCloser(strings.NewReader(tt.input)), nil
				})
				ips, err := ipgen.IPs(context.Background(), &Range{})
				require.NoError(t, err)
				result := chanToSlice(t, chanIPToGeneric(ips), len(tt.expected))
				require.Equal(t, tt.expected, result)
			}()
			waitDone(t, done)
		})
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

func TestFilterIPRequestGenerator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []*Request
		filtered []bool
		expected []interface{}
	}{
		{
			name: "EmptyFilter",
			input: []*Request{
				newScanRequest(withDstIP(net.IPv4(10, 0, 1, 1).To4())),
				newScanRequest(withDstIP(net.IPv4(10, 0, 2, 2).To4())),
			},
			expected: []interface{}{
				newScanRequest(withDstIP(net.IPv4(10, 0, 1, 1).To4())),
				newScanRequest(withDstIP(net.IPv4(10, 0, 2, 2).To4())),
			},
		},
		{
			name: "OneIPFilter",
			input: []*Request{
				newScanRequest(withDstIP(net.IPv4(10, 0, 1, 1).To4())),
				newScanRequest(withDstIP(net.IPv4(10, 0, 2, 2).To4())),
			},
			filtered: []bool{true, false},
			expected: []interface{}{
				newScanRequest(withDstIP(net.IPv4(10, 0, 2, 2).To4())),
			},
		},
		{
			name: "OneIPFilterMiddle",
			input: []*Request{
				newScanRequest(withDstIP(net.IPv4(10, 0, 1, 1).To4())),
				newScanRequest(withDstIP(net.IPv4(10, 0, 2, 2).To4())),
				newScanRequest(withDstIP(net.IPv4(10, 0, 3, 3).To4())),
			},
			filtered: []bool{false, true, false},
			expected: []interface{}{
				newScanRequest(withDstIP(net.IPv4(10, 0, 1, 1).To4())),
				newScanRequest(withDstIP(net.IPv4(10, 0, 3, 3).To4())),
			},
		},
		{
			name: "TwoIPFilter",
			input: []*Request{
				newScanRequest(withDstIP(net.IPv4(10, 0, 1, 1).To4())),
				newScanRequest(withDstIP(net.IPv4(10, 0, 2, 2).To4())),
				newScanRequest(withDstIP(net.IPv4(10, 0, 3, 3).To4())),
			},
			filtered: []bool{true, false, true},
			expected: []interface{}{
				newScanRequest(withDstIP(net.IPv4(10, 0, 2, 2).To4())),
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

				ctrl := gomock.NewController(t)
				delegate := NewMockRequestGenerator(ctrl)

				input := make(chan *Request, len(tt.input))
				for _, in := range tt.input {
					input <- in
				}
				close(input)
				r := newScanRange(
					withSubnet(&net.IPNet{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)}),
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
				result := chanToSlice(t, chanPairToGeneric(requests), len(tt.expected))
				require.Equal(t, tt.expected, result)
			}()
			waitDone(t, done)
		})
	}
}

func TestFilterIPRequestGeneratorWithGeneratorError(t *testing.T) {
	t.Parallel()

	done := make(chan interface{})
	go func() {
		defer close(done)

		ctrl := gomock.NewController(t)
		delegate := NewMockRequestGenerator(ctrl)

		r := newScanRange(
			withSubnet(&net.IPNet{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)}),
		)
		delegate.EXPECT().GenerateRequests(gomock.Not(gomock.Nil()), r).
			Return(nil, errors.New("generate error"))

		excludeIPs := NewMockIPContainer(ctrl)
		reqgen := NewFilterIPRequestGenerator(delegate, excludeIPs)
		_, err := reqgen.GenerateRequests(context.Background(), r)

		require.Error(t, err)
	}()
	waitDone(t, done)
}

func TestFilterIPRequestGeneratorWithIPContainerError(t *testing.T) {
	t.Parallel()

	done := make(chan interface{})
	go func() {
		defer close(done)

		ctrl := gomock.NewController(t)
		delegate := NewMockRequestGenerator(ctrl)

		r := newScanRange(
			withSubnet(&net.IPNet{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)}),
		)
		input := make(chan *Request, 1)
		input <- newScanRequest(withDstIP(net.IPv4(10, 0, 1, 1).To4()))
		close(input)
		delegate.EXPECT().GenerateRequests(gomock.Not(gomock.Nil()), r).
			Return(input, nil)

		excludeIPs := NewMockIPContainer(ctrl)
		excludeIPs.EXPECT().Contains(gomock.Any()).Return(false, errors.New("ip container error"))

		reqgen := NewFilterIPRequestGenerator(delegate, excludeIPs)
		requests, err := reqgen.GenerateRequests(context.Background(), r)

		require.NoError(t, err)
		result := chanToSlice(t, chanPairToGeneric(requests), 1)
		require.Equal(t, []interface{}{
			newScanRequest(
				withDstIP(net.IPv4(10, 0, 1, 1).To4()),
				withError(errors.New("ip container error")))}, result)
	}()
	waitDone(t, done)
}
