//go:generate go tool mockgen -package neighbor -destination=mock_request_test.go github.com/v-byte-cpu/sx/pkg/scan RequestGenerator

package neighbor

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/v-byte-cpu/sx/pkg/scan"
	"go.uber.org/mock/gomock"
)

func TestCacheStoresIPv4AndIPv6Neighbors(t *testing.T) {
	t.Parallel()

	cache := NewCache()
	ipv4MAC := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	ipv6MAC := net.HardwareAddr{0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}
	cache.Put(netip.MustParseAddr("192.0.2.1"), ipv4MAC)
	cache.Put(netip.MustParseAddr("fe80::1%en0"), ipv6MAC)
	otherMAC := net.HardwareAddr{0x00, 1, 1, 1, 1, 1}
	cache.Put(netip.MustParseAddr("fe80::1%en1"), otherMAC)
	fallbackMAC := net.HardwareAddr{0x00, 2, 2, 2, 2, 2}
	cache.Put(netip.MustParseAddr("fe80::2"), fallbackMAC)

	require.Equal(t, ipv4MAC, cache.Get(netip.MustParseAddr("192.0.2.1")))
	require.Equal(t, ipv6MAC, cache.Get(netip.MustParseAddr("fe80::1%en0")))
	require.Equal(t, otherMAC, cache.Get(netip.MustParseAddr("fe80::1%en1")))
	require.Equal(t, fallbackMAC, cache.Get(netip.MustParseAddr("fe80::2%en0")))
}

func TestCacheRequestGeneratorUsesNeighborThenGateway(t *testing.T) {
	t.Parallel()

	controller := gomock.NewController(t)
	upstream := NewMockRequestGenerator(controller)
	scanRange := &scan.Range{}
	requests := make(chan *scan.Request, 2)
	requests <- &scan.Request{DstIP: netip.MustParseAddr("2001:db8::1")}
	requests <- &scan.Request{DstIP: netip.MustParseAddr("2001:db8::2")}
	close(requests)
	upstream.EXPECT().GenerateRequests(gomock.Any(), scanRange).Return((<-chan *scan.Request)(requests), nil)

	directMAC := net.HardwareAddr{0x00, 1, 2, 3, 4, 5}
	gatewayMAC := net.HardwareAddr{0x00, 6, 7, 8, 9, 10}
	cache := NewCache()
	cache.Put(netip.MustParseAddr("2001:db8::1"), directMAC)
	generated, err := NewCacheRequestGenerator(upstream, gatewayMAC, cache).GenerateRequests(context.Background(), scanRange)
	require.NoError(t, err)

	first := <-generated
	second := <-generated
	require.Equal(t, directMAC, net.HardwareAddr(first.DstMAC))
	require.Equal(t, gatewayMAC, net.HardwareAddr(second.DstMAC))
	require.NoError(t, first.Err)
	require.NoError(t, second.Err)
}

func TestFillCacheReportsInvalidAddressLine(t *testing.T) {
	t.Parallel()

	err := FillCache(NewCache(), strings.NewReader(strings.Join([]string{
		`{"ip":"192.0.2.1","mac":"00:11:22:33:44:55"}`,
		`{"ip":"not-an-ip","mac":"00:11:22:33:44:55"}`,
	}, "\n")))

	require.EqualError(t, err, "neighbor cache: line 2: invalid IP")
}
