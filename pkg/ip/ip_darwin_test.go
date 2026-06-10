package ip

import (
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/route"
)

func TestParseDefaultRoute(t *testing.T) {
	t.Parallel()
	addrs := make([]route.Addr, syscall.RTAX_MAX)
	addrs[syscall.RTAX_DST] = &route.Inet4Addr{}
	addrs[syscall.RTAX_GATEWAY] = &route.Inet4Addr{IP: [4]byte{192, 168, 0, 1}}
	addrs[syscall.RTAX_NETMASK] = &route.Inet4Addr{}
	message := &route.RouteMessage{
		Flags: syscall.RTF_GATEWAY,
		Index: 11,
		Addrs: addrs,
	}

	result, ok := parseDefaultRoute(message)

	require.True(t, ok)
	require.Equal(t, 11, result.interfaceIndex)
	require.Equal(t, net.IPv4(192, 168, 0, 1).To4(), result.gatewayIP)
}

func TestParseDefaultRouteRejectsNonDefaultRoutes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		message *route.RouteMessage
	}{
		{
			name: "MessageError",
			message: &route.RouteMessage{
				Err:   errors.New("route error"),
				Index: 11,
			},
		},
		{
			name: "MissingGatewayFlag",
			message: &route.RouteMessage{
				Index: 11,
				Addrs: defaultRouteAddrs(
					&route.Inet4Addr{},
					&route.Inet4Addr{IP: [4]byte{192, 168, 0, 1}},
					&route.Inet4Addr{},
				),
			},
		},
		{
			name: "MissingInterfaceIndex",
			message: &route.RouteMessage{
				Flags: syscall.RTF_GATEWAY,
				Addrs: defaultRouteAddrs(
					&route.Inet4Addr{},
					&route.Inet4Addr{IP: [4]byte{192, 168, 0, 1}},
					&route.Inet4Addr{},
				),
			},
		},
		{
			name: "NonZeroDestination",
			message: &route.RouteMessage{
				Flags: syscall.RTF_GATEWAY,
				Index: 11,
				Addrs: defaultRouteAddrs(
					&route.Inet4Addr{IP: [4]byte{10, 0, 0, 0}},
					&route.Inet4Addr{IP: [4]byte{192, 168, 0, 1}},
					&route.Inet4Addr{},
				),
			},
		},
		{
			name: "NonZeroNetmask",
			message: &route.RouteMessage{
				Flags: syscall.RTF_GATEWAY,
				Index: 11,
				Addrs: defaultRouteAddrs(
					&route.Inet4Addr{},
					&route.Inet4Addr{IP: [4]byte{192, 168, 0, 1}},
					&route.Inet4Addr{IP: [4]byte{255, 255, 255, 0}},
				),
			},
		},
		{
			name: "MissingGateway",
			message: &route.RouteMessage{
				Flags: syscall.RTF_GATEWAY,
				Index: 11,
				Addrs: defaultRouteAddrs(
					&route.Inet4Addr{},
					nil,
					&route.Inet4Addr{},
				),
			},
		},
	}
	for _, vtt := range tests {
		tt := vtt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, ok := parseDefaultRoute(tt.message)
			require.False(t, ok)
		})
	}
}

func defaultRouteAddrs(dst, gateway, netmask route.Addr) []route.Addr {
	addrs := make([]route.Addr, syscall.RTAX_MAX)
	addrs[syscall.RTAX_DST] = dst
	addrs[syscall.RTAX_GATEWAY] = gateway
	addrs[syscall.RTAX_NETMASK] = netmask
	return addrs
}
