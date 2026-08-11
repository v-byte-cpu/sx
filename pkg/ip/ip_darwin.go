package ip

import (
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/net/route"
)

type defaultRoute struct {
	interfaceIndex int
	gatewayIP      netip.Addr
}

func GetDefaultInterface(target netip.Addr) (iface *net.Interface, ifaceIP netip.Addr, err error) {
	defaultRoute, err := findDefaultRoute(0, target)
	if err != nil || defaultRoute == nil {
		return nil, netip.Addr{}, err
	}
	if iface, err = net.InterfaceByIndex(defaultRoute.interfaceIndex); err != nil {
		return nil, netip.Addr{}, err
	}
	if ifaceIP, err = GetInterfaceIP(iface, target); err != nil {
		return nil, netip.Addr{}, err
	}
	return iface, ifaceIP, nil
}

func GetDefaultGatewayIP(iface *net.Interface, target netip.Addr) (gatewayIP netip.Addr, err error) {
	defaultRoute, err := findDefaultRoute(iface.Index, target)
	if err != nil || defaultRoute == nil {
		return netip.Addr{}, err
	}
	return defaultRoute.gatewayIP, nil
}

func findDefaultRoute(interfaceIndex int, target netip.Addr) (*defaultRoute, error) {
	rib, err := route.FetchRIB(routeAddressFamily(target), route.RIBTypeRoute, 0)
	if err != nil {
		return nil, err
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, err
	}
	for _, message := range messages {
		routeMessage, ok := message.(*route.RouteMessage)
		if !ok {
			continue
		}
		defaultRoute, ok := parseDefaultRoute(routeMessage, target)
		if ok && (interfaceIndex == 0 || interfaceIndex == defaultRoute.interfaceIndex) {
			return &defaultRoute, nil
		}
	}
	return nil, nil
}

func parseDefaultRoute(message *route.RouteMessage, target netip.Addr) (defaultRoute, bool) {
	if message.Err != nil || message.Index == 0 || message.Flags&syscall.RTF_GATEWAY == 0 {
		return defaultRoute{}, false
	}
	if target.Is4() {
		return parseDefaultIPv4Route(message)
	}
	return parseDefaultIPv6Route(message)
}

func parseDefaultIPv4Route(message *route.RouteMessage) (defaultRoute, bool) {
	dst, ok := routeAddr[*route.Inet4Addr](message.Addrs, syscall.RTAX_DST)
	if !ok || !isZeroInet4Addr(dst) {
		return defaultRoute{}, false
	}
	netmask, ok := routeAddr[*route.Inet4Addr](message.Addrs, syscall.RTAX_NETMASK)
	if ok && !isZeroInet4Addr(netmask) {
		return defaultRoute{}, false
	}
	gateway, ok := routeAddr[*route.Inet4Addr](message.Addrs, syscall.RTAX_GATEWAY)
	if !ok || isZeroInet4Addr(gateway) {
		return defaultRoute{}, false
	}
	return defaultRoute{
		interfaceIndex: message.Index,
		gatewayIP:      netip.AddrFrom4(gateway.IP),
	}, true
}

func parseDefaultIPv6Route(message *route.RouteMessage) (defaultRoute, bool) {
	dst, ok := routeAddr[*route.Inet6Addr](message.Addrs, syscall.RTAX_DST)
	if !ok || !isZeroInet6Addr(dst) {
		return defaultRoute{}, false
	}
	netmask, ok := routeAddr[*route.Inet6Addr](message.Addrs, syscall.RTAX_NETMASK)
	if ok && !isZeroInet6Addr(netmask) {
		return defaultRoute{}, false
	}
	gateway, ok := routeAddr[*route.Inet6Addr](message.Addrs, syscall.RTAX_GATEWAY)
	if !ok || isZeroInet6Addr(gateway) {
		return defaultRoute{}, false
	}
	return defaultRoute{
		interfaceIndex: message.Index,
		gatewayIP:      netip.AddrFrom16(gateway.IP),
	}, true
}

func routeAddr[T route.Addr](addrs []route.Addr, index int) (T, bool) {
	var zero T
	if index >= len(addrs) {
		return zero, false
	}
	addr, ok := addrs[index].(T)
	return addr, ok
}

func isZeroInet4Addr(addr *route.Inet4Addr) bool {
	for _, octet := range addr.IP {
		if octet != 0 {
			return false
		}
	}
	return true
}

func isZeroInet6Addr(addr *route.Inet6Addr) bool {
	for _, octet := range addr.IP {
		if octet != 0 {
			return false
		}
	}
	return true
}

func routeAddressFamily(target netip.Addr) int {
	if target.Is4() {
		return syscall.AF_INET
	}
	return syscall.AF_INET6
}
