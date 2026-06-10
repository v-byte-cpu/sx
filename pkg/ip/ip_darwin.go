package ip

import (
	"net"
	"syscall"

	"golang.org/x/net/route"
)

type defaultRoute struct {
	interfaceIndex int
	gatewayIP      net.IP
}

func GetDefaultInterface() (iface *net.Interface, ifaceIP net.IP, err error) {
	defaultRoute, err := findDefaultRoute(0)
	if err != nil || defaultRoute == nil {
		return nil, nil, err
	}
	if iface, err = net.InterfaceByIndex(defaultRoute.interfaceIndex); err != nil {
		return nil, nil, err
	}
	if ifaceIP, err = GetInterfaceIP(iface); err != nil {
		return nil, nil, err
	}
	return iface, ifaceIP, nil
}

func GetDefaultGatewayIP(iface *net.Interface) (gatewayIP net.IP, err error) {
	defaultRoute, err := findDefaultRoute(iface.Index)
	if err != nil || defaultRoute == nil {
		return nil, err
	}
	return defaultRoute.gatewayIP, nil
}

func findDefaultRoute(interfaceIndex int) (*defaultRoute, error) {
	rib, err := route.FetchRIB(syscall.AF_INET, route.RIBTypeRoute, 0)
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
		defaultRoute, ok := parseDefaultRoute(routeMessage)
		if ok && (interfaceIndex == 0 || interfaceIndex == defaultRoute.interfaceIndex) {
			return &defaultRoute, nil
		}
	}
	return nil, nil
}

func parseDefaultRoute(message *route.RouteMessage) (defaultRoute, bool) {
	if message.Err != nil || message.Index == 0 || message.Flags&syscall.RTF_GATEWAY == 0 {
		return defaultRoute{}, false
	}
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
		gatewayIP:      net.IP(gateway.IP[:]).To4(),
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
