package ip

import (
	"math"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

func GetDefaultInterface(target netip.Addr) (iface *net.Interface, ifaceIP netip.Addr, err error) {
	var routes []netlink.Route
	if routes, err = netlink.RouteList(nil, routeFamily(target)); err != nil {
		return
	}
	priority := math.MaxInt32
	for _, route := range routes {
		// found default gateway
		if route.Dst == nil && route.Priority < priority {
			priority = route.Priority
			if iface, err = net.InterfaceByIndex(route.LinkIndex); err != nil {
				return
			}
			if route.Src != nil {
				if ifaceIP, _ = netip.AddrFromSlice(route.Src); ifaceIP.IsValid() {
					ifaceIP = ifaceIP.Unmap()
					continue
				}
			}
			ifaceIP, err = GetInterfaceIP(iface, target)
		}
	}
	return
}

func GetDefaultGatewayIP(iface *net.Interface, target netip.Addr) (gatewayIP netip.Addr, err error) {
	var routes []netlink.Route
	if routes, err = netlink.RouteList(nil, routeFamily(target)); err != nil {
		return
	}
	priority := math.MaxInt32
	for _, route := range routes {
		// found default gateway
		if route.Dst == nil && route.LinkIndex == iface.Index && route.Priority < priority {
			priority = route.Priority
			gatewayIP, _ = netip.AddrFromSlice(route.Gw)
			gatewayIP = gatewayIP.Unmap()
		}
	}
	return
}

func routeFamily(target netip.Addr) int {
	if target.Is4() {
		return nl.FAMILY_V4
	}
	return nl.FAMILY_V6
}
