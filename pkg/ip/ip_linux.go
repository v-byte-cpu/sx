package ip

import (
	"math"
	"net"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

func GetDefaultInterface() (iface *net.Interface, ifaceIP net.IP, err error) {
	var routes []netlink.Route
	if routes, err = netlink.RouteList(nil, nl.FAMILY_V4); err != nil {
		return
	}
	priority := math.MaxInt32
	for _, route := range routes {
		// found default gateway
		if route.Dst == nil && route.Src == nil && route.Priority < priority {
			priority = route.Priority
			if iface, err = net.InterfaceByIndex(route.LinkIndex); err != nil {
				return
			}
			if ifaceIP, err = GetInterfaceIP(iface); err != nil {
				return
			}
		}
	}
	return
}

func GetDefaultGatewayIP(iface *net.Interface) (gatewayIP net.IP, err error) {
	var routes []netlink.Route
	if routes, err = netlink.RouteList(nil, nl.FAMILY_V4); err != nil {
		return
	}
	priority := math.MaxInt32
	for _, route := range routes {
		// found default gateway
		if route.Dst == nil && route.Src == nil && route.LinkIndex == iface.Index && route.Priority < priority {
			priority = route.Priority
			gatewayIP = route.Gw
		}
	}
	return
}
