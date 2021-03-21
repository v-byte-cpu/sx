package ip

import (
	"errors"
	"net"

	"github.com/google/gopacket/routing"
)

var ErrInvalidAddr = errors.New("invalid IP subnet/host")

func Inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func DupIP(ip net.IP) net.IP {
	dup := make([]byte, 4)
	copy(dup, ip.To4())
	return dup
}

func ParseIPNet(subnet string) (*net.IPNet, error) {
	_, result, err := net.ParseCIDR(subnet)
	if err == nil {
		return result, err
	}
	// try to parse host IP address instead
	ipAddr := net.ParseIP(subnet)
	if ipAddr == nil {
		return nil, ErrInvalidAddr
	}
	return &net.IPNet{IP: ipAddr.To4(), Mask: net.CIDRMask(32, 32)}, nil
}

func GetSubnetInterface(dstSubnet *net.IPNet) (iface *net.Interface, ifaceIP *net.IPNet, err error) {
	if iface, ifaceIP, err = GetLocalSubnetInterface(dstSubnet); err != nil {
		return
	}
	if iface != nil && ifaceIP != nil {
		return
	}
	// fallback to remote net (routing)
	var router routing.Router
	if router, err = routing.New(); err != nil {
		return
	}
	var srcIP net.IP
	if iface, _, srcIP, err = router.Route(dstSubnet.IP); err != nil {
		return
	}
	srcNet := &net.IPNet{IP: srcIP, Mask: net.CIDRMask(32, 32)}
	ifaceIP, err = GetLocalSubnetInterfaceIP(iface, srcNet)
	return
}

func GetSubnetInterfaceIP(iface *net.Interface, dstSubnet *net.IPNet) (ifaceIP *net.IPNet, err error) {
	if ifaceIP, err = GetLocalSubnetInterfaceIP(iface, dstSubnet); err != nil {
		return
	}
	if ifaceIP != nil {
		return
	}
	// fallback to remote net (routing)
	var router routing.Router
	if router, err = routing.New(); err != nil {
		return
	}
	var srcIP net.IP
	if _, _, srcIP, err = router.RouteWithSrc(iface.HardwareAddr, nil, dstSubnet.IP); err != nil {
		return
	}
	srcNet := &net.IPNet{IP: srcIP, Mask: net.CIDRMask(32, 32)}
	return GetLocalSubnetInterfaceIP(iface, srcNet)
}

func GetLocalSubnetInterface(dstSubnet *net.IPNet) (*net.Interface, *net.IPNet, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	for _, iface := range ifaces {
		iface := iface
		ifaceIP, err := GetLocalSubnetInterfaceIP(&iface, dstSubnet)
		if err != nil {
			return nil, nil, err
		}
		if ifaceIP != nil {
			return &iface, ifaceIP, nil
		}
	}
	return nil, nil, nil
}

func GetLocalSubnetInterfaceIP(iface *net.Interface, dstSubnet *net.IPNet) (*net.IPNet, error) {
	dstSubnetIP := dstSubnet.IP.Mask(dstSubnet.Mask)
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.Contains(dstSubnetIP) {
			return ipnet, nil
		}
	}
	return nil, nil
}
