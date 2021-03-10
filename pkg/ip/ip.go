package ip

import (
	"errors"
	"net"
)

var (
	ErrInvalidAddr     = errors.New("invalid IP subnet/host")
	ErrSubnetInterface = errors.New("no directly connected interfaces to destination subnet")
)

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

func GetSubnetInterface(dstSubnet *net.IPNet) (*net.Interface, net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	for _, iface := range ifaces {
		iface := iface
		ifaceIP, err := GetSubnetInterfaceIP(&iface, dstSubnet)
		if err != nil {
			return nil, nil, err
		}
		if ifaceIP != nil {
			return &iface, ifaceIP.To4(), nil
		}
	}
	return nil, nil, ErrSubnetInterface
}

func GetSubnetInterfaceIP(iface *net.Interface, dstSubnet *net.IPNet) (net.IP, error) {
	dstSubnetIP := dstSubnet.IP.Mask(dstSubnet.Mask)
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.Contains(dstSubnetIP) {
			return ipnet.IP.To4(), nil
		}
	}
	return nil, nil
}
