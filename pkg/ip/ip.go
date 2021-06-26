package ip

import (
	"errors"
	"fmt"
	"net"
)

var ErrInvalidAddr = errors.New("invalid IP subnet/host")

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

func GetInterfaceIP(iface *net.Interface) (ifaceIP net.IP, err error) {
	var addrs []net.Addr
	if addrs, err = iface.Addrs(); err != nil || len(addrs) == 0 {
		return
	}
	if ipnet, ok := addrs[0].(*net.IPNet); ok {
		return ipnet.IP, nil
	}
	return nil, fmt.Errorf("invalid IP address: %v", addrs[0])
}

func GetLocalSubnetInterface(dstSubnet *net.IPNet) (iface *net.Interface, ifaceIP net.IP, err error) {
	var ifaces []net.Interface
	if ifaces, err = net.Interfaces(); err != nil {
		return
	}
	for _, v := range ifaces {
		viface := v
		if ifaceIP, err = GetLocalSubnetInterfaceIP(&viface, dstSubnet); err != nil {
			return
		}
		if ifaceIP != nil {
			return &viface, ifaceIP, nil
		}
	}
	return
}

func GetLocalSubnetInterfaceIP(iface *net.Interface, dstSubnet *net.IPNet) (net.IP, error) {
	dstSubnetIP := dstSubnet.IP.Mask(dstSubnet.Mask)
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.Contains(dstSubnetIP) {
			return ipnet.IP, nil
		}
	}
	return nil, nil
}
