package ip

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

var ErrInvalidAddr = errors.New("invalid IP subnet/host")

// ParsePrefix parses an IP host or prefix. A scoped IPv6 host returns its zone
// separately because netip.Prefix deliberately does not retain zones.
func ParsePrefix(input string) (netip.Prefix, string, error) {
	if percent, slash := strings.LastIndexByte(input, '%'), strings.LastIndexByte(input, '/'); percent >= 0 && slash > percent {
		zone := input[percent+1 : slash]
		prefix, err := netip.ParsePrefix(input[:percent] + input[slash:])
		if err != nil || zone == "" || !prefix.Addr().Is6() {
			return netip.Prefix{}, "", ErrInvalidAddr
		}
		return prefix.Masked(), zone, nil
	}
	if prefix, err := netip.ParsePrefix(input); err == nil {
		addr := prefix.Addr()
		bits := prefix.Bits()
		if addr.Is4In6() {
			if bits < 96 {
				return netip.Prefix{}, "", ErrInvalidAddr
			}
			addr = addr.Unmap()
			bits -= 96
		}
		return netip.PrefixFrom(addr, bits).Masked(), "", nil
	}

	addr, err := netip.ParseAddr(input)
	if err != nil {
		return netip.Prefix{}, "", ErrInvalidAddr
	}
	zone := addr.Zone()
	addr = addr.WithZone("").Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), zone, nil
}

func GetInterfaceIP(iface *net.Interface, target netip.Addr) (netip.Addr, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return netip.Addr{}, err
	}
	prefixes := make([]netip.Prefix, 0, len(addrs))
	for _, addr := range addrs {
		prefix, err := netip.ParsePrefix(addr.String())
		if err == nil {
			prefixes = append(prefixes, prefix)
		}
	}
	result := selectInterfaceIP(prefixes, target)
	if !result.IsValid() {
		return netip.Addr{}, fmt.Errorf("interface has no matching IP address: %s", iface.Name)
	}
	return result, nil
}

func selectInterfaceIP(addresses []netip.Prefix, target netip.Addr) netip.Addr {
	wantIPv4 := target.Is4()
	wantLinkLocal := target.Is6() && (target.IsLinkLocalUnicast() || target.IsLinkLocalMulticast())
	for _, prefix := range addresses {
		addr := prefix.Addr().Unmap()
		if addr.Is4() != wantIPv4 {
			continue
		}
		if addr.Is6() && addr.IsLinkLocalUnicast() != wantLinkLocal {
			continue
		}
		return addr
	}
	return netip.Addr{}
}

func GetLocalPrefixInterface(dstPrefix netip.Prefix) (iface *net.Interface, ifaceIP netip.Addr, err error) {
	var ifaces []net.Interface
	if ifaces, err = net.Interfaces(); err != nil {
		return
	}
	for _, v := range ifaces {
		viface := v
		if ifaceIP, err = GetLocalPrefixInterfaceIP(&viface, dstPrefix); err != nil {
			return
		}
		if ifaceIP.IsValid() {
			return &viface, ifaceIP, nil
		}
	}
	return
}

func GetLocalPrefixInterfaceIP(iface *net.Interface, dstPrefix netip.Prefix) (netip.Addr, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return netip.Addr{}, err
	}
	for _, addr := range addrs {
		prefix, err := netip.ParsePrefix(addr.String())
		if err == nil && prefix.Contains(dstPrefix.Addr()) {
			return prefix.Addr().Unmap(), nil
		}
	}
	return netip.Addr{}, nil
}
