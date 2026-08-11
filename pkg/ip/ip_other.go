//go:build !linux && !darwin

package ip

import (
	"errors"
	"net"
	"net/netip"
)

var errOS = errors.New("OS platform is not supported")

func GetDefaultInterface(_ netip.Addr) (iface *net.Interface, ifaceIP netip.Addr, err error) {
	err = errOS
	return
}

func GetDefaultGatewayIP(_ *net.Interface, _ netip.Addr) (gatewayIP netip.Addr, err error) {
	err = errOS
	return
}
