// +build !linux

package ip

import (
	"errors"
	"net"
)

var errOS = errors.New("OS platform is not supported")

func GetDefaultInterface() (iface *net.Interface, ifaceIP net.IP, err error) {
	err = errOS
	return
}

func GetDefaultGatewayIP(iface *net.Interface) (gatewayIP net.IP, err error) {
	err = errOS
	return
}
