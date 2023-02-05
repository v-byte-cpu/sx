//go:build !linux && !darwin
// +build !linux,!darwin

package ip

import (
	"errors"
	//xnet "golang.org/x/net"
	"net"
)

var errOS = errors.New("OS platform is not supported")

func GetDefaultInterface() (iface *net.Interface, ifaceIP net.IP, err error) {

	//xnet.FetchRIB()
	err = errOS
	return
}

func GetDefaultGatewayIP(iface *net.Interface) (gatewayIP net.IP, err error) {
	err = errOS
	return
}
