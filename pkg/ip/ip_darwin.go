//go:build darwin
// +build darwin

package ip

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"
)

func GetDefaultInterface() (iface *net.Interface, ifaceIP net.IP, err error) {
	return discoverGWDefaults()
}

func GetDefaultGatewayIP(iface *net.Interface) (gatewayIP net.IP, err error) {
	iface, ip, err := discoverGWDefaults()
	return ip, err
}

func discoverGWDefaults() (*net.Interface, net.IP, error) {
	routeCmd := exec.Command("/sbin/route", "-n", "get", "0.0.0.0")
	output, err := routeCmd.CombinedOutput()
	if err != nil {
		return nil, nil, err
	}

	// Darwin default format:
	//    route to: default
	//destination: default
	//       mask: default
	//    gateway: 10.0.0.1
	//  interface: en0
	//      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
	// recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
	//       0         0         0         0         0         0      1500         0

	ifname := parseValue("interface", string(output))
	if len(ifname) <= 0 {
		return nil, nil, fmt.Errorf("no interface found")
	}

	gw := parseValue("gateway", string(output))
	if len(gw) <= 0 {
		return nil, nil, fmt.Errorf("no gateway found")
	}

	ip := net.ParseIP(gw)
	ifi, err := net.InterfaceByName(ifname)

	return ifi, ip, err
}

func parseValue(key, data string) string {
	r := regexp.MustCompile(fmt.Sprintf(".*%s:\\s*([^\\s\\n]*){0,1}\\s*\\n.*", key))
	match := r.FindStringSubmatch(data)
	if match != nil && len(match) == 2 {
		return match[1]
	}
	return ""
}
