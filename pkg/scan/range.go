package scan

import (
	"context"
	"errors"
	"net"

	"github.com/v-byte-cpu/sx/pkg/ip"
)

var ErrPortRange = errors.New("invalid port range")
var ErrSubnet = errors.New("invalid subnet")

type Request struct {
	Meta    map[string]interface{}
	SrcIP   net.IP
	DstIP   net.IP
	SrcMAC  []byte
	DstMAC  []byte
	DstPort uint16
}

func IPPortPairs(ctx context.Context, r *Range) (<-chan *Request, error) {
	if r.StartPort > r.EndPort {
		return nil, ErrPortRange
	}
	if r.Subnet == nil {
		return nil, ErrSubnet
	}
	out := make(chan *Request)
	go func() {
		defer close(out)
		for port := r.StartPort; port <= r.EndPort; port++ {
			ipnet := r.Subnet
			for ipaddr := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ipaddr); ip.Inc(ipaddr) {
				select {
				case <-ctx.Done():
					return
				case out <- &Request{
					SrcIP: r.SrcIP, SrcMAC: r.SrcMAC,
					DstIP: ip.DupIP(ipaddr), DstPort: port}:
				}
			}
		}
	}()
	return out, nil
}
