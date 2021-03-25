//go:generate mockgen -package scan -destination=mock_request_test.go -source request.go

package scan

import (
	"context"
	"errors"
	"net"
	"time"

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
	Err     error
}

type PortGenerator interface {
	Ports(ctx context.Context, r *Range) (<-chan uint16, error)
}

func NewPortGenerator() PortGenerator {
	return &portGenerator{}
}

// TODO randomizedPortGenerator
type portGenerator struct{}

func (*portGenerator) Ports(ctx context.Context, r *Range) (<-chan uint16, error) {
	if err := validatePorts(r.Ports); err != nil {
		return nil, err
	}
	out := make(chan uint16)
	go func() {
		defer close(out)
		for _, portRange := range r.Ports {
			for port := int(portRange.StartPort); port <= int(portRange.EndPort); port++ {
				select {
				case <-ctx.Done():
					return
				case out <- uint16(port):
				}
			}
		}
	}()
	return out, nil
}

func validatePorts(ports []*PortRange) error {
	if len(ports) == 0 {
		return ErrPortRange
	}
	for _, portRange := range ports {
		if portRange.StartPort > portRange.EndPort {
			return ErrPortRange
		}
	}
	return nil
}

type IPGenerator interface {
	IPs(ctx context.Context, r *Range) (<-chan net.IP, error)
}

func NewIPGenerator() IPGenerator {
	return &ipGenerator{}
}

type ipGenerator struct{}

func (*ipGenerator) IPs(ctx context.Context, r *Range) (<-chan net.IP, error) {
	if r.DstSubnet == nil {
		return nil, ErrSubnet
	}
	out := make(chan net.IP)
	go func() {
		defer close(out)
		ipnet := r.DstSubnet
		for ipaddr := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ipaddr); ip.Inc(ipaddr) {
			select {
			case <-ctx.Done():
				return
			case out <- ip.DupIP(ipaddr):
			}
		}
	}()
	return out, nil
}

type RequestGenerator interface {
	GenerateRequests(ctx context.Context, r *Range) (<-chan *Request, error)
}

func NewIPPortRequestGenerator(ipgen IPGenerator, portgen PortGenerator) RequestGenerator {
	return &ipPortRequestGenerator{ipgen, portgen}
}

type ipPortRequestGenerator struct {
	ipgen   IPGenerator
	portgen PortGenerator
}

func (rg *ipPortRequestGenerator) GenerateRequests(ctx context.Context, r *Range) (<-chan *Request, error) {
	ports, err := rg.portgen.Ports(ctx, r)
	if err != nil {
		return nil, err
	}
	ips, err := rg.ipgen.IPs(ctx, r)
	if err != nil {
		return nil, err
	}
	out := make(chan *Request)
	go func() {
		defer close(out)
		for port := range ports {
			for ipaddr := range ips {
				writeRequest(ctx, out, &Request{
					SrcIP: r.SrcIP, SrcMAC: r.SrcMAC,
					DstIP: ipaddr, DstPort: port})
			}
			if ips, err = rg.ipgen.IPs(ctx, r); err != nil {
				writeRequest(ctx, out, &Request{Err: err})
				return
			}
		}
	}()
	return out, nil
}

func writeRequest(ctx context.Context, out chan<- *Request, request *Request) {
	select {
	case <-ctx.Done():
		return
	case out <- request:
	}
}

func NewIPRequestGenerator(ipgen IPGenerator) RequestGenerator {
	return &ipRequestGenerator{ipgen}
}

type ipRequestGenerator struct {
	ipgen IPGenerator
}

func (rg *ipRequestGenerator) GenerateRequests(ctx context.Context, r *Range) (<-chan *Request, error) {
	ips, err := rg.ipgen.IPs(ctx, r)
	if err != nil {
		return nil, err
	}
	out := make(chan *Request)
	go func() {
		defer close(out)
		for ipaddr := range ips {
			writeRequest(ctx, out, &Request{
				SrcIP: r.SrcIP, SrcMAC: r.SrcMAC, DstIP: ipaddr,
			})
		}
	}()
	return out, nil
}

type LiveRequestGenerator struct {
	delegate      RequestGenerator
	rescanTimeout time.Duration
}

func NewLiveRequestGenerator(rg RequestGenerator, rescanTimeout time.Duration) RequestGenerator {
	return &LiveRequestGenerator{rg, rescanTimeout}
}

func (rg *LiveRequestGenerator) GenerateRequests(ctx context.Context, r *Range) (<-chan *Request, error) {
	requests, err := rg.delegate.GenerateRequests(ctx, r)
	if err != nil {
		return nil, err
	}
	result := make(chan *Request, cap(requests))
	go func() {
		defer close(result)
		var request *Request
		var ok bool
		for {
			select {
			case <-ctx.Done():
				return
			case request, ok = <-requests:
			}
			if ok {
				select {
				case <-ctx.Done():
					return
				case result <- request:
				}
				continue
			}

			select {
			case <-ctx.Done():
				return
			case <-time.After(rg.rescanTimeout):
				requests, _ = rg.delegate.GenerateRequests(ctx, r)
			}
		}
	}()
	return result, nil
}
