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
}

type RequestGenerator interface {
	GenerateRequests(ctx context.Context, r *Range) (<-chan *Request, error)
}

type RequestGeneratorFunc func(ctx context.Context, r *Range) (<-chan *Request, error)

func (rg RequestGeneratorFunc) GenerateRequests(ctx context.Context, r *Range) (<-chan *Request, error) {
	return rg(ctx, r)
}

func Requests(ctx context.Context, r *Range) (<-chan *Request, error) {
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

type LiveRequestGenerator struct {
	rescanTimeout time.Duration
}

func NewLiveRequestGenerator(rescanTimeout time.Duration) RequestGenerator {
	return &LiveRequestGenerator{rescanTimeout}
}

func (rg *LiveRequestGenerator) GenerateRequests(ctx context.Context, r *Range) (<-chan *Request, error) {
	requests, err := Requests(ctx, r)
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
				requests, _ = Requests(ctx, r)
			}
		}
	}()
	return result, nil
}
