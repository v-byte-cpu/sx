//go:generate mockgen -package scan -destination=mock_request_test.go -source request.go
//go:generate easyjson -output_filename request_easyjson.go request.go

package scan

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/v-byte-cpu/sx/pkg/ip"
)

var (
	ErrPortRange = errors.New("invalid port range")
	ErrSubnet    = errors.New("invalid subnet")
	ErrIP        = errors.New("invalid ip")
	ErrPort      = errors.New("invalid port")
	ErrJSON      = errors.New("invalid json")
)

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

type IPGetter interface {
	GetIP() (net.IP, error)
}

type wrapIP net.IP

func (i wrapIP) GetIP() (net.IP, error) {
	return net.IP(i), nil
}

type IPGenerator interface {
	IPs(ctx context.Context, r *Range) (<-chan IPGetter, error)
}

func NewIPGenerator() IPGenerator {
	return &ipGenerator{}
}

type ipGenerator struct{}

func (*ipGenerator) IPs(ctx context.Context, r *Range) (<-chan IPGetter, error) {
	if r.DstSubnet == nil {
		return nil, ErrSubnet
	}
	out := make(chan IPGetter)
	go func() {
		defer close(out)
		ipnet := r.DstSubnet
		for ipaddr := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ipaddr); ip.Inc(ipaddr) {
			writeIP(ctx, out, wrapIP(ip.DupIP(ipaddr)))
		}
	}()
	return out, nil
}

type RequestGenerator interface {
	GenerateRequests(ctx context.Context, r *Range) (<-chan *Request, error)
}

func NewIPPortGenerator(ipgen IPGenerator, portgen PortGenerator) RequestGenerator {
	return &ipPortGenerator{ipgen, portgen}
}

type ipPortGenerator struct {
	ipgen   IPGenerator
	portgen PortGenerator
}

func (rg *ipPortGenerator) GenerateRequests(ctx context.Context, r *Range) (<-chan *Request, error) {
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
				dstip, err := ipaddr.GetIP()
				writeRequest(ctx, out, &Request{
					SrcIP: r.SrcIP, SrcMAC: r.SrcMAC,
					DstIP: dstip, DstPort: port, Err: err})
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
			dstip, err := ipaddr.GetIP()
			writeRequest(ctx, out, &Request{
				SrcIP: r.SrcIP, SrcMAC: r.SrcMAC, DstIP: dstip,
				Err: err,
			})
		}
	}()
	return out, nil
}

//easyjson:json
type IPPort struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

type fileIPPortGenerator struct {
	openFile OpenFileFunc
}

type OpenFileFunc func() (io.ReadCloser, error)

func NewFileIPPortGenerator(openFile OpenFileFunc) RequestGenerator {
	return &fileIPPortGenerator{openFile}
}

// TODO add meta field
func (rg *fileIPPortGenerator) GenerateRequests(ctx context.Context, _ *Range) (<-chan *Request, error) {
	input, err := rg.openFile()
	if err != nil {
		return nil, err
	}
	out := make(chan *Request)
	go func() {
		defer close(out)
		defer input.Close()
		scanner := bufio.NewScanner(input)
		var entry IPPort
		for scanner.Scan() {
			if err := entry.UnmarshalJSON(scanner.Bytes()); err != nil {
				writeRequest(ctx, out, &Request{Err: ErrJSON})
				return
			}
			ip := net.ParseIP(entry.IP)
			if ip == nil {
				writeRequest(ctx, out, &Request{Err: ErrIP})
				return
			}
			if !isValidPort(entry.Port) {
				writeRequest(ctx, out, &Request{Err: ErrPort})
				return
			}
			writeRequest(ctx, out, &Request{DstIP: ip, DstPort: uint16(entry.Port)})
		}
		if err = scanner.Err(); err != nil {
			writeRequest(ctx, out, &Request{Err: err})
		}
	}()
	return out, nil
}

func isValidPort(port int) bool {
	return port > 0 && port <= 0xFFFF
}

type ipError struct {
	error
}

func (err *ipError) GetIP() (net.IP, error) {
	return nil, err
}

type fileIPGenerator struct {
	openFile OpenFileFunc
}

func NewFileIPGenerator(openFile OpenFileFunc) IPGenerator {
	return &fileIPGenerator{openFile}
}

func (g *fileIPGenerator) IPs(ctx context.Context, _ *Range) (<-chan IPGetter, error) {
	input, err := g.openFile()
	if err != nil {
		return nil, err
	}
	out := make(chan IPGetter)
	go func() {
		defer close(out)
		defer input.Close()
		scanner := bufio.NewScanner(input)
		var entry IPPort
		for scanner.Scan() {
			if err := entry.UnmarshalJSON(scanner.Bytes()); err != nil {
				writeIP(ctx, out, &ipError{error: ErrJSON})
				return
			}
			ip := net.ParseIP(entry.IP)
			if ip == nil {
				writeIP(ctx, out, &ipError{error: ErrIP})
				return
			}
			writeIP(ctx, out, wrapIP(ip))
		}
		if err = scanner.Err(); err != nil {
			writeIP(ctx, out, &ipError{error: err})
		}
	}()
	return out, nil
}

func writeIP(ctx context.Context, out chan<- IPGetter, ip IPGetter) {
	select {
	case <-ctx.Done():
		return
	case out <- ip:
	}
}

type liveRequestGenerator struct {
	delegate      RequestGenerator
	rescanTimeout time.Duration
}

func NewLiveRequestGenerator(rg RequestGenerator, rescanTimeout time.Duration) RequestGenerator {
	return &liveRequestGenerator{rg, rescanTimeout}
}

func (rg *liveRequestGenerator) GenerateRequests(ctx context.Context, r *Range) (<-chan *Request, error) {
	requests, err := rg.delegate.GenerateRequests(ctx, r)
	if err != nil {
		return nil, err
	}
	out := make(chan *Request, cap(requests))
	go func() {
		defer close(out)
		var request *Request
		var ok bool
		for {
			select {
			case <-ctx.Done():
				return
			case request, ok = <-requests:
			}
			if ok {
				writeRequest(ctx, out, request)
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
	return out, nil
}
