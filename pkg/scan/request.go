//go:generate mockgen -package scan -destination=mock_request_test.go . PortGenerator,IPGenerator,RequestGenerator,IPContainer
//go:generate easyjson -output_filename request_easyjson.go request.go

package scan

import (
	"bufio"
	"context"
	"errors"
	"io"
	"math/big"
	"net"
	"time"
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

type PortGetter interface {
	GetPort() (uint16, error)
}

type WrapPort uint16

func (p WrapPort) GetPort() (uint16, error) {
	return uint16(p), nil
}

type portError struct {
	error
}

func (err *portError) GetPort() (uint16, error) {
	return 0, err
}

type PortGenerator interface {
	Ports(ctx context.Context, r *Range) (<-chan PortGetter, error)
}

func NewPortGenerator() PortGenerator {
	return &portGenerator{}
}

type portGenerator struct{}

func (*portGenerator) Ports(ctx context.Context, r *Range) (<-chan PortGetter, error) {
	if err := validatePorts(r.Ports); err != nil {
		return nil, err
	}
	out := make(chan PortGetter, 100)
	go func() {
		defer close(out)
		for _, portRange := range r.Ports {
			it, err := newRangeIterator(int64(portRange.EndPort) - int64(portRange.StartPort) + 1)
			if err != nil {
				writePort(ctx, out, &portError{err})
				continue
			}
			basePort := int64(portRange.StartPort) - 1
			for {
				writePort(ctx, out, WrapPort(basePort+it.Int().Int64()))
				if !it.Next() {
					break
				}
			}
		}
	}()
	return out, nil
}

func writePort(ctx context.Context, out chan<- PortGetter, port PortGetter) {
	select {
	case <-ctx.Done():
		return
	case out <- port:
	}
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

type WrapIP net.IP

func (i WrapIP) GetIP() (net.IP, error) {
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
	ipnet := r.DstSubnet
	ones, bits := ipnet.Mask.Size()
	it, err := newRangeIterator(1 << (bits - ones))
	if err != nil {
		return nil, err
	}

	baseIP := big.NewInt(0).SetBytes(ipnet.IP.Mask(ipnet.Mask))
	baseIP.Sub(baseIP, big.NewInt(1))

	out := make(chan IPGetter, 100)
	go func() {
		defer close(out)
		for {
			i := it.Int()
			baseIP.Add(baseIP, i)
			// TODO IPv6
			ipaddr := baseIP.FillBytes(make([]byte, 4))
			baseIP.Sub(baseIP, i)

			writeIP(ctx, out, WrapIP(ipaddr))

			if !it.Next() {
				return
			}
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
	out := make(chan *Request, 100)
	go func() {
		defer close(out)
		for p := range ports {
			port, err := p.GetPort()
			if err != nil {
				writeRequest(ctx, out, &Request{Err: err})
				continue
			}
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

func (rg *fileIPPortGenerator) GenerateRequests(ctx context.Context, r *Range) (<-chan *Request, error) {
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
			entry.IP = ""
			entry.Port = 0
			if err := entry.UnmarshalJSON(scanner.Bytes()); err != nil {
				writeRequest(ctx, out, &Request{Err: ErrJSON})
				return
			}
			ip := net.ParseIP(entry.IP)
			if ip == nil {
				writeRequest(ctx, out, &Request{Err: ErrIP})
				continue
			}
			if !isValidPort(entry.Port) {
				writeRequest(ctx, out, &Request{Err: ErrPort})
				continue
			}
			writeRequest(ctx, out, &Request{
				SrcIP: r.SrcIP, SrcMAC: r.SrcMAC, DstIP: ip, DstPort: uint16(entry.Port)})
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
			writeIP(ctx, out, WrapIP(ip))
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
			if request, ok = readRequest(ctx, requests); ok {
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

func readRequest(ctx context.Context, requests <-chan *Request) (request *Request, ok bool) {
	select {
	case <-ctx.Done():
	case request, ok = <-requests:
	}
	return
}

type IPContainer interface {
	Contains(ip net.IP) (bool, error)
}

type filterIPRequestGenerator struct {
	delegate   RequestGenerator
	excludeIPs IPContainer
}

func NewFilterIPRequestGenerator(delegate RequestGenerator, excludeIPs IPContainer) RequestGenerator {
	return &filterIPRequestGenerator{delegate, excludeIPs}
}

func (rg *filterIPRequestGenerator) GenerateRequests(ctx context.Context, r *Range) (<-chan *Request, error) {
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
			if request, ok = readRequest(ctx, requests); !ok {
				return
			}
			contains, err := rg.excludeIPs.Contains(request.DstIP)
			if err != nil {
				request.Err = err
				writeRequest(ctx, out, request)
				continue
			}
			if contains {
				continue
			}
			writeRequest(ctx, out, request)
		}
	}()
	return out, nil
}
