//go:generate go tool mockgen -package scan -destination=mock_request_test.go . PortGenerator,IPGenerator,RequestGenerator,IPContainer
//go:generate go tool easyjson -output_filename request_easyjson.go request.go

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

// GeneratorResult contains one asynchronously generated value or its error.
type GeneratorResult[T any] struct {
	// Value contains the generated value when Err is nil.
	Value T
	// Err contains an error for this generated item.
	Err error
}

// PortGenerator produces ports for a scan range.
type PortGenerator interface {
	// Ports generates the ports described by r until completion or context cancellation.
	Ports(ctx context.Context, r *Range) (<-chan GeneratorResult[uint16], error)
}

func NewPortGenerator() PortGenerator {
	return &portGenerator{}
}

type portGenerator struct{}

func (*portGenerator) Ports(ctx context.Context, r *Range) (<-chan GeneratorResult[uint16], error) {
	if err := validatePorts(r.Ports); err != nil {
		return nil, err
	}
	out := make(chan GeneratorResult[uint16], 100)
	go func() {
		defer close(out)
		for _, portRange := range r.Ports {
			it, err := newRangeIterator(int64(portRange.EndPort) - int64(portRange.StartPort) + 1)
			if err != nil {
				if !sendContext(ctx, out, GeneratorResult[uint16]{Err: err}) {
					return
				}
				continue
			}
			basePort := int64(portRange.StartPort) - 1
			for {
				if !sendContext(ctx, out, GeneratorResult[uint16]{
					Value: uint16(basePort + it.Int().Int64()),
				}) {
					return
				}
				if !it.Next() {
					break
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

// IPGenerator produces IP addresses for a scan range.
type IPGenerator interface {
	// IPs generates the IP addresses described by r until completion or context cancellation.
	IPs(ctx context.Context, r *Range) (<-chan GeneratorResult[net.IP], error)
}

func NewIPGenerator() IPGenerator {
	return &ipGenerator{}
}

type ipGenerator struct{}

func (*ipGenerator) IPs(ctx context.Context, r *Range) (<-chan GeneratorResult[net.IP], error) {
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

	out := make(chan GeneratorResult[net.IP], 100)
	go func() {
		defer close(out)
		for {
			i := it.Int()
			baseIP.Add(baseIP, i)
			// TODO IPv6
			ipaddr := baseIP.FillBytes(make([]byte, 4))
			baseIP.Sub(baseIP, i)

			if !sendContext(ctx, out, GeneratorResult[net.IP]{Value: ipaddr}) {
				return
			}

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
			if p.Err != nil {
				if !sendContext(ctx, out, &Request{Err: p.Err}) {
					return
				}
				continue
			}
			for ipaddr := range ips {
				if !sendContext(ctx, out, &Request{
					SrcIP: r.SrcIP, SrcMAC: r.SrcMAC,
					DstIP: ipaddr.Value, DstPort: p.Value, Err: ipaddr.Err}) {
					return
				}
			}
			if ips, err = rg.ipgen.IPs(ctx, r); err != nil {
				sendContext(ctx, out, &Request{Err: err})
				return
			}
		}
	}()
	return out, nil
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
			if !sendContext(ctx, out, &Request{
				SrcIP: r.SrcIP, SrcMAC: r.SrcMAC, DstIP: ipaddr.Value,
				Err: ipaddr.Err}) {
				return
			}
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
				sendContext(ctx, out, &Request{Err: ErrJSON})
				return
			}
			ip := net.ParseIP(entry.IP)
			if ip == nil {
				if !sendContext(ctx, out, &Request{Err: ErrIP}) {
					return
				}
				continue
			}
			if !isValidPort(entry.Port) {
				if !sendContext(ctx, out, &Request{Err: ErrPort}) {
					return
				}
				continue
			}
			if !sendContext(ctx, out, &Request{
				SrcIP: r.SrcIP, SrcMAC: r.SrcMAC, DstIP: ip, DstPort: uint16(entry.Port)}) {
				return
			}
		}
		if err = scanner.Err(); err != nil {
			sendContext(ctx, out, &Request{Err: err})
		}
	}()
	return out, nil
}

func isValidPort(port int) bool {
	return port > 0 && port <= 0xFFFF
}

type fileIPGenerator struct {
	openFile OpenFileFunc
}

func NewFileIPGenerator(openFile OpenFileFunc) IPGenerator {
	return &fileIPGenerator{openFile}
}

func (g *fileIPGenerator) IPs(ctx context.Context, _ *Range) (<-chan GeneratorResult[net.IP], error) {
	input, err := g.openFile()
	if err != nil {
		return nil, err
	}
	out := make(chan GeneratorResult[net.IP])
	go func() {
		defer close(out)
		defer input.Close()
		scanner := bufio.NewScanner(input)
		var entry IPPort
		for scanner.Scan() {
			entry = IPPort{}
			if err := entry.UnmarshalJSON(scanner.Bytes()); err != nil {
				sendContext(ctx, out, GeneratorResult[net.IP]{Err: ErrJSON})
				return
			}
			ip := net.ParseIP(entry.IP)
			if ip == nil {
				sendContext(ctx, out, GeneratorResult[net.IP]{Err: ErrIP})
				return
			}
			if !sendContext(ctx, out, GeneratorResult[net.IP]{Value: ip}) {
				return
			}
		}
		if err = scanner.Err(); err != nil {
			sendContext(ctx, out, GeneratorResult[net.IP]{Err: err})
		}
	}()
	return out, nil
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
				if !sendContext(ctx, out, request) {
					return
				}
				continue
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(rg.rescanTimeout):
				requests, err = rg.delegate.GenerateRequests(ctx, r)
				if err != nil {
					sendContext(ctx, out, &Request{Err: err})
					return
				}
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
				if !sendContext(ctx, out, request) {
					return
				}
				continue
			}
			if contains {
				continue
			}
			if !sendContext(ctx, out, request) {
				return
			}
		}
	}()
	return out, nil
}
