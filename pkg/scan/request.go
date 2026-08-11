//go:generate go tool mockgen -package scan -destination=mock_request_test.go . PortGenerator,IPGenerator,RequestGenerator,IPContainer
//go:generate go tool easyjson -output_filename request_easyjson.go request.go

package scan

import (
	"bufio"
	"context"
	"errors"
	"io"
	"math/big"
	"net/netip"
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
	SrcIP   netip.Addr
	DstIP   netip.Addr
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
	IPs(ctx context.Context, r *Range) (<-chan GeneratorResult[netip.Addr], error)
}

func NewIPGenerator() IPGenerator {
	return &ipGenerator{}
}

type ipGenerator struct{}

func (*ipGenerator) IPs(ctx context.Context, r *Range) (<-chan GeneratorResult[netip.Addr], error) {
	if !r.DstPrefix.IsValid() {
		return nil, ErrSubnet
	}
	prefix := r.DstPrefix.Masked()
	bits := prefix.Addr().BitLen()
	hostBits := bits - prefix.Bits()
	if hostBits > 32 {
		return nil, errRangeSize
	}
	it, err := newRangeIterator(1 << hostBits)
	if err != nil {
		return nil, err
	}

	baseIP := big.NewInt(0).SetBytes(prefix.Addr().AsSlice())
	baseIP.Sub(baseIP, big.NewInt(1))

	out := make(chan GeneratorResult[netip.Addr], 100)
	go func() {
		defer close(out)
		for {
			i := it.Int()
			baseIP.Add(baseIP, i)
			addr, ok := netip.AddrFromSlice(baseIP.FillBytes(make([]byte, bits/8)))
			baseIP.Sub(baseIP, i)
			if !ok {
				sendContext(ctx, out, GeneratorResult[netip.Addr]{Err: ErrIP})
				return
			}
			if r.DstZone != "" {
				addr = addr.WithZone(r.DstZone)
			}

			if !sendContext(ctx, out, GeneratorResult[netip.Addr]{Value: addr}) {
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
		for scanner.Scan() {
			request, fatal := parseFileIPPortRequest(scanner.Bytes(), r)
			if !sendContext(ctx, out, request) {
				return
			}
			if fatal {
				return
			}
		}
		if err = scanner.Err(); err != nil {
			sendContext(ctx, out, &Request{Err: err})
		}
	}()
	return out, nil
}

func parseFileIPPortRequest(data []byte, r *Range) (*Request, bool) {
	var entry IPPort
	if err := entry.UnmarshalJSON(data); err != nil {
		return &Request{Err: ErrJSON}, true
	}
	ip, err := netip.ParseAddr(entry.IP)
	if err != nil {
		return &Request{Err: ErrIP}, false
	}
	if !isValidPort(entry.Port) {
		return &Request{Err: ErrPort}, false
	}
	ip = ip.Unmap()
	if r.SrcIP.IsValid() && r.SrcIP.Is4() != ip.Is4() {
		return &Request{Err: ErrIP}, false
	}
	return &Request{
		SrcIP: r.SrcIP, SrcMAC: r.SrcMAC, DstIP: ip, DstPort: uint16(entry.Port),
	}, false
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

func (g *fileIPGenerator) IPs(ctx context.Context, r *Range) (<-chan GeneratorResult[netip.Addr], error) {
	input, err := g.openFile()
	if err != nil {
		return nil, err
	}
	out := make(chan GeneratorResult[netip.Addr])
	go func() {
		defer close(out)
		defer input.Close()
		scanner := bufio.NewScanner(input)
		var entry IPPort
		for scanner.Scan() {
			entry = IPPort{}
			if err := entry.UnmarshalJSON(scanner.Bytes()); err != nil {
				sendContext(ctx, out, GeneratorResult[netip.Addr]{Err: ErrJSON})
				return
			}
			ip, err := netip.ParseAddr(entry.IP)
			if err != nil {
				sendContext(ctx, out, GeneratorResult[netip.Addr]{Err: ErrIP})
				return
			}
			ip = ip.Unmap()
			if r.SrcIP.IsValid() && r.SrcIP.Is4() != ip.Is4() {
				sendContext(ctx, out, GeneratorResult[netip.Addr]{Err: ErrIP})
				return
			}
			if !sendContext(ctx, out, GeneratorResult[netip.Addr]{Value: ip}) {
				return
			}
		}
		if err = scanner.Err(); err != nil {
			sendContext(ctx, out, GeneratorResult[netip.Addr]{Err: err})
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
	// Contains reports whether ip belongs to the container.
	Contains(ip netip.Addr) (bool, error)
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
