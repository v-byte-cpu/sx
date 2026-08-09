//go:generate go tool mockgen -package scan -destination=mock_engine_test.go . PacketSource,Scanner

package scan

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/v-byte-cpu/sx/pkg/packet"
)

type PortRange struct {
	StartPort uint16
	EndPort   uint16
}

type Range struct {
	Interface *net.Interface
	DstSubnet *net.IPNet
	SrcIP     net.IP
	SrcMAC    net.HardwareAddr
	Ports     []*PortRange
}

// Engine runs a scan and reports its completion and errors.
type Engine interface {
	// Start runs a scan for r until completion or context cancellation.
	Start(ctx context.Context, r *Range) (done <-chan struct{}, errc <-chan error)
}

type Resulter interface {
	Results() <-chan Result
}

type EngineResulter interface {
	Engine
	Resulter
}

type engineResulter struct {
	Engine
	Resulter
}

func NewEngineResulter(e Engine, r Resulter) EngineResulter {
	return &engineResulter{Engine: e, Resulter: r}
}

type PacketSource interface {
	Packets(ctx context.Context, r *Range) <-chan *packet.BufferData
}

func NewPacketSource(reqgen RequestGenerator, pktgen PacketGenerator) PacketSource {
	return &packetSource{reqgen, pktgen}
}

type packetSource struct {
	reqgen RequestGenerator
	pktgen PacketGenerator
}

func (s *packetSource) Packets(ctx context.Context, r *Range) <-chan *packet.BufferData {
	requests, err := s.reqgen.GenerateRequests(ctx, r)
	if err != nil {
		out := make(chan *packet.BufferData, 1)
		out <- &packet.BufferData{Err: err}
		close(out)
		return out
	}
	return s.pktgen.Packets(ctx, requests)
}

type PacketEngine struct {
	src PacketSource
	snd packet.Sender
	rcv packet.Receiver
}

func NewPacketEngine(ps PacketSource, s packet.Sender, r packet.Receiver) *PacketEngine {
	return &PacketEngine{src: ps, snd: s, rcv: r}
}

// Start runs a packet scan for r until completion or context cancellation.
func (e *PacketEngine) Start(ctx context.Context, r *Range) (<-chan struct{}, <-chan error) {
	packets := e.src.Packets(ctx, r)
	done, errc1 := e.snd.SendPackets(ctx, packets)
	errc2 := e.rcv.ReceivePackets(ctx)
	return done, mergeChannels(ctx, 100, errc1, errc2)
}

type PacketMethod interface {
	PacketSource
	packet.Processor
	Resulter
}

func SetupPacketEngine(rw packet.ReadWriter, m PacketMethod) EngineResulter {
	sender := packet.NewSender(rw)
	receiver := packet.NewReceiver(rw, m)
	engine := NewPacketEngine(m, sender, receiver)
	return NewEngineResulter(engine, m)
}

type Scanner interface {
	Scan(ctx context.Context, r *Request) (Result, error)
}

type RateLimiter interface {
	// Take should block to make sure that the RPS is met.
	Take() time.Time
}

type rateLimitScanner struct {
	Scanner
	limiter RateLimiter
}

func NewRateLimitScanner(delegate Scanner, limiter RateLimiter) Scanner {
	return &rateLimitScanner{Scanner: delegate, limiter: limiter}
}

func (s *rateLimitScanner) Scan(ctx context.Context, r *Request) (Result, error) {
	s.limiter.Take()
	return s.Scanner.Scan(ctx, r)
}

// ScanEngine runs scanner workers over generated requests.
type ScanEngine struct {
	reqgen      RequestGenerator
	scanner     Scanner
	results     ResultChan
	workerCount int
}

// Assert that ScanEngine conforms to the scan.EngineResulter interface.
var _ EngineResulter = (*ScanEngine)(nil)

// ScanEngineOption configures a ScanEngine.
type ScanEngineOption func(s *ScanEngine)

// WithScanWorkerCount sets the number of concurrent scanner workers.
func WithScanWorkerCount(workerCount int) ScanEngineOption {
	return func(s *ScanEngine) {
		s.workerCount = workerCount
	}
}

// NewScanEngine creates a ScanEngine from its request, scanner, and result dependencies.
func NewScanEngine(reqgen RequestGenerator,
	scanner Scanner, results ResultChan, opts ...ScanEngineOption) *ScanEngine {
	s := &ScanEngine{
		reqgen:      reqgen,
		scanner:     scanner,
		results:     results,
		workerCount: 100,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Results returns scan results until the result context is canceled.
func (e *ScanEngine) Results() <-chan Result {
	return e.results.Chan()
}

// Start runs a scan for r until completion or context cancellation.
func (e *ScanEngine) Start(ctx context.Context, r *Range) (<-chan struct{}, <-chan error) {
	done := make(chan struct{})
	errc := make(chan error, 100)
	requests, err := e.reqgen.GenerateRequests(ctx, r)
	if err != nil {
		errc <- err
		close(errc)
		close(done)
		return done, errc
	}
	go func() {
		defer close(done)
		defer close(errc)
		var wg sync.WaitGroup
		for i := 1; i <= e.workerCount; i++ {
			wg.Add(1)
			go e.worker(ctx, &wg, requests, errc)
		}
		wg.Wait()
	}()
	return done, errc
}

func (e *ScanEngine) worker(ctx context.Context, wg *sync.WaitGroup,
	requests <-chan *Request, errc chan<- error) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case r, ok := <-requests:
			if !ok {
				return
			}
			if r.Err != nil {
				if !sendContext(ctx, errc, r.Err) {
					return
				}
				continue
			}
			result, err := e.scanner.Scan(ctx, r)
			if err != nil {
				if !sendContext(ctx, errc, err) {
					return
				}
				continue
			}
			if result != nil {
				e.results.Put(result)
			}
		}
	}
}
