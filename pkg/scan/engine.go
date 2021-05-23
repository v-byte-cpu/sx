//go:generate mockgen -package scan -destination=mock_engine_test.go . PacketSource,Scanner

package scan

import (
	"context"
	"net"
	"sync"

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

type Engine interface {
	Start(ctx context.Context, r *Range) (done <-chan interface{}, errc <-chan error)
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

func (e *PacketEngine) Start(ctx context.Context, r *Range) (<-chan interface{}, <-chan error) {
	packets := e.src.Packets(ctx, r)
	done, errc1 := e.snd.SendPackets(ctx, packets)
	errc2 := e.rcv.ReceivePackets(ctx)
	return done, mergeErrChan(ctx, errc1, errc2)
}

// generics would be helpful :)
func mergeErrChan(ctx context.Context, channels ...<-chan error) <-chan error {
	var wg sync.WaitGroup
	wg.Add(len(channels))

	out := make(chan error, 100)
	multiplex := func(c <-chan error) {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case e, ok := <-c:
				if !ok {
					return
				}
				writeError(ctx, out, e)
			}
		}
	}
	for _, c := range channels {
		go multiplex(c)
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
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

type GenericEngine struct {
	reqgen      RequestGenerator
	scanner     Scanner
	results     ResultChan
	workerCount int
}

// Assert that GenericEngine conforms to the scan.EngineResulter interface
var _ EngineResulter = (*GenericEngine)(nil)

type GenericEngineOption func(s *GenericEngine)

func WithScanWorkerCount(workerCount int) GenericEngineOption {
	return func(s *GenericEngine) {
		s.workerCount = workerCount
	}
}

func NewScanEngine(reqgen RequestGenerator,
	scanner Scanner, results ResultChan, opts ...GenericEngineOption) *GenericEngine {
	s := &GenericEngine{
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

func (e *GenericEngine) Results() <-chan Result {
	return e.results.Chan()
}

func (e *GenericEngine) Start(ctx context.Context, r *Range) (<-chan interface{}, <-chan error) {
	done := make(chan interface{})
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

func (e *GenericEngine) worker(ctx context.Context, wg *sync.WaitGroup,
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
				writeError(ctx, errc, r.Err)
				continue
			}
			// TODO rate limit
			result, err := e.scanner.Scan(ctx, r)
			if err != nil {
				writeError(ctx, errc, err)
				continue
			}
			if result != nil {
				e.results.Put(result)
			}
		}
	}
}

func writeError(ctx context.Context, out chan<- error, err error) {
	select {
	case <-ctx.Done():
		return
	case out <- err:
	}
}
