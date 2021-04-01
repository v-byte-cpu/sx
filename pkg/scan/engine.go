//go:generate mockgen -package scan -destination=mock_engine_test.go . PacketSource

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
	SrcSubnet *net.IPNet
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

	out := make(chan error)
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
				select {
				case <-ctx.Done():
					return
				case out <- e:
				}
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
