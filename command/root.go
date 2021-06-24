package command

import (
	"context"
	"math/rand"
	"os"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/v-byte-cpu/sx/command/log"
	"github.com/v-byte-cpu/sx/pkg/packet"
	"github.com/v-byte-cpu/sx/pkg/packet/afpacket"
	"github.com/v-byte-cpu/sx/pkg/scan"
	"go.uber.org/ratelimit"
)

func Main(version string) {
	rand.Seed(time.Now().Unix())
	if err := newRootCmd(version).Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd(version string) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "sx",
		Short:   "Fast, modern, easy-to-use network scanner",
		Version: version,
	}

	tcpCmd := newTCPFlagsCmd().cmd
	tcpCmd.AddCommand(
		newTCPSYNCmd().cmd,
		newTCPFINCmd().cmd,
		newTCPNULLCmd().cmd,
		newTCPXmasCmd().cmd,
	)

	cmd.AddCommand(
		newARPCmd().cmd,
		newICMPCmd().cmd,
		newUDPCmd().cmd,
		tcpCmd,
		newSocksCmd().cmd,
		newDockerCmd().cmd,
		newElasticCmd().cmd,
	)

	return cmd
}

type bpfFilterFunc func(r *scan.Range) (filter string, maxPacketLength int)

type engineConfig struct {
	logger    log.Logger
	scanRange *scan.Range
	exitDelay time.Duration
}

type engineConfigOption func(c *engineConfig)

func withLogger(logger log.Logger) engineConfigOption {
	return func(c *engineConfig) {
		c.logger = logger
	}
}

func withScanRange(r *scan.Range) engineConfigOption {
	return func(c *engineConfig) {
		c.scanRange = r
	}
}

func withExitDelay(exitDelay time.Duration) engineConfigOption {
	return func(c *engineConfig) {
		c.exitDelay = exitDelay
	}
}

func newEngineConfig(opts ...engineConfigOption) *engineConfig {
	c := &engineConfig{
		exitDelay: defaultExitDelay,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

type packetScanConfig struct {
	*engineConfig
	scanMethod scan.PacketMethod
	bpfFilter  bpfFilterFunc
	rateCount  int
	rateWindow time.Duration
}

type packetScanConfigOption func(c *packetScanConfig)

func withPacketEngineConfig(conf *engineConfig) packetScanConfigOption {
	return func(c *packetScanConfig) {
		c.engineConfig = conf
	}
}

func withPacketScanMethod(sm scan.PacketMethod) packetScanConfigOption {
	return func(c *packetScanConfig) {
		c.scanMethod = sm
	}
}

func withPacketBPFFilter(bpfFilter bpfFilterFunc) packetScanConfigOption {
	return func(c *packetScanConfig) {
		c.bpfFilter = bpfFilter
	}
}

func withRateCount(rateCount int) packetScanConfigOption {
	return func(c *packetScanConfig) {
		c.rateCount = rateCount
	}
}

func withRateWindow(rateWindow time.Duration) packetScanConfigOption {
	return func(c *packetScanConfig) {
		c.rateWindow = rateWindow
	}
}

func newPacketScanConfig(opts ...packetScanConfigOption) *packetScanConfig {
	c := &packetScanConfig{}
	for _, o := range opts {
		o(c)
	}
	return c
}

func startPacketScanEngine(ctx context.Context, conf *packetScanConfig) error {
	r := conf.scanRange

	// setup network interface to read/write packets
	ps, err := afpacket.NewPacketSource(r.Interface.Name)
	if err != nil {
		return err
	}
	defer ps.Close()
	err = ps.SetBPFFilter(conf.bpfFilter(r))
	if err != nil {
		return err
	}
	var rw packet.ReadWriter = ps
	// setup rate limit for sending packets
	if conf.rateCount > 0 {
		rw = packet.NewRateLimitReadWriter(ps,
			ratelimit.New(conf.rateCount, ratelimit.Per(conf.rateWindow)))
	}
	engine := scan.SetupPacketEngine(rw, conf.scanMethod)
	return startScanEngine(ctx, engine, conf.engineConfig)
}

func startScanEngine(ctx context.Context, engine scan.EngineResulter, conf *engineConfig) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	logger := conf.logger

	// setup result logging
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.LogResults(ctx, engine.Results())
	}()

	// start scan
	done, errc := engine.Start(ctx, conf.scanRange)
	go func() {
		defer cancel()
		<-done
		<-time.After(conf.exitDelay)
	}()

	// error logging
	wg.Add(1)
	go func() {
		defer wg.Done()
		for err := range errc {
			logger.Error(err)
		}
	}()
	wg.Wait()
	return nil
}
