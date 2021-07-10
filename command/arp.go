package command

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/v-byte-cpu/sx/command/log"
	"github.com/v-byte-cpu/sx/pkg/ip"
	"github.com/v-byte-cpu/sx/pkg/scan"
	"github.com/v-byte-cpu/sx/pkg/scan/arp"
)

func newARPCmd() *arpCmd {
	c := &arpCmd{}

	cmd := &cobra.Command{
		Use:     "arp [flags] subnet",
		Example: strings.Join([]string{"arp 192.168.0.1/24", "arp 10.0.0.1"}, "\n"),
		Short:   "Perform ARP scan",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			if len(args) != 1 {
				return errors.New("requires one ip subnet argument")
			}
			dstSubnet, err := ip.ParseIPNet(args[0])
			if err != nil {
				return
			}

			if err = c.opts.parseRawOptions(); err != nil {
				return
			}
			var r *scan.Range
			if r, err = c.opts.getScanRange(dstSubnet); err != nil {
				return err
			}
			if r.SrcMAC == nil {
				return errSrcMAC
			}
			var logger log.Logger
			if logger, err = c.opts.getLogger(); err != nil {
				return err
			}

			m := c.opts.newARPScanMethod(ctx)

			return startPacketScanEngine(ctx, newPacketScanConfig(
				withPacketScanMethod(m),
				withPacketBPFFilter(arp.BPFFilter),
				withRateCount(c.opts.rateCount),
				withRateWindow(c.opts.rateWindow),
				withPacketEngineConfig(newEngineConfig(
					withLogger(logger),
					withScanRange(r),
					withExitDelay(c.opts.exitDelay),
				)),
			))
		},
	}

	c.opts.initCliFlags(cmd)

	c.cmd = cmd
	return c
}

type arpCmd struct {
	cmd  *cobra.Command
	opts arpCmdOpts
}

type arpCmdOpts struct {
	packetScanCmdOpts
	liveTimeout time.Duration
}

func (o *arpCmdOpts) initCliFlags(cmd *cobra.Command) {
	o.packetScanCmdOpts.initCliFlags(cmd)
	cmd.Flags().DurationVar(&o.liveTimeout, "live", 0, "enable live mode")
}

func (o *arpCmdOpts) getLogger() (logger log.Logger, err error) {
	if logger, err = o.packetScanCmdOpts.getLogger("arp", os.Stdout); err != nil {
		return
	}
	if o.liveTimeout > 0 {
		logger = log.NewUniqueLogger(logger)
	}
	return
}

func (o *arpCmdOpts) newARPScanMethod(ctx context.Context) *arp.ScanMethod {
	var reqgen scan.RequestGenerator = scan.NewIPRequestGenerator(scan.NewIPGenerator())
	if o.excludeIPs != nil {
		reqgen = scan.NewFilterIPRequestGenerator(reqgen, o.excludeIPs)
	}
	if o.liveTimeout > 0 {
		reqgen = scan.NewLiveRequestGenerator(reqgen, o.liveTimeout)
	}
	pktgen := scan.NewPacketMultiGenerator(arp.NewPacketFiller(), runtime.NumCPU())
	psrc := scan.NewPacketSource(reqgen, pktgen)
	results := scan.NewResultChan(ctx, 1000)
	return arp.NewScanMethod(psrc, results)
}
