package command

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/v-byte-cpu/sx/command/log"
	"github.com/v-byte-cpu/sx/pkg/ip"
	"github.com/v-byte-cpu/sx/pkg/scan"
	"github.com/v-byte-cpu/sx/pkg/scan/ndp"
)

func newNDPCmd() *ndpCmd {
	command := &ndpCmd{}
	cmd := &cobra.Command{
		Use:     "ndp [flags] [subnet]",
		Short:   "Perform IPv6 Neighbor Discovery scan",
		Example: strings.Join([]string{"ndp fe80::/120", "ndp --file ips.jsonl", "ndp --live 5s fe80::1%en0"}, "\n"),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			if len(args) > 1 || (len(args) == 0 && command.opts.ipFile == "") {
				return errors.New("requires one IPv6 subnet argument or file")
			}

			var dstZone string
			var dstPrefix netip.Prefix
			if len(args) == 1 {
				if dstPrefix, dstZone, err = ip.ParsePrefix(args[0]); err != nil {
					return err
				}
				if !dstPrefix.Addr().Is6() {
					return errors.New("NDP supports IPv6 only")
				}
			}
			if err = command.opts.parseRawOptions(); err != nil {
				return err
			}
			if command.opts.scanRange, err = command.opts.getScanRangeForFamily(dstPrefix, dstZone, true); err != nil {
				return err
			}
			if command.opts.scanRange.SrcMAC == nil {
				return errSrcMAC
			}
			if command.opts.logger, err = command.opts.getLogger(); err != nil {
				return err
			}

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()
			method := command.opts.newScanMethod(ctx)
			return startPacketScanEngine(ctx, newPacketScanConfig(
				withPacketScanMethod(method),
				withPacketBPFFilter(ndp.BPFFilter),
				withRateCount(command.opts.rateCount),
				withRateWindow(command.opts.rateWindow),
				withPacketEngineConfig(newEngineConfig(
					withLogger(command.opts.logger),
					withScanRange(command.opts.scanRange),
					withExitDelay(command.opts.exitDelay),
				)),
			))
		},
	}
	command.opts.initCliFlags(cmd)
	command.cmd = cmd
	return command
}

type ndpCmd struct {
	cmd  *cobra.Command
	opts ndpCmdOpts
}

type ndpCmdOpts struct {
	packetScanCmdOpts
	ipFile      string
	liveTimeout time.Duration
	scanRange   *scan.Range
	logger      log.Logger
}

func (o *ndpCmdOpts) initCliFlags(cmd *cobra.Command) {
	o.packetScanCmdOpts.initCliFlags(cmd)
	cmd.Flags().StringVarP(&o.ipFile, "file", "f", "", "set JSONL file with IPv6 addresses to scan")
	cmd.Flags().DurationVar(&o.liveTimeout, "live", 0, "enable live mode")
}

func (o *ndpCmdOpts) getLogger() (log.Logger, error) {
	logger, err := o.packetScanCmdOpts.getLogger(ndp.ScanType, os.Stdout)
	if err == nil && o.liveTimeout > 0 {
		logger = log.NewUniqueLogger(logger)
	}
	return logger, err
}

func (o *ndpCmdOpts) newScanMethod(ctx context.Context) *ndp.ScanMethod {
	ipGenerator := scan.NewIPGenerator()
	if o.ipFile != "" {
		ipGenerator = scan.NewFileIPGenerator(func() (io.ReadCloser, error) {
			if o.ipFile == "-" {
				return io.NopCloser(os.Stdin), nil
			}
			return os.Open(o.ipFile)
		})
	}
	requests := scan.NewIPRequestGenerator(ipGenerator)
	if o.excludeIPs != nil {
		requests = scan.NewFilterIPRequestGenerator(requests, o.excludeIPs)
	}
	if o.liveTimeout > 0 {
		requests = scan.NewLiveRequestGenerator(requests, o.liveTimeout)
	}
	packets := scan.NewPacketMultiGenerator(ndp.NewPacketFiller(), runtime.NumCPU())
	return ndp.NewScanMethod(
		scan.NewPacketSource(requests, packets),
		scan.NewResultChan(ctx, 1000),
		o.scanRange.Interface.Name,
	)
}
