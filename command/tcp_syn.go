package command

import (
	"context"
	"os"
	"os/signal"
	"strings"

	"github.com/google/gopacket/layers"
	"github.com/spf13/cobra"
	"github.com/v-byte-cpu/sx/pkg/scan/tcp"
)

func newTCPSYNCmd() *tcpSYNCmd {
	c := &tcpSYNCmd{}

	cmd := &cobra.Command{
		Use:     "syn [flags] subnet",
		Example: strings.Join([]string{"tcp syn -p 22 192.168.0.1/24", "tcp syn -p 22-4567 10.0.0.1"}, "\n"),
		Short:   "Perform TCP SYN scan",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			if err = c.opts.parseRawOptions(); err != nil {
				return
			}
			return c.opts.startScan(ctx, args)
		},
	}

	c.opts.initCliFlags(cmd)

	c.cmd = cmd
	return c
}

type tcpSYNCmd struct {
	cmd  *cobra.Command
	opts tcpSYNCmdOpts
}

type tcpSYNCmdOpts struct {
	tcpCmdOpts
}

func newTCPSYNCmdOpts(opts tcpCmdOpts) *tcpSYNCmdOpts {
	return &tcpSYNCmdOpts{opts}
}

func (o *tcpSYNCmdOpts) startScan(ctx context.Context, args []string) (err error) {
	scanName := tcp.SYNScanType

	var conf *scanConfig
	if conf, err = o.parseScanConfig(scanName, args); err != nil {
		return
	}

	m := o.newTCPScanMethod(ctx, conf,
		withTCPScanName(scanName),
		withTCPPacketFiller(tcp.NewPacketFiller(tcp.WithSYN())),
		withTCPPacketFilterFunc(func(pkt *layers.TCP) bool {
			// port is open
			return pkt.SYN && pkt.ACK
		}),
		withTCPPacketFlags(tcp.EmptyFlags),
	)

	return startPacketScanEngine(ctx, newPacketScanConfig(
		withPacketScanMethod(m),
		withPacketBPFFilter(tcp.SYNACKBPFFilter),
		withRateCount(o.rateCount),
		withRateWindow(o.rateWindow),
		withPacketEngineConfig(newEngineConfig(
			withLogger(conf.logger),
			withScanRange(conf.scanRange),
			withExitDelay(o.exitDelay),
		)),
	))
}
