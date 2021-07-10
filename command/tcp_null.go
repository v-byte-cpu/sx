package command

import (
	"context"
	"os"
	"os/signal"
	"strings"

	"github.com/spf13/cobra"
	"github.com/v-byte-cpu/sx/pkg/scan/tcp"
)

func newTCPNULLCmd() *tcpNULLCmd {
	c := &tcpNULLCmd{}

	cmd := &cobra.Command{
		Use:     "null [flags] subnet",
		Example: strings.Join([]string{"tcp null -p 22 192.168.0.1/24", "tcp null -p 22-4567 10.0.0.1"}, "\n"),
		Short:   "Perform TCP NULL scan",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			if err = c.opts.parseRawOptions(); err != nil {
				return
			}

			scanName := tcp.NULLScanType
			if err = c.opts.parseOptions(scanName, args); err != nil {
				return
			}

			m := c.opts.newTCPScanMethod(ctx,
				withTCPScanName(scanName),
				withTCPPacketFillerOptions(),
				withTCPPacketFilterFunc(tcp.TrueFilter),
				withTCPPacketFlags(tcp.AllFlags),
			)

			return startPacketScanEngine(ctx, newPacketScanConfig(
				withPacketScanMethod(m),
				withPacketBPFFilter(tcp.BPFFilter),
				withRateCount(c.opts.rateCount),
				withRateWindow(c.opts.rateWindow),
				withPacketVPNmode(c.opts.vpnMode),
				withPacketEngineConfig(newEngineConfig(
					withLogger(c.opts.logger),
					withScanRange(c.opts.scanRange),
					withExitDelay(c.opts.exitDelay),
				)),
			))
		},
	}

	c.opts.initCliFlags(cmd)

	c.cmd = cmd
	return c
}

type tcpNULLCmd struct {
	cmd  *cobra.Command
	opts tcpCmdOpts
}
