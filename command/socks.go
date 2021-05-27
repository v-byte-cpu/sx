package command

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/v-byte-cpu/sx/command/log"
	"github.com/v-byte-cpu/sx/pkg/scan"
	"github.com/v-byte-cpu/sx/pkg/scan/socks5"
)

func newSocksCmd() *socksCmd {
	c := &socksCmd{}

	cmd := &cobra.Command{
		Use: "socks [flags] subnet",
		Example: strings.Join([]string{
			"socks -p 1080 192.168.0.1/24", "socks -p 1080-4567 10.0.0.1",
			"socks -f ip_ports_file.jsonl", "socks -p 1080-4567 -f ips_file.jsonl"}, "\n"),
		Short: "Perform SOCKS5 scan",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			if err = c.opts.parseRawOptions(); err != nil {
				return
			}
			scanRange, err := c.opts.parseScanRange(args)
			if err != nil {
				return
			}

			var logger log.Logger
			if logger, err = c.opts.getLogger(socks5.ScanType, os.Stdout); err != nil {
				return
			}

			engine := c.opts.newSOCKSScanEngine(ctx)
			return startScanEngine(ctx, engine,
				newEngineConfig(
					withLogger(logger),
					withScanRange(scanRange),
					withExitDelay(c.opts.exitDelay),
				))
		},
	}

	c.opts.initCliFlags(cmd)

	c.cmd = cmd
	return c
}

type socksCmd struct {
	cmd  *cobra.Command
	opts socksCmdOpts
}

type socksCmdOpts struct {
	genericScanCmdOpts
	timeout time.Duration
}

func (o *socksCmdOpts) initCliFlags(cmd *cobra.Command) {
	o.genericScanCmdOpts.initCliFlags(cmd)
	cmd.Flags().DurationVarP(&o.timeout, "timeout", "t", 2*time.Second, "set connect and data timeout")
}

func (o *socksCmdOpts) newSOCKSScanEngine(ctx context.Context) scan.EngineResulter {
	scanner := socks5.NewScanner(
		socks5.WithDialTimeout(o.timeout),
		socks5.WithDataTimeout(o.timeout))
	results := scan.NewResultChan(ctx, 1000)
	return scan.NewScanEngine(o.newIPPortGenerator(), scanner, results, scan.WithScanWorkerCount(o.workers))
}
