package command

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/v-byte-cpu/sx/command/log"
	"github.com/v-byte-cpu/sx/pkg/scan"
	"github.com/v-byte-cpu/sx/pkg/scan/docker"
)

func newDockerCmd() *dockerCmd {
	c := &dockerCmd{}

	cmd := &cobra.Command{
		Use: "docker [flags] [subnet]",
		Example: strings.Join([]string{
			"docker -p 2375 192.168.0.1/24", "docker -p 2300-2500 10.0.0.1",
			"docker --proto https -p 2300-2500 192.168.0.3",
			"docker -f ip_ports_file.jsonl", "docker -p 9200-9300 -f ips_file.jsonl"}, "\n"),
		Short: "Perform Docker scan",
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
			if logger, err = c.opts.getLogger(docker.ScanType, os.Stdout); err != nil {
				return
			}

			engine := c.opts.newDockerScanEngine(ctx)
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

type dockerCmd struct {
	cmd  *cobra.Command
	opts dockerCmdOpts
}

type dockerCmdOpts struct {
	genericScanCmdOpts
	timeout time.Duration
	proto   string
}

// TODO test
func (o *dockerCmdOpts) initCliFlags(cmd *cobra.Command) {
	o.genericScanCmdOpts.initCliFlags(cmd)
	cmd.Flags().DurationVarP(&o.timeout, "timeout", "t", defaultTimeout, "set request timeout")
	cmd.Flags().StringVar(&o.proto, "proto", cliHTTPProtoFlag, "set protocol to use, only http or https are valid")
}

// TODO test
func (o *dockerCmdOpts) parseRawOptions() (err error) {
	if err = o.genericScanCmdOpts.parseRawOptions(); err != nil {
		return
	}
	if o.proto != cliHTTPProtoFlag && o.proto != cliHTTPSProtoFlag {
		return errors.New("invalid HTTP proto flag: http or https required")
	}
	return
}

func (o *dockerCmdOpts) newDockerScanEngine(ctx context.Context) scan.EngineResulter {
	scanner := docker.NewScanner(o.proto, docker.WithDataTimeout(o.timeout))
	results := scan.NewResultChan(ctx, 1000)
	return scan.NewScanEngine(o.newIPPortGenerator(), scanner, results, scan.WithScanWorkerCount(o.workers))
}
