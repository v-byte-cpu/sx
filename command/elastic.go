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
	"github.com/v-byte-cpu/sx/pkg/scan/elastic"
)

func newElasticCmd() *elasticCmd {
	c := &elasticCmd{}

	cmd := &cobra.Command{
		Use: "elastic [flags] [subnet]",
		Example: strings.Join([]string{
			"elastic -p 9200 192.168.0.1/24", "elastic -p 9200-9300 10.0.0.1",
			"elastic --proto https -p 9200-9201 192.168.0.3",
			"elastic -f ip_ports_file.jsonl", "elastic -p 9200-9300 -f ips_file.jsonl"}, "\n"),
		Short: "Perform Elasticsearch scan",
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
			if logger, err = c.opts.getLogger(elastic.ScanType, os.Stdout); err != nil {
				return
			}

			engine := c.opts.newElasticScanEngine(ctx)
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

type elasticCmd struct {
	cmd  *cobra.Command
	opts elasticCmdOpts
}

type elasticCmdOpts struct {
	genericScanCmdOpts
	timeout time.Duration
	proto   string
}

func (o *elasticCmdOpts) initCliFlags(cmd *cobra.Command) {
	o.genericScanCmdOpts.initCliFlags(cmd)
	cmd.Flags().DurationVarP(&o.timeout, "timeout", "t", defaultTimeout, "set request timeout")
	cmd.Flags().StringVar(&o.proto, "proto", cliHTTPProtoFlag, "set protocol to use, only http or https are valid")
}

func (o *elasticCmdOpts) parseRawOptions() (err error) {
	if err = o.genericScanCmdOpts.parseRawOptions(); err != nil {
		return
	}
	if o.proto != cliHTTPProtoFlag && o.proto != cliHTTPSProtoFlag {
		return errors.New("invalid HTTP proto flag: http or https required")
	}
	return
}

func (o *elasticCmdOpts) newElasticScanEngine(ctx context.Context) scan.EngineResulter {
	scanner := elastic.NewScanner(o.proto, elastic.WithDataTimeout(o.timeout))
	return o.newScanEngine(ctx, scanner)
}
