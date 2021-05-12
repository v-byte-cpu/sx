package command

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"strings"

	"github.com/spf13/cobra"
	"github.com/v-byte-cpu/sx/command/log"
	"github.com/v-byte-cpu/sx/pkg/scan"
	"github.com/v-byte-cpu/sx/pkg/scan/elastic"
)

func init() {
	elasticCmd.Flags().StringVarP(&cliPortsFlag, "ports", "p", "", "set ports to scan")
	elasticCmd.Flags().StringVarP(&cliIPPortFileFlag, "file", "f", "", "set JSONL file with ip/port pairs to scan")
	elasticCmd.Flags().StringVar(&cliProtoFlag, "proto", "", "set protocol to use, http is used by default; only http or https are valid")
	elasticCmd.Flags().IntVarP(&cliWorkerCountFlag, "workers", "w", defaultWorkerCount, "set workers count")
	elasticCmd.Flags().DurationVarP(&cliTimeoutFlag, "timeout", "t", defaultTimeout, "set request timeout")
	rootCmd.AddCommand(elasticCmd)
}

var elasticCmd = &cobra.Command{
	Use: "elastic [flags] [subnet]",
	Example: strings.Join([]string{
		"elastic -p 9200 192.168.0.1/24", "elastic -p 9200-9300 10.0.0.1",
		"elastic --proto https -p 9200-9201 192.168.0.3",
		"elastic -f ip_ports_file.jsonl", "elastic -p 9200-9300 -f ips_file.jsonl"}, "\n"),
	Short: "Perform Elasticsearch scan",
	PreRunE: func(cmd *cobra.Command, args []string) (err error) {
		if len(cliProtoFlag) == 0 {
			cliProtoFlag = cliHTTPProtoFlag
		}
		if cliProtoFlag != cliHTTPProtoFlag && cliProtoFlag != cliHTTPSProtoFlag {
			return errors.New("invalid HTTP proto flag: http or https required")
		}
		cliDstSubnet, err = parseDstSubnet(args)
		return
	},
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()

		var logger log.Logger
		if logger, err = getLogger("elastic", os.Stdout); err != nil {
			return
		}

		engine := newElasticScanEngine(ctx)
		return startScanEngine(ctx, engine,
			newEngineConfig(
				withLogger(logger),
				withScanRange(&scan.Range{
					DstSubnet: cliDstSubnet,
					Ports:     cliPortRanges,
				}),
			))
	},
}

func newElasticScanEngine(ctx context.Context) scan.EngineResulter {
	scanner := elastic.NewScanner(cliProtoFlag, elastic.WithDataTimeout(cliTimeoutFlag))
	results := scan.NewResultChan(ctx, 1000)
	return scan.NewScanEngine(newIPPortGenerator(), scanner, results, scan.WithScanWorkerCount(cliWorkerCountFlag))
}
