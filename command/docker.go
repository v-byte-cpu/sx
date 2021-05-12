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
	"github.com/v-byte-cpu/sx/pkg/scan/docker"
)

func init() {
	dockerCmd.Flags().StringVarP(&cliPortsFlag, "ports", "p", "", "set ports to scan")
	dockerCmd.Flags().StringVarP(&cliIPPortFileFlag, "file", "f", "", "set JSONL file with ip/port pairs to scan")
	dockerCmd.Flags().StringVar(&cliProtoFlag, "proto", "", "set protocol to use, http is used by default; only http or https are valid")
	dockerCmd.Flags().IntVarP(&cliWorkerCountFlag, "workers", "w", defaultWorkerCount, "set workers count")
	dockerCmd.Flags().DurationVarP(&cliTimeoutFlag, "timeout", "t", defaultTimeout, "set request timeout")
	rootCmd.AddCommand(dockerCmd)
}

var dockerCmd = &cobra.Command{
	Use: "docker [flags] [subnet]",
	Example: strings.Join([]string{
		"docker -p 2375 192.168.0.1/24", "docker -p 2300-2500 10.0.0.1",
		"docker --proto https -p 2300-2500 192.168.0.3",
		"docker -f ip_ports_file.jsonl", "docker -p 9200-9300 -f ips_file.jsonl"}, "\n"),
	Short: "Perform Docker scan",
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
		if logger, err = getLogger("docker", os.Stdout); err != nil {
			return
		}

		engine := newDockerScanEngine(ctx)
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

func newDockerScanEngine(ctx context.Context) scan.EngineResulter {
	scanner := docker.NewScanner(cliProtoFlag, docker.WithDataTimeout(cliTimeoutFlag))
	results := scan.NewResultChan(ctx, 1000)
	return scan.NewScanEngine(newIPPortGenerator(), scanner, results, scan.WithScanWorkerCount(cliWorkerCountFlag))
}
