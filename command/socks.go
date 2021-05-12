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

func init() {
	socksCmd.Flags().StringVarP(&cliPortsFlag, "ports", "p", "", "set ports to scan")
	socksCmd.Flags().StringVarP(&cliIPPortFileFlag, "file", "f", "", "set JSONL file with ip/port pairs to scan")
	socksCmd.Flags().IntVarP(&cliWorkerCountFlag, "workers", "w", defaultWorkerCount, "set workers count")
	socksCmd.Flags().DurationVarP(&cliTimeoutFlag, "timeout", "t", 2*time.Second, "set connect and data timeout")
	rootCmd.AddCommand(socksCmd)
}

var socksCmd = &cobra.Command{
	Use: "socks [flags] subnet",
	Example: strings.Join([]string{
		"socks -p 1080 192.168.0.1/24", "socks -p 1080-4567 10.0.0.1",
		"socks -f ip_ports_file.jsonl", "socks -p 1080-4567 -f ips_file.jsonl"}, "\n"),
	Short: "Perform SOCKS5 scan",
	// Long:  "Perform SOCKS scan. SOCKS5 scan is used by default unless --version option is specified",
	PreRunE: func(cmd *cobra.Command, args []string) (err error) {
		cliDstSubnet, err = parseDstSubnet(args)
		return
	},
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()

		var logger log.Logger
		if logger, err = getLogger("socks", os.Stdout); err != nil {
			return
		}

		engine := newSOCKSScanEngine(ctx)
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

func newSOCKSScanEngine(ctx context.Context) scan.EngineResulter {
	scanner := socks5.NewScanner(
		socks5.WithDialTimeout(cliTimeoutFlag),
		socks5.WithDataTimeout(cliTimeoutFlag))
	results := scan.NewResultChan(ctx, 1000)
	return scan.NewScanEngine(newIPPortGenerator(), scanner, results, scan.WithScanWorkerCount(cliWorkerCountFlag))
}
