package command

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	"github.com/v-byte-cpu/sx/pkg/scan"
	"github.com/v-byte-cpu/sx/pkg/scan/arp"
	"github.com/v-byte-cpu/sx/pkg/scan/icmp"
	"github.com/v-byte-cpu/sx/pkg/scan/udp"
)

func init() {
	udpCmd.Flags().StringVarP(&cliPortsFlag, "ports", "p", "", "set ports to scan")
	rootCmd.AddCommand(udpCmd)
}

var udpCmd = &cobra.Command{
	Use:     "udp [flags] subnet",
	Example: strings.Join([]string{"udp -p 22 192.168.0.1/24", "udp -p 22-4567 10.0.0.1"}, "\n"),
	Short:   "Perform UDP scan",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return errors.New("requires one ip subnet argument")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()

		var conf *scanConfig
		if conf, err = parseScanConfig(udp.ScanType, args[0]); err != nil {
			return
		}

		m := newUDPScanMethod(ctx, conf)

		return startEngine(ctx, &engineConfig{
			logger:     conf.logger,
			scanRange:  conf.scanRange,
			scanMethod: m,
			bpfFilter:  icmp.BPFFilter,
			rateCount:  cliRateCount,
			rateWindow: cliRateWindow,
		})
	},
}

func newUDPScanMethod(ctx context.Context, conf *scanConfig) *udp.ScanMethod {
	portgen := scan.NewPortGenerator()
	ipgen := scan.NewIPGenerator()
	reqgen := arp.NewCacheRequestGenerator(
		scan.NewIPPortRequestGenerator(ipgen, portgen), conf.gatewayIP, conf.cache)
	pktgen := scan.NewPacketMultiGenerator(udp.NewPacketFiller(), runtime.NumCPU())
	psrc := scan.NewPacketSource(reqgen, pktgen)
	results := scan.NewResultChan(ctx, 1000)
	return udp.NewScanMethod(psrc, results)
}
