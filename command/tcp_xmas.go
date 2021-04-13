package command

import (
	"context"
	"os"
	"os/signal"
	"strings"

	"github.com/spf13/cobra"
	"github.com/v-byte-cpu/sx/pkg/scan/tcp"
)

func init() {
	tcpCmd.AddCommand(tcpxmasCmd)
}

var tcpxmasCmd = &cobra.Command{
	Use:     "xmas [flags] subnet",
	Example: strings.Join([]string{"tcp xmas -p 22 192.168.0.1/24", "tcp xmas -p 22-4567 10.0.0.1"}, "\n"),
	Short:   "Perform TCP Xmas scan",
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()

		scanName := tcp.XmasScanType

		var conf *scanConfig
		if conf, err = parseScanConfig(scanName, cliDstSubnet); err != nil {
			return
		}

		m := newTCPScanMethod(ctx, conf,
			withTCPScanName(scanName),
			withTCPPacketFiller(tcp.NewPacketFiller(tcp.WithFIN(), tcp.WithPSH(), tcp.WithURG())),
			withTCPPacketFilterFunc(tcp.TrueFilter),
			withTCPPacketFlags(tcp.AllFlags),
		)

		return startPacketScanEngine(ctx, newPacketScanConfig(
			withPacketScanMethod(m),
			withPacketBPFFilter(tcp.BPFFilter),
			withPacketEngineConfig(newEngineConfig(
				withLogger(conf.logger),
				withScanRange(conf.scanRange),
			)),
		))
	},
}
