package command

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"strings"

	"github.com/spf13/cobra"
	"github.com/v-byte-cpu/sx/pkg/scan/tcp"
)

func init() {
	tcpCmd.AddCommand(tcpfinCmd)
}

var tcpfinCmd = &cobra.Command{
	Use:     "fin [flags] subnet",
	Example: strings.Join([]string{"tcp fin -p 22 192.168.0.1/24", "tcp fin -p 22-4567 10.0.0.1"}, "\n"),
	Short:   "Perform TCP FIN scan",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return errors.New("requires one ip subnet argument")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()

		scanName := tcp.FINScanType

		var conf *scanConfig
		if conf, err = parseScanConfig(scanName, args[0]); err != nil {
			return
		}

		m := newTCPScanMethod(ctx, conf,
			withTCPScanName(scanName),
			withTCPPacketFiller(tcp.NewPacketFiller(tcp.WithFIN())),
			withTCPPacketFilterFunc(tcp.TrueFilter),
			withTCPPacketFlags(tcp.AllFlags),
		)

		return startEngine(ctx, newEngineConfig(
			withLogger(conf.logger),
			withScanRange(conf.scanRange),
			withScanMethod(m),
			withBPFFilter(tcp.BPFFilter)))
	},
}
