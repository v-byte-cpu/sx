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
	tcpCmd.AddCommand(tcpnullCmd)
}

var tcpnullCmd = &cobra.Command{
	Use:     "null [flags] subnet",
	Example: strings.Join([]string{"tcp null -p 22 192.168.0.1/24", "tcp null -p 22-4567 10.0.0.1"}, "\n"),
	Short:   "Perform TCP NULL scan",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return errors.New("requires one ip subnet argument")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		var conf *scanConfig
		if conf, err = parseScanConfig(tcp.NULLScanType, args[0], portsFlag); err != nil {
			return
		}

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()

		m := newTCPScanMethod(ctx, conf,
			withTCPScanName(tcp.NULLScanType),
			withTCPPacketFiller(tcp.NewPacketFiller()),
			withTCPPacketFilterFunc(tcp.TrueFilter),
			withTCPPacketFlags(tcp.AllFlags),
		)

		return startEngine(ctx, &engineConfig{
			logger:     conf.logger,
			scanRange:  conf.scanRange,
			scanMethod: m,
			bpfFilter:  tcp.BPFFilter,
		})
	},
}
