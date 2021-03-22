package command

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"strings"

	"github.com/google/gopacket/layers"
	"github.com/spf13/cobra"
	"github.com/v-byte-cpu/sx/pkg/scan/tcp"
)

func init() {
	tcpCmd.AddCommand(tcpsynCmd)
}

var tcpsynCmd = &cobra.Command{
	Use:     "syn [flags] subnet",
	Example: strings.Join([]string{"tcp syn -p 22 192.168.0.1/24", "tcp syn -p 22-4567 10.0.0.1"}, "\n"),
	Short:   "Perform TCP SYN scan",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return errors.New("requires one ip subnet argument")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()
		return startTCPSYNScan(ctx, args[0], cliPortsFlag)
	},
}

func startTCPSYNScan(ctx context.Context, subnet, ports string) (err error) {
	scanName := tcp.SYNScanType

	var conf *scanConfig
	if conf, err = parseScanConfig(scanName, subnet, ports); err != nil {
		return
	}

	m := newTCPScanMethod(ctx, conf,
		withTCPScanName(scanName),
		withTCPPacketFiller(tcp.NewPacketFiller(tcp.WithSYN())),
		withTCPPacketFilterFunc(func(pkt *layers.TCP) bool {
			// port is open
			return pkt.SYN && pkt.ACK
		}),
		withTCPPacketFlags(tcp.EmptyFlags),
	)

	return startEngine(ctx, &engineConfig{
		logger:     conf.logger,
		scanRange:  conf.scanRange,
		scanMethod: m,
		// TODO SYN,ACK filter
		bpfFilter: tcp.BPFFilter,
	})
}
