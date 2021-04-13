package command

import (
	"context"
	"net"
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
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()
		return startTCPSYNScan(ctx, cliDstSubnet)
	},
}

func startTCPSYNScan(ctx context.Context, dstSubnet *net.IPNet) (err error) {
	scanName := tcp.SYNScanType

	var conf *scanConfig
	if conf, err = parseScanConfig(scanName, dstSubnet); err != nil {
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

	return startPacketScanEngine(ctx, newPacketScanConfig(
		withPacketScanMethod(m),
		withPacketBPFFilter(tcp.SYNACKBPFFilter),
		withPacketEngineConfig(newEngineConfig(
			withLogger(conf.logger),
			withScanRange(conf.scanRange),
		)),
	))
}
