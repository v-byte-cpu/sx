package command

import (
	"context"
	"errors"
	golog "log"
	"os"
	"os/signal"
	"runtime"
	"strings"

	"github.com/google/gopacket/layers"
	"github.com/spf13/cobra"
	"github.com/v-byte-cpu/sx/pkg/scan"
	"github.com/v-byte-cpu/sx/pkg/scan/arp"
	"github.com/v-byte-cpu/sx/pkg/scan/tcp"
)

func init() {
	tcpCmd.PersistentFlags().StringVarP(&portsFlag, "ports", "p", "", "set ports to scan")
	if err := tcpCmd.MarkPersistentFlagRequired("ports"); err != nil {
		golog.Fatalln(err)
	}
	rootCmd.AddCommand(tcpCmd)
}

var tcpCmd = &cobra.Command{
	Use:     "tcp [flags] subnet",
	Example: strings.Join([]string{"tcp -p 22 192.168.0.1/24", "tcp -p 22-4567 10.0.0.1"}, "\n"),
	Short:   "Perform TCP scan",
	Long:    "Perform TCP scan. TCP SYN scan is used by default unless --flags option is specified",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return errors.New("requires one ip subnet argument")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		var conf *scanConfig
		if conf, err = parseScanConfig(tcp.SYNScanType, args[0], portsFlag); err != nil {
			return
		}

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()

		m := newTCPScanMethod(ctx, conf,
			withTCPScanName(tcp.SYNScanType),
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
			bpfFilter:  tcp.BPFFilter,
		})
	},
}

type tcpScanConfig struct {
	scanName     string
	packetFiller scan.PacketFiller
	packetFilter tcp.PacketFilterFunc
	packetFlags  tcp.PacketFlagsFunc
}

type tcpScanConfigOption func(c *tcpScanConfig)

func withTCPScanName(scanName string) tcpScanConfigOption {
	return func(c *tcpScanConfig) {
		c.scanName = scanName
	}
}

func withTCPPacketFiller(filler scan.PacketFiller) tcpScanConfigOption {
	return func(c *tcpScanConfig) {
		c.packetFiller = filler
	}
}

func withTCPPacketFilterFunc(filter tcp.PacketFilterFunc) tcpScanConfigOption {
	return func(c *tcpScanConfig) {
		c.packetFilter = filter
	}
}

func withTCPPacketFlags(packetFlags tcp.PacketFlagsFunc) tcpScanConfigOption {
	return func(c *tcpScanConfig) {
		c.packetFlags = packetFlags
	}
}

func newTCPScanMethod(ctx context.Context, conf *scanConfig, opts ...tcpScanConfigOption) *tcp.ScanMethod {
	c := &tcpScanConfig{}
	for _, o := range opts {
		o(c)
	}
	reqgen := arp.NewCacheRequestGenerator(
		scan.RequestGeneratorFunc(scan.Requests), conf.gatewayIP, conf.cache)
	pktgen := scan.NewPacketMultiGenerator(c.packetFiller, runtime.NumCPU())
	psrc := scan.NewPacketSource(reqgen, pktgen)
	results := scan.NewResultChan(ctx, 1000)
	return tcp.NewScanMethod(
		c.scanName, psrc, results,
		tcp.WithPacketFilterFunc(c.packetFilter),
		tcp.WithPacketFlagsFunc(tcp.EmptyFlags))
}
