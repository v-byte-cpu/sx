package command

import (
	"context"
	"errors"
	golog "log"
	"os"
	"os/signal"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	"github.com/v-byte-cpu/sx/pkg/scan"
	"github.com/v-byte-cpu/sx/pkg/scan/arp"
	"github.com/v-byte-cpu/sx/pkg/scan/tcp"
)

var cliTCPPacketFlags string

const (
	cliTCPSYNPacketFlag = "syn"
	cliTCPACKPacketFlag = "ack"
	cliTCPFINPacketFlag = "fin"
	cliTCPRSTPacketFlag = "rst"
	cliTCPPSHPacketFlag = "psh"
	cliTCPURGPacketFlag = "urg"
	cliTCPECEPacketFlag = "ece"
	cliTCPCWRPacketFlag = "cwr"
	cliTCPNSPacketFlag  = "ns"
)

var (
	errTCPflag = errors.New("invalid TCP packet flag")
)

func init() {
	tcpCmd.PersistentFlags().StringVarP(&cliPortsFlag, "ports", "p", "", "set ports to scan")
	if err := tcpCmd.MarkPersistentFlagRequired("ports"); err != nil {
		golog.Fatalln(err)
	}
	tcpCmd.PersistentFlags().StringVarP(&cliARPCacheFileFlag, "arp-cache", "a", "",
		strings.Join([]string{"set ARP cache file", "reads from stdin by default"}, "\n"))
	tcpCmd.Flags().StringVar(&cliTCPPacketFlags, "flags", "", "set TCP flags")
	rootCmd.AddCommand(tcpCmd)
}

var tcpCmd = &cobra.Command{
	Use: "tcp [flags] subnet",
	Example: strings.Join([]string{
		"tcp -p 22 192.168.0.1/24", "tcp -p 22-4567 10.0.0.1",
		"tcp --flags fin,ack -p 22 192.168.0.3"}, "\n"),
	Short: "Perform TCP scan",
	Long:  "Perform TCP scan. TCP SYN scan is used by default unless --flags option is specified",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return errors.New("requires one ip subnet argument")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()

		if len(cliTCPPacketFlags) == 0 {
			return startTCPSYNScan(ctx, args[0])
		}

		var tcpFlags []string
		if tcpFlags, err = parseTCPFlags(cliTCPPacketFlags); err != nil {
			return err
		}

		var opts []tcp.PacketFillerOption
		for _, flag := range tcpFlags {
			opts = append(opts, tcpPacketFlagOptions[flag])
		}

		scanName := tcp.FlagsScanType
		var conf *scanConfig
		if conf, err = parseScanConfig(scanName, args[0]); err != nil {
			return
		}

		m := newTCPScanMethod(ctx, conf,
			withTCPScanName(scanName),
			withTCPPacketFiller(tcp.NewPacketFiller(opts...)),
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

var tcpPacketFlagOptions = map[string]tcp.PacketFillerOption{
	cliTCPSYNPacketFlag: tcp.WithSYN(),
	cliTCPACKPacketFlag: tcp.WithACK(),
	cliTCPFINPacketFlag: tcp.WithFIN(),
	cliTCPRSTPacketFlag: tcp.WithRST(),
	cliTCPPSHPacketFlag: tcp.WithPSH(),
	cliTCPURGPacketFlag: tcp.WithURG(),
	cliTCPECEPacketFlag: tcp.WithECE(),
	cliTCPCWRPacketFlag: tcp.WithCWR(),
	cliTCPNSPacketFlag:  tcp.WithNS(),
}

func parseTCPFlags(tcpFlags string) ([]string, error) {
	if len(tcpFlags) == 0 {
		return []string{}, nil
	}
	flags := strings.Split(tcpFlags, ",")
	for _, flag := range flags {
		if _, ok := tcpPacketFlagOptions[flag]; !ok {
			return nil, errTCPflag
		}
	}
	return flags, nil
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
	portgen := scan.NewPortGenerator()
	ipgen := scan.NewIPGenerator()
	reqgen := arp.NewCacheRequestGenerator(
		scan.NewIPPortGenerator(ipgen, portgen), conf.gatewayIP, conf.cache)
	pktgen := scan.NewPacketMultiGenerator(c.packetFiller, runtime.NumCPU())
	psrc := scan.NewPacketSource(reqgen, pktgen)
	results := scan.NewResultChan(ctx, 1000)
	return tcp.NewScanMethod(
		c.scanName, psrc, results,
		tcp.WithPacketFilterFunc(c.packetFilter),
		tcp.WithPacketFlagsFunc(c.packetFlags))
}
