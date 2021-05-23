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
	"github.com/v-byte-cpu/sx/pkg/scan/tcp"
)

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

func newTCPFlagsCmd() *tcpFlagsCmd {
	c := &tcpFlagsCmd{}

	cmd := &cobra.Command{
		Use: "tcp [flags] subnet",
		Example: strings.Join([]string{
			"tcp -p 22 192.168.0.1/24", "tcp -p 22-4567 10.0.0.1",
			"tcp --flags fin,ack -p 22 192.168.0.3"}, "\n"),
		Short: "Perform TCP scan",
		Long:  "Perform TCP scan. TCP SYN scan is used by default unless --flags option is specified",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			if err = c.opts.parseRawOptions(); err != nil {
				return
			}
			if len(c.opts.tcpFlags) == 0 {
				return newTCPSYNCmdOpts(c.opts.tcpCmdOpts).startScan(ctx, args)
			}

			scanName := tcp.FlagsScanType
			var conf *scanConfig
			if conf, err = c.opts.parseScanConfig(scanName, args); err != nil {
				return
			}

			var opts []tcp.PacketFillerOption
			for _, flag := range c.opts.tcpFlags {
				opts = append(opts, tcpPacketFlagOptions[flag])
			}

			m := c.opts.newTCPScanMethod(ctx, conf,
				withTCPScanName(scanName),
				withTCPPacketFiller(tcp.NewPacketFiller(opts...)),
				withTCPPacketFilterFunc(tcp.TrueFilter),
				withTCPPacketFlags(tcp.AllFlags),
			)

			return startPacketScanEngine(ctx, newPacketScanConfig(
				withPacketScanMethod(m),
				withPacketBPFFilter(tcp.BPFFilter),
				withRateCount(c.opts.rateCount),
				withRateWindow(c.opts.rateWindow),
				withPacketEngineConfig(newEngineConfig(
					withLogger(conf.logger),
					withScanRange(conf.scanRange),
					withExitDelay(c.opts.exitDelay),
				)),
			))
		},
	}

	c.opts.initCliFlags(cmd)

	c.cmd = cmd
	return c
}

type tcpFlagsCmd struct {
	cmd  *cobra.Command
	opts tcpFlagsCmdOpts
}

type tcpFlagsCmdOpts struct {
	tcpCmdOpts
	tcpFlags []string

	rawTCPFlags string
}

// TODO test
func (o *tcpFlagsCmdOpts) initCliFlags(cmd *cobra.Command) {
	o.ipPortScanCmdOpts.initCliFlags(cmd)
	cmd.Flags().StringVar(&o.rawTCPFlags, "flags", "", "set TCP flags")
}

// TODO test
func (o *tcpFlagsCmdOpts) parseRawOptions() (err error) {
	if err = o.ipPortScanCmdOpts.parseRawOptions(); err != nil {
		return
	}
	o.tcpFlags, err = parseTCPFlags(o.rawTCPFlags)
	return
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

// TODO lowercase test
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

type tcpCmdOpts struct {
	ipPortScanCmdOpts
}

func (o *tcpCmdOpts) newTCPScanMethod(ctx context.Context, conf *scanConfig, opts ...tcpScanConfigOption) *tcp.ScanMethod {
	c := &tcpScanConfig{}
	for _, opt := range opts {
		opt(c)
	}
	reqgen := arp.NewCacheRequestGenerator(o.newIPPortGenerator(), conf.gatewayMAC, conf.cache)
	pktgen := scan.NewPacketMultiGenerator(c.packetFiller, runtime.NumCPU())
	psrc := scan.NewPacketSource(reqgen, pktgen)
	results := scan.NewResultChan(ctx, 1000)
	return tcp.NewScanMethod(
		c.scanName, psrc, results,
		tcp.WithPacketFilterFunc(c.packetFilter),
		tcp.WithPacketFlagsFunc(c.packetFlags))
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
