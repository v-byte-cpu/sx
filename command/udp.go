package command

import (
	"context"
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

func newUDPCmd() *udpCmd {
	c := &udpCmd{}

	cmd := &cobra.Command{
		Use: "udp [flags] subnet",
		Example: strings.Join([]string{
			"udp -p 22 192.168.0.1/24",
			"udp -p 22-4567 10.0.0.1",
			"udp --ttl 37 -p 53 192.168.0.1/24",
			"udp --ipproto 157 -p 53 192.168.0.1/24",
			`udp --payload '\x01\x02\x03' -p 53 192.168.0.1/24`}, "\n"),
		Short: "Perform UDP scan",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			if err = c.opts.parseRawOptions(); err != nil {
				return
			}
			var conf *scanConfig
			if conf, err = c.opts.parseScanConfig(udp.ScanType, args); err != nil {
				return
			}

			m := c.opts.newUDPScanMethod(ctx, conf)

			return startPacketScanEngine(ctx, newPacketScanConfig(
				withPacketScanMethod(m),
				withPacketBPFFilter(icmp.BPFFilter),
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

type udpCmd struct {
	cmd  *cobra.Command
	opts udpCmdOpts
}

type udpCmdOpts struct {
	ipPortScanCmdOpts
	ipTTL      uint8
	ipFlags    uint8
	ipProtocol uint8
	ipTotalLen uint16

	udpPayload []byte

	rawIPFlags    string
	rawUDPPayload string
}

// TODO test
func (o *udpCmdOpts) initCliFlags(cmd *cobra.Command) {
	o.ipPortScanCmdOpts.initCliFlags(cmd)
	cmd.Flags().Uint8Var(&o.ipTTL, "ttl", 64, "set IP TTL field of generated packet")
	cmd.Flags().Uint8Var(&o.ipProtocol, "ipproto", 17,
		strings.Join([]string{"set IP Protocol field of generated packet", "UDP by default"}, "\n"))
	cmd.Flags().StringVar(&o.rawIPFlags, "ipflags", "DF", "set IP Flags field of generated packet")
	cmd.Flags().Uint16Var(&o.ipTotalLen, "iplen", 0,
		strings.Join([]string{"set IP Total Length field of generated packet", "calculated by default"}, "\n"))

	cmd.Flags().StringVar(&o.rawUDPPayload, "payload", "",
		strings.Join([]string{"set byte payload of generated packet", "0 bytes by default"}, "\n"))
}

// TODO test
func (o *udpCmdOpts) parseRawOptions() (err error) {
	if err = o.ipPortScanCmdOpts.parseRawOptions(); err != nil {
		return
	}
	if len(o.rawIPFlags) > 0 {
		if o.ipFlags, err = parseIPFlags(o.rawIPFlags); err != nil {
			return
		}
	}
	if len(o.rawUDPPayload) > 0 {
		if o.udpPayload, err = parsePacketPayload(o.rawUDPPayload); err != nil {
			return
		}
	}
	return
}

func (o *udpCmdOpts) newUDPScanMethod(ctx context.Context, conf *scanConfig) *udp.ScanMethod {
	reqgen := arp.NewCacheRequestGenerator(o.newIPPortGenerator(), conf.gatewayMAC, conf.cache)
	pktgen := scan.NewPacketMultiGenerator(udp.NewPacketFiller(o.getUDPOptions()...), runtime.NumCPU())
	psrc := scan.NewPacketSource(reqgen, pktgen)
	results := scan.NewResultChan(ctx, 1000)
	return udp.NewScanMethod(psrc, results)
}

func (o *udpCmdOpts) getUDPOptions() (opts []udp.PacketFillerOption) {
	opts = append(opts,
		udp.WithTTL(o.ipTTL),
		udp.WithIPProtocol(o.ipProtocol),
		udp.WithIPFlags(o.ipFlags),
		udp.WithIPTotalLength(o.ipTotalLen))

	if len(o.udpPayload) > 0 {
		opts = append(opts, udp.WithPayload(o.udpPayload))
	}
	return
}
