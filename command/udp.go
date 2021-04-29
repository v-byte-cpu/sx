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

var (
	cliUDPPayloadFlag string

	cliUDPPayload []byte
)

func init() {
	addPacketScanOptions(udpCmd)
	udpCmd.Flags().StringVarP(&cliIPPortFileFlag, "file", "f", "", "set JSONL file with ip/port pairs to scan")
	udpCmd.Flags().StringVar(&cliIPTTLFlag, "ttl", "",
		strings.Join([]string{"set IP TTL field of generated packet", "64 by default"}, "\n"))
	udpCmd.Flags().StringVar(&cliIPTotalLenFlag, "iplen", "",
		strings.Join([]string{"set IP Total Length field of generated packet", "calculated by default"}, "\n"))
	udpCmd.Flags().StringVar(&cliIPProtocolFlag, "ipproto", "",
		strings.Join([]string{"set IP Protocol field of generated packet", "17 (UDP) by default"}, "\n"))
	udpCmd.Flags().StringVar(&cliIPFlagsFlag, "ipflags", "",
		strings.Join([]string{"set IP Flags field of generated packet", "DF by default"}, "\n"))

	udpCmd.Flags().StringVarP(&cliPortsFlag, "ports", "p", "", "set ports to scan")
	udpCmd.Flags().StringVar(&cliUDPPayloadFlag, "payload", "",
		strings.Join([]string{"set byte payload of generated packet", "0 bytes by default"}, "\n"))

	udpCmd.Flags().StringVarP(&cliARPCacheFileFlag, "arp-cache", "a", "",
		strings.Join([]string{"set ARP cache file", "reads from stdin by default"}, "\n"))
	rootCmd.AddCommand(udpCmd)
}

var udpCmd = &cobra.Command{
	Use: "udp [flags] subnet",
	Example: strings.Join([]string{
		"udp -p 22 192.168.0.1/24",
		"udp -p 22-4567 10.0.0.1",
		"udp --ttl 37 -p 53 192.168.0.1/24",
		"udp --ipproto 157 -p 53 192.168.0.1/24",
		`udp --payload '\x01\x02\x03' -p 53 192.168.0.1/24`}, "\n"),
	Short: "Perform UDP scan",
	PreRunE: func(cmd *cobra.Command, args []string) (err error) {
		if cliDstSubnet, err = parseDstSubnet(args); err != nil {
			return
		}
		if err = validatePacketScanStdin(); err != nil {
			return
		}
		if len(cliUDPPayloadFlag) > 0 {
			cliUDPPayload, err = parsePacketPayload(cliUDPPayloadFlag)
		}
		return
	},
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()

		var conf *scanConfig
		if conf, err = parseScanConfig(udp.ScanType, cliDstSubnet); err != nil {
			return
		}

		m := newUDPScanMethod(ctx, conf)

		return startPacketScanEngine(ctx, newPacketScanConfig(
			withPacketScanMethod(m),
			withPacketBPFFilter(icmp.BPFFilter),
			withPacketEngineConfig(newEngineConfig(
				withLogger(conf.logger),
				withScanRange(conf.scanRange),
			)),
		))
	},
}

func newUDPScanMethod(ctx context.Context, conf *scanConfig) *udp.ScanMethod {
	reqgen := arp.NewCacheRequestGenerator(newIPPortGenerator(), conf.gatewayMAC, conf.cache)
	pktgen := scan.NewPacketMultiGenerator(udp.NewPacketFiller(getUDPOptions()...), runtime.NumCPU())
	psrc := scan.NewPacketSource(reqgen, pktgen)
	results := scan.NewResultChan(ctx, 1000)
	return udp.NewScanMethod(psrc, results)
}

func getUDPOptions() (opts []udp.PacketFillerOption) {
	if len(cliIPTTLFlag) > 0 {
		opts = append(opts, udp.WithTTL(cliTTL))
	}
	if len(cliIPTotalLenFlag) > 0 {
		opts = append(opts, udp.WithIPTotalLength(cliIPTotalLen))
	}
	if len(cliIPProtocolFlag) > 0 {
		opts = append(opts, udp.WithIPProtocol(cliIPProtocol))
	}
	if len(cliIPFlagsFlag) > 0 {
		opts = append(opts, udp.WithIPFlags(cliIPFlags))
	}
	if len(cliUDPPayloadFlag) > 0 {
		opts = append(opts, udp.WithPayload(cliUDPPayload))
	}
	return
}
