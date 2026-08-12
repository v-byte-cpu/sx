package command

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/v-byte-cpu/sx/command/log"
	"github.com/v-byte-cpu/sx/pkg/ip"
	"github.com/v-byte-cpu/sx/pkg/scan"
	"github.com/v-byte-cpu/sx/pkg/scan/icmp"
)

const defaultICMPDiscoveryGroup = "ff02::1"

var (
	errICMPDiscoveryGroup             = errors.New("group must be a single IPv6 link-local multicast address")
	errICMPDiscoveryInterfaceRequired = errors.New("--iface is required")
)

type icmpDiscoverCmd struct {
	cmd  *cobra.Command
	opts icmpDiscoverCmdOpts
}

func newICMPDiscoverCmd() *icmpDiscoverCmd {
	c := &icmpDiscoverCmd{}
	c.cmd = &cobra.Command{
		Use: "discover [group]",
		Example: strings.Join([]string{
			"icmp discover --iface en0",
			"icmp discover --iface en0 --srcip fe80::1234",
			"icmp discover --iface en0 ff02::1%en0",
			"icmp discover --iface en0 --json",
		}, "\n"),
		Short: "Discover IPv6 neighbors with one multicast echo request",
		Long: "Best-effort IPv6 neighbor discovery using one ICMPv6 Echo Request to a link-local multicast group. " +
			"Hosts may ignore multicast echo requests, so an empty result does not prove that the link has no hosts.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error { return c.run(args) },
	}
	c.cmd.Flags().BoolVar(&c.opts.json, "json", false, "enable JSON output")
	c.cmd.Flags().StringVarP(&c.opts.rawInterface, "iface", "i", "", "set interface to send/receive packets")
	c.cmd.Flags().StringVar(&c.opts.rawSrcIP, "srcip", "", "set source IP address for generated packets")
	c.cmd.Flags().DurationVar(&c.opts.exitDelay, "exit-delay", time.Second,
		"set how long to wait for response packets after sending the request")
	return c
}

func (c *icmpDiscoverCmd) run(args []string) error {
	if c.opts.rawInterface == "" {
		return errICMPDiscoveryInterfaceRequired
	}
	group := ""
	if len(args) == 1 {
		group = args[0]
	}
	dstPrefix, dstZone, err := parseICMPDiscoveryGroup(group)
	if err != nil {
		return err
	}
	if err = validateICMPDiscoveryZone(dstZone, c.opts.rawInterface); err != nil {
		return err
	}
	if err = c.opts.parseRawOptions(); err != nil {
		return err
	}
	if c.opts.scanRange, err = c.opts.getScanRangeForFamily(dstPrefix, dstZone, true); err != nil {
		return err
	}
	if err = validateICMPDiscoverySourceIP(c.opts.scanRange.SrcIP); err != nil {
		return err
	}
	if !validICMPDiscoverySourceMAC(c.opts.scanRange.SrcMAC) {
		return errSrcMAC
	}
	probe, err := icmp.NewDiscoveryProbe()
	if err != nil {
		return fmt.Errorf("create ICMPv6 discovery probe: %w", err)
	}
	logger, err := c.opts.getLogger()
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	method := c.opts.newScanMethod(ctx, probe)
	return startPacketScanEngine(ctx, newPacketScanConfig(
		withPacketScanMethod(method),
		withPacketBPFFilter(icmp.DiscoveryBPFFilter),
		withPacketEngineConfig(newEngineConfig(
			withLogger(logger),
			withScanRange(c.opts.scanRange),
			withExitDelay(c.opts.exitDelay),
		)),
	))
}

type icmpDiscoverCmdOpts struct {
	packetScanCmdOpts
	scanRange *scan.Range
}

func (o *icmpDiscoverCmdOpts) getLogger() (log.Logger, error) {
	logger, err := o.packetScanCmdOpts.getLogger(icmp.DiscoveryScanType, os.Stdout)
	if err != nil {
		return nil, err
	}
	return log.NewUniqueLogger(logger), nil
}

func (o *icmpDiscoverCmdOpts) newScanMethod(ctx context.Context, probe icmp.DiscoveryProbe) *icmp.DiscoveryScanMethod {
	requests := scan.NewIPRequestGenerator(scan.NewIPGenerator())
	packets := scan.NewPacketGenerator(icmp.NewDiscoveryPacketFiller(probe))
	source := scan.NewPacketSource(requests, packets)
	return icmp.NewDiscoveryScanMethod(
		source,
		scan.NewResultChan(ctx, 1000),
		probe,
		o.scanRange.SrcIP,
		o.scanRange.Interface.Name,
	)
}

func parseICMPDiscoveryGroup(raw string) (netip.Prefix, string, error) {
	if raw == "" {
		raw = defaultICMPDiscoveryGroup
	}
	if strings.Contains(raw, "/") {
		return netip.Prefix{}, "", errICMPDiscoveryGroup
	}
	prefix, zone, err := ip.ParsePrefix(raw)
	if err != nil || prefix.Bits() != 128 || !prefix.Addr().IsLinkLocalMulticast() {
		if err != nil {
			return netip.Prefix{}, "", fmt.Errorf("%w: %v", errICMPDiscoveryGroup, err)
		}
		return netip.Prefix{}, "", errICMPDiscoveryGroup
	}
	return prefix, zone, nil
}

func validateICMPDiscoveryZone(zone, interfaceName string) error {
	if zone != "" && zone != interfaceName {
		return errSrcInterface
	}
	return nil
}

func validateICMPDiscoverySourceIP(source netip.Addr) error {
	if !source.Is6() || !source.IsLinkLocalUnicast() {
		return errSrcIP
	}
	return nil
}

func validICMPDiscoverySourceMAC(mac net.HardwareAddr) bool {
	if len(mac) != 6 || mac[0]&1 != 0 {
		return false
	}
	for _, b := range mac {
		if b != 0 {
			return true
		}
	}
	return false
}
