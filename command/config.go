package command

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/spf13/cobra"
	"github.com/v-byte-cpu/sx/command/log"
	"github.com/v-byte-cpu/sx/pkg/ip"
	"github.com/v-byte-cpu/sx/pkg/scan"
	"github.com/v-byte-cpu/sx/pkg/scan/neighbor"
	"github.com/yl2chen/cidranger"
	"go.uber.org/ratelimit"
)

const (
	defaultWorkerCount = 100
	defaultExitDelay   = 300 * time.Millisecond
	flagHopLimit       = "hop-limit"
	flagNextHeader     = "next-header"
	flagPayloadLength  = "payload-length"
)

var (
	errSrcIP              = errors.New("invalid source IP")
	errSrcMAC             = errors.New("invalid source MAC")
	errSrcInterface       = errors.New("invalid source interface")
	errRateLimit          = errors.New("invalid ratelimit")
	errNeighborCacheStdin = errors.New("neighbor cache is expected from file or stdin pipe")
	errIPFlags            = errors.New("invalid ip flags")
	errNoDstIP            = errors.New("requires one ip subnet argument or file with ip/port pairs")
	errNeighborStdin      = errors.New("neighbor cache and IP file can not be read from stdin at the same time")
)

type packetScanCmdOpts struct {
	json       bool
	iface      *net.Interface
	srcIP      netip.Addr
	srcMAC     net.HardwareAddr
	rateCount  int
	rateWindow time.Duration
	exitDelay  time.Duration
	excludeIPs scan.IPContainer

	rawInterface   string
	rawSrcIP       string
	rawSrcMAC      string
	rawRateLimit   string
	rawExcludeFile string
}

func (o *packetScanCmdOpts) initCliFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&o.json, "json", false, "enable JSON output")
	cmd.Flags().StringVarP(&o.rawInterface, "iface", "i", "", "set interface to send/receive packets")
	cmd.Flags().StringVar(&o.rawSrcIP, "srcip", "", "set source IP address for generated packets")
	cmd.Flags().StringVar(&o.rawSrcMAC, "srcmac", "", "set source MAC address for generated packets")
	cmd.Flags().StringVar(&o.rawExcludeFile, "exclude", "",
		strings.Join([]string{
			"set file with IPs or subnets in CIDR notation to exclude, one-per line.",
			"It is useful to exclude RFC 1918 addresses, multicast, IANA reserved space, and other IANA special-purpose addresses."}, "\n"))
	cmd.Flags().StringVarP(&o.rawRateLimit, "rate", "r", "",
		strings.Join([]string{
			"set rate limit for generated packets",
			`format: "rateCount/rateWindow"`,
			"where rateCount is a number of packets, rateWindow is the time interval",
			"e.g. 1000/s -- 1000 packets per second", "500/7s -- 500 packets per 7 seconds\n"}, "\n"))
	cmd.Flags().DurationVar(&o.exitDelay, "exit-delay", defaultExitDelay,
		strings.Join([]string{
			"set exit delay to wait for last response packets",
			"any expression accepted by time.ParseDuration is valid"}, "\n"))
}

func (o *packetScanCmdOpts) parseRawOptions() (err error) {
	if len(o.rawInterface) > 0 {
		if o.iface, err = net.InterfaceByName(o.rawInterface); err != nil {
			return
		}
	}
	if len(o.rawSrcIP) > 0 {
		if o.srcIP, err = netip.ParseAddr(o.rawSrcIP); err != nil {
			return errSrcIP
		}
		o.srcIP = o.srcIP.Unmap()
	}
	if len(o.rawSrcMAC) > 0 {
		if o.srcMAC, err = net.ParseMAC(o.rawSrcMAC); err != nil {
			return
		}
	}
	if len(o.rawRateLimit) > 0 {
		if o.rateCount, o.rateWindow, err = parseRateLimit(o.rawRateLimit); err != nil {
			return
		}
	}
	if len(o.rawExcludeFile) > 0 {
		if o.excludeIPs, err = parseExcludeFile(func() (io.ReadCloser, error) {
			return os.Open(o.rawExcludeFile)
		}); err != nil {
			return
		}
	}
	return
}

func (o *packetScanCmdOpts) getScanRange(dstPrefix netip.Prefix, dstZone string) (*scan.Range, error) {
	return o.getScanRangeForFamily(dstPrefix, dstZone, dstPrefix.IsValid() && dstPrefix.Addr().Is6())
}

func (o *packetScanCmdOpts) getScanRangeForFamily(dstPrefix netip.Prefix, dstZone string, ipv6 bool) (*scan.Range, error) {
	iface, srcAddr, err := o.getInterface(dstPrefix, dstZone, ipv6)
	if err != nil {
		return nil, err
	}
	if iface == nil {
		return nil, errSrcInterface
	}

	if o.srcIP.IsValid() {
		srcAddr = o.srcIP
	}
	if !srcAddr.IsValid() {
		return nil, errSrcIP
	}
	if dstPrefix.IsValid() && srcAddr.Is4() != dstPrefix.Addr().Is4() {
		return nil, errSrcIP
	}

	srcMAC := iface.HardwareAddr
	if o.srcMAC != nil {
		srcMAC = o.srcMAC
	}

	return &scan.Range{
		Interface: iface,
		DstPrefix: dstPrefix,
		DstZone:   dstZone,
		SrcIP:     srcAddr,
		SrcMAC:    srcMAC}, nil
}

func (o *packetScanCmdOpts) getInterface(dstPrefix netip.Prefix, dstZone string, ipv6 bool) (iface *net.Interface, ifaceIP netip.Addr, err error) {
	if scopedIface, scoped, scopedErr := o.getScopedSourceInterface(dstZone); scoped || scopedErr != nil {
		return scopedIface, o.srcIP, scopedErr
	}
	if dstPrefix.IsValid() {
		// try to find directly connected interface
		if iface, ifaceIP, err = o.getLocalPrefixInterface(dstPrefix, dstZone); err != nil {
			return
		}
		// found local interface
		if iface != nil && ifaceIP.IsValid() {
			return
		}
	}
	target := netip.IPv4Unspecified()
	if ipv6 {
		target = netip.IPv6Unspecified()
	}
	if dstPrefix.IsValid() {
		target = dstPrefix.Addr()
		if dstZone != "" {
			target = target.WithZone(dstZone)
		}
	}
	if o.iface != nil {
		// try to get first ip address
		ifaceIP, err = ip.GetInterfaceIP(o.iface, target)
		return o.iface, ifaceIP, err
	}
	// fallback to interface of default gateway
	return ip.GetDefaultInterface(target)
}

func (o *packetScanCmdOpts) getScopedSourceInterface(dstZone string) (*net.Interface, bool, error) {
	sourceZone := o.srcIP.Zone()
	if sourceZone == "" {
		return nil, false, nil
	}
	if dstZone != "" && dstZone != sourceZone {
		return nil, true, errSrcInterface
	}
	if o.iface != nil {
		if o.iface.Name != sourceZone {
			return nil, true, errSrcInterface
		}
		return o.iface, true, nil
	}
	iface, err := net.InterfaceByName(sourceZone)
	if err != nil {
		return nil, true, err
	}
	o.iface = iface
	return iface, true, nil
}

func (o *packetScanCmdOpts) getLocalPrefixInterface(dstPrefix netip.Prefix, dstZone string) (iface *net.Interface, ifaceIP netip.Addr, err error) {
	if dstZone != "" {
		if o.iface != nil && o.iface.Name != dstZone {
			return nil, netip.Addr{}, errSrcInterface
		}
		if o.iface == nil {
			if o.iface, err = net.InterfaceByName(dstZone); err != nil {
				return nil, netip.Addr{}, err
			}
		}
	}
	if o.iface == nil {
		return ip.GetLocalPrefixInterface(dstPrefix)
	}
	ifaceIP, err = ip.GetLocalPrefixInterfaceIP(o.iface, dstPrefix)
	return o.iface, ifaceIP, err
}

func (o *packetScanCmdOpts) getLogger(name string, w io.Writer) (logger log.Logger, err error) {
	opts := []log.LoggerOption{log.FlushInterval(1 * time.Second)}
	if o.json {
		opts = append(opts, log.JSON())
	}
	logger, err = log.NewLogger(w, name, opts...)
	return
}

func validateIPVersionFlags(cmd *cobra.Command, ipv6 bool, ipv4Flags, ipv6Flags []string) error {
	unsupported := ipv6Flags
	family := "IPv4"
	if ipv6 {
		unsupported = ipv4Flags
		family = "IPv6"
	}
	for _, name := range unsupported {
		if cmd.Flags().Changed(name) {
			return errors.New("--" + name + " is not supported with " + family)
		}
	}
	return nil
}

type ipScanCmdOpts struct {
	packetScanCmdOpts
	ipFile            string
	neighborCacheFile string
	arpCacheFile      string
	gatewayMAC        net.HardwareAddr
	vpnMode           bool
	ipv6              bool

	logger    log.Logger
	scanRange *scan.Range
	cache     *neighbor.Cache

	rawGatewayMAC string
}

func (o *ipScanCmdOpts) initCliFlags(cmd *cobra.Command) {
	o.packetScanCmdOpts.initCliFlags(cmd)
	cmd.Flags().StringVar(&o.rawGatewayMAC, "gwmac", "", "set gateway MAC address to send generated packets to")
	cmd.Flags().StringVarP(&o.ipFile, "file", "f", "", "set JSONL file with IPs to scan")
	cmd.Flags().BoolVar(&o.ipv6, "ipv6", false, "use IPv6 for file-only scans")
	cmd.Flags().StringVarP(&o.neighborCacheFile, "neighbor-cache", "a", "",
		strings.Join([]string{"set neighbor cache file", "reads from stdin by default"}, "\n"))
	cmd.Flags().StringVar(&o.arpCacheFile, "arp-cache", "", "deprecated alias for --neighbor-cache")
	_ = cmd.Flags().MarkDeprecated("arp-cache", "use --neighbor-cache instead")
}

func (o *ipScanCmdOpts) parseRawOptions() (err error) {
	if err = o.packetScanCmdOpts.parseRawOptions(); err != nil {
		return
	}
	if len(o.rawGatewayMAC) > 0 {
		if o.gatewayMAC, err = net.ParseMAC(o.rawGatewayMAC); err != nil {
			return
		}
	}
	if o.neighborCacheFile != "" && o.arpCacheFile != "" {
		return errors.New("neighbor-cache and arp-cache can not be used together")
	}
	return
}

func (o *ipScanCmdOpts) parseOptions(scanName string, args []string) (err error) {

	dstPrefix, dstZone, err := o.parseDstPrefix(args)
	if err != nil {
		return
	}
	ipv6 := o.ipv6
	if dstPrefix.IsValid() {
		ipv6 = dstPrefix.Addr().Is6()
	}
	if o.scanRange, err = o.getScanRangeForFamily(dstPrefix, dstZone, ipv6); err != nil {
		return
	}
	o.ipv6 = o.scanRange.SrcIP.Is6()
	if o.scanRange.SrcMAC == nil {
		o.vpnMode = true
	}

	if o.logger, err = o.getLogger(scanName, os.Stdout); err != nil {
		return
	}

	// VPN interfaces exchange raw IP packets and do not need neighbor MACs.
	if o.vpnMode {
		return
	}
	if err = o.validateNeighborStdin(); err != nil {
		return
	}

	if o.cache, err = o.parseNeighborCache(); err != nil {
		return
	}

	if o.gatewayMAC, err = o.getGatewayMAC(o.scanRange.Interface, o.cache); err != nil {
		return
	}
	return
}

func (o *ipScanCmdOpts) validateNeighborStdin() (err error) {
	if o.isNeighborCacheFromStdin() && o.ipFile == "-" {
		return errNeighborStdin
	}
	return
}

func (o *ipScanCmdOpts) parseDstPrefix(args []string) (netip.Prefix, string, error) {
	if len(args) == 0 && len(o.ipFile) == 0 {
		return netip.Prefix{}, "", errNoDstIP
	}
	if len(args) == 0 {
		return netip.Prefix{}, "", nil
	}
	return ip.ParsePrefix(args[0])
}

func (o *ipScanCmdOpts) parseDstSubnet(args []string) (*net.IPNet, error) {
	prefix, _, err := o.parseDstPrefix(args)
	if err != nil || !prefix.IsValid() {
		return nil, err
	}
	return &net.IPNet{
		IP:   net.IP(prefix.Addr().AsSlice()),
		Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
	}, nil
}

func (o *ipScanCmdOpts) parseNeighborCache() (cache *neighbor.Cache, err error) {
	var r io.ReadCloser
	if r, err = o.openNeighborCache(); err != nil {
		return
	}
	defer r.Close()
	cache = neighbor.NewCache()
	err = neighbor.FillCache(cache, r)
	return
}

func (o *ipScanCmdOpts) openNeighborCache() (r io.ReadCloser, err error) {
	if !o.isNeighborCacheFromStdin() {
		return os.Open(o.cacheFile())
	}
	// read from stdin
	var info os.FileInfo
	if info, err = os.Stdin.Stat(); err != nil {
		return
	}
	// only data being piped to stdin is valid
	if (info.Mode() & os.ModeCharDevice) != 0 {
		// stdin from terminal is not valid
		return nil, errNeighborCacheStdin
	}
	r = io.NopCloser(os.Stdin)
	return
}

func (o *ipScanCmdOpts) isNeighborCacheFromStdin() bool {
	cacheFile := o.cacheFile()
	return len(cacheFile) == 0 || cacheFile == "-"
}

func (o *ipScanCmdOpts) cacheFile() string {
	if o.neighborCacheFile != "" {
		return o.neighborCacheFile
	}
	return o.arpCacheFile
}

func (o *ipScanCmdOpts) getGatewayMAC(iface *net.Interface, cache *neighbor.Cache) (mac net.HardwareAddr, err error) {
	if o.gatewayMAC != nil {
		return o.gatewayMAC, nil
	}
	var gatewayIP netip.Addr
	if gatewayIP, err = ip.GetDefaultGatewayIP(iface, o.scanRange.SrcIP); err != nil {
		return
	}
	if gatewayIP.IsLinkLocalUnicast() {
		gatewayIP = gatewayIP.WithZone(iface.Name)
	}
	mac = cache.Get(gatewayIP)
	return
}

type ipPortScanCmdOpts struct {
	ipScanCmdOpts
	portFile   string
	portRanges []*scan.PortRange

	rawPortRanges string
}

func (o *ipPortScanCmdOpts) initCliFlags(cmd *cobra.Command) {
	o.ipScanCmdOpts.initCliFlags(cmd)
	cmd.Flags().StringVarP(&o.rawPortRanges, "ports", "p", "", "set ports to scan")
	cmd.Flags().StringVar(&o.portFile, "ports-file", "", "set file with ports or port ranges to scan, one-per line")
}

func (o *ipPortScanCmdOpts) parseRawOptions() (err error) {
	if err = o.ipScanCmdOpts.parseRawOptions(); err != nil {
		return
	}
	if len(o.rawPortRanges) > 0 {
		if o.portRanges, err = parsePortRanges(o.rawPortRanges); err != nil {
			return
		}
	}
	if len(o.portFile) > 0 {
		portRanges, err := parsePortsFile(func() (io.ReadCloser, error) {
			return os.Open(o.portFile)
		})
		if err != nil {
			return err
		}
		o.portRanges = append(o.portRanges, portRanges...)
	}
	return
}

func (o *ipPortScanCmdOpts) parseOptions(scanName string, args []string) (err error) {
	if err = o.ipScanCmdOpts.parseOptions(scanName, args); err != nil {
		return
	}
	o.scanRange.Ports = o.portRanges
	return
}

func (o *ipPortScanCmdOpts) newIPPortGenerator() (reqgen scan.RequestGenerator) {
	defer func() {
		if o.excludeIPs != nil {
			reqgen = scan.NewFilterIPRequestGenerator(reqgen, o.excludeIPs)
		}
	}()
	if len(o.ipFile) == 0 {
		return scan.NewIPPortGenerator(scan.NewIPGenerator(), scan.NewPortGenerator())
	}
	if len(o.portRanges) == 0 {
		return scan.NewFileIPPortGenerator(func() (io.ReadCloser, error) {
			return os.Open(o.ipFile)
		})
	}
	ipgen := scan.NewFileIPGenerator(func() (io.ReadCloser, error) {
		if o.ipFile == "-" {
			return io.NopCloser(os.Stdin), nil
		}
		return os.Open(o.ipFile)
	})
	return scan.NewIPPortGenerator(ipgen, scan.NewPortGenerator())
}

type genericScanCmdOpts struct {
	json       bool
	ipFile     string
	portFile   string
	portRanges []*scan.PortRange
	workers    int
	rateCount  int
	rateWindow time.Duration
	exitDelay  time.Duration
	excludeIPs scan.IPContainer

	rawPortRanges  string
	rawRateLimit   string
	rawExcludeFile string
}

func (o *genericScanCmdOpts) initCliFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&o.json, "json", false, "enable JSON output")
	cmd.Flags().StringVarP(&o.rawPortRanges, "ports", "p", "", "set ports to scan")
	cmd.Flags().StringVar(&o.portFile, "ports-file", "", "set file with ports or port ranges to scan, one-per line")
	cmd.Flags().StringVarP(&o.ipFile, "file", "f", "", "set JSONL file with ip/port pairs to scan")
	cmd.Flags().IntVarP(&o.workers, "workers", "w", defaultWorkerCount, "set workers count")
	cmd.Flags().StringVar(&o.rawExcludeFile, "exclude", "",
		strings.Join([]string{
			"set file with IPs or subnets in CIDR notation to exclude, one-per line.",
			"It is useful to exclude RFC 1918 addresses, multicast, IANA reserved space, and other IANA special-purpose addresses."}, "\n"))
	cmd.Flags().StringVarP(&o.rawRateLimit, "rate", "r", "",
		strings.Join([]string{
			"set rate limit for generated scan requests",
			`format: "rateCount/rateWindow"`,
			"where rateCount is a number of scan requests, rateWindow is the time interval",
			"e.g. 1000/s -- 1000 requests per second", "500/7s -- 500 requests per 7 seconds\n"}, "\n"))
	cmd.Flags().DurationVar(&o.exitDelay, "exit-delay", defaultExitDelay,
		strings.Join([]string{
			"set exit delay to wait for last response",
			"any expression accepted by time.ParseDuration is valid"}, "\n"))
}

func (o *genericScanCmdOpts) parseRawOptions() (err error) {
	if len(o.rawPortRanges) > 0 {
		if o.portRanges, err = parsePortRanges(o.rawPortRanges); err != nil {
			return
		}
	}
	if len(o.portFile) > 0 {
		portRanges, err := parsePortsFile(func() (io.ReadCloser, error) {
			return os.Open(o.portFile)
		})
		if err != nil {
			return err
		}
		o.portRanges = append(o.portRanges, portRanges...)
	}
	// TODO parsePortsFile
	if len(o.rawRateLimit) > 0 {
		if o.rateCount, o.rateWindow, err = parseRateLimit(o.rawRateLimit); err != nil {
			return
		}
	}
	if len(o.rawExcludeFile) > 0 {
		if o.excludeIPs, err = parseExcludeFile(func() (io.ReadCloser, error) {
			return os.Open(o.rawExcludeFile)
		}); err != nil {
			return
		}
	}
	if o.workers <= 0 {
		return errors.New("invalid workers count")
	}
	return
}

func (o *genericScanCmdOpts) parseScanRange(args []string) (r *scan.Range, err error) {
	dstPrefix, dstZone, err := o.parseDstPrefix(args)
	r = &scan.Range{
		DstPrefix: dstPrefix,
		DstZone:   dstZone,
		Ports:     o.portRanges,
	}
	return
}

func (o *genericScanCmdOpts) parseDstPrefix(args []string) (netip.Prefix, string, error) {
	if len(args) == 0 && len(o.ipFile) == 0 {
		return netip.Prefix{}, "", errNoDstIP
	}
	if len(args) == 0 {
		return netip.Prefix{}, "", nil
	}
	return ip.ParsePrefix(args[0])
}

func (o *genericScanCmdOpts) getLogger(name string, w io.Writer) (logger log.Logger, err error) {
	opts := []log.LoggerOption{log.FlushInterval(1 * time.Second)}
	if o.json {
		opts = append(opts, log.JSON())
	}
	logger, err = log.NewLogger(w, name, opts...)
	return
}

func (o *genericScanCmdOpts) newScanEngine(ctx context.Context, scanner scan.Scanner) *scan.ScanEngine {
	if o.rateCount > 0 {
		scanner = scan.NewRateLimitScanner(scanner,
			ratelimit.New(o.rateCount, ratelimit.Per(o.rateWindow)))
	}
	results := scan.NewResultChan(ctx, 1000)
	return scan.NewScanEngine(o.newIPPortGenerator(), scanner, results, scan.WithScanWorkerCount(o.workers))
}

func (o *genericScanCmdOpts) newIPPortGenerator() (reqgen scan.RequestGenerator) {
	defer func() {
		if o.excludeIPs != nil {
			reqgen = scan.NewFilterIPRequestGenerator(reqgen, o.excludeIPs)
		}
	}()
	if len(o.ipFile) == 0 {
		return scan.NewIPPortGenerator(scan.NewIPGenerator(), scan.NewPortGenerator())
	}
	if len(o.portRanges) == 0 {
		return scan.NewFileIPPortGenerator(func() (io.ReadCloser, error) {
			return os.Open(o.ipFile)
		})
	}
	ipgen := scan.NewFileIPGenerator(func() (io.ReadCloser, error) {
		if o.ipFile == "-" {
			return io.NopCloser(os.Stdin), nil
		}
		return os.Open(o.ipFile)
	})
	return scan.NewIPPortGenerator(ipgen, scan.NewPortGenerator())
}

func parsePortRange(portsRange string) (r *scan.PortRange, err error) {
	ports := strings.Split(portsRange, "-")
	var port uint64
	if port, err = strconv.ParseUint(ports[0], 10, 16); err != nil {
		return
	}
	result := &scan.PortRange{StartPort: uint16(port), EndPort: uint16(port)}
	if len(ports) < 2 {
		return result, nil
	}
	if port, err = strconv.ParseUint(ports[1], 10, 16); err != nil {
		return
	}
	result.EndPort = uint16(port)
	return result, nil
}

func parsePortRanges(portsRanges string) (result []*scan.PortRange, err error) {
	var ports *scan.PortRange
	for _, portsRange := range strings.Split(portsRanges, ",") {
		if ports, err = parsePortRange(portsRange); err != nil {
			return
		}
		result = append(result, ports)
	}
	return
}

func parseRateLimit(rateLimit string) (rateCount int, rateWindow time.Duration, err error) {
	parts := strings.Split(rateLimit, "/")
	if len(parts) > 2 {
		return 0, 0, errRateLimit
	}
	var rate int64
	if rate, err = strconv.ParseInt(parts[0], 10, 32); err != nil || rate < 0 {
		return 0, 0, errRateLimit
	}
	rateCount = int(rate)
	rateWindow = 1 * time.Second
	if len(parts) < 2 {
		return
	}
	win := parts[1]
	if len(win) > 0 && (win[0] < '0' || win[0] > '9') {
		win = "1" + win
	}
	if rateWindow, err = time.ParseDuration(win); err != nil || rateWindow < 0 {
		return 0, 0, errRateLimit
	}
	return
}

func parsePacketPayload(payload string) (result []byte, err error) {
	var unquoted string
	if unquoted, err = strconv.Unquote(`"` + payload + `"`); err != nil {
		return
	}
	return []byte(unquoted), nil
}

func parseIPFlags(inputFlags string) (result uint8, err error) {
	if len(inputFlags) == 0 {
		return
	}
	flags := strings.Split(strings.ToLower(inputFlags), ",")
	for _, flag := range flags {
		switch flag {
		case "df":
			result |= uint8(layers.IPv4DontFragment)
		case "evil":
			result |= uint8(layers.IPv4EvilBit)
		case "mf":
			result |= uint8(layers.IPv4MoreFragments)
		default:
			return 0, errIPFlags
		}
	}
	return
}

type openFileFunc func() (io.ReadCloser, error)

type ipContainer struct {
	ranger cidranger.Ranger
}

func (c *ipContainer) Contains(addr netip.Addr) (bool, error) {
	return c.ranger.Contains(net.IP(addr.WithZone("").AsSlice()))
}

func parseExcludeFile(openFile openFileFunc) (excludeIPs scan.IPContainer, err error) {
	input, err := openFile()
	if err != nil {
		return
	}
	defer input.Close()

	ranger := cidranger.NewPCTrieRanger()
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		line := scanner.Text()
		if comment := strings.Index(line, "#"); comment != -1 {
			line = line[:comment]
		}
		line = strings.Trim(line, " ")
		if len(line) == 0 {
			continue
		}
		prefix, zone, parseErr := ip.ParsePrefix(line)
		if parseErr != nil || zone != "" {
			err = ip.ErrInvalidAddr
			return
		}
		ipnet := net.IPNet{
			IP:   net.IP(prefix.Addr().AsSlice()),
			Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
		}
		if err = ranger.Insert(cidranger.NewBasicRangerEntry(ipnet)); err != nil {
			return
		}
	}
	excludeIPs = &ipContainer{ranger: ranger}
	return
}

func parsePortsFile(openFile openFileFunc) (result []*scan.PortRange, err error) {
	input, err := openFile()
	if err != nil {
		return
	}
	defer input.Close()
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		line := scanner.Text()
		if comment := strings.Index(line, "#"); comment != -1 {
			line = line[:comment]
		}
		line = strings.Trim(line, " ")
		if len(line) == 0 {
			continue
		}
		ports, err := parsePortRange(line)
		if err != nil {
			return nil, err
		}
		result = append(result, ports)
	}
	return
}
