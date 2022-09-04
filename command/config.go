package command

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/spf13/cobra"
	"github.com/v-byte-cpu/sx/command/log"
	"github.com/v-byte-cpu/sx/pkg/ip"
	"github.com/v-byte-cpu/sx/pkg/scan"
	"github.com/v-byte-cpu/sx/pkg/scan/arp"
	"github.com/yl2chen/cidranger"
	"go.uber.org/ratelimit"
)

const (
	cliHTTPProtoFlag  = "http"
	cliHTTPSProtoFlag = "https"

	defaultWorkerCount = 100
	defaultTimeout     = 5 * time.Second
	defaultExitDelay   = 300 * time.Millisecond
)

var (
	errSrcIP         = errors.New("invalid source IP")
	errSrcMAC        = errors.New("invalid source MAC")
	errSrcInterface  = errors.New("invalid source interface")
	errRateLimit     = errors.New("invalid ratelimit")
	errARPCacheStdin = errors.New("ARP cache is expected from file or stdin pipe")
	errIPFlags       = errors.New("invalid ip flags")
	errNoDstIP       = errors.New("requires one ip subnet argument or file with ip/port pairs")
	errARPStdin      = errors.New("ARP cache and IP file can not be read from stdin at the same time")
)

type packetScanCmdOpts struct {
	json       bool
	iface      *net.Interface
	srcIP      net.IP
	srcMAC     net.HardwareAddr
	rateCount  int
	rateWindow time.Duration
	exitDelay  time.Duration
	excludeIPs scan.IPContainer

	rawInterface   string
	rawSrcMAC      string
	rawRateLimit   string
	rawExcludeFile string
}

func (o *packetScanCmdOpts) initCliFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&o.json, "json", false, "enable JSON output")
	cmd.Flags().StringVarP(&o.rawInterface, "iface", "i", "", "set interface to send/receive packets")
	cmd.Flags().IPVar(&o.srcIP, "srcip", nil, "set source IP address for generated packets")
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

func (o *packetScanCmdOpts) getScanRange(dstSubnet *net.IPNet) (*scan.Range, error) {
	iface, srcIP, err := o.getInterface(dstSubnet)
	if err != nil {
		return nil, err
	}
	if iface == nil {
		return nil, errSrcInterface
	}

	if o.srcIP != nil {
		srcIP = o.srcIP
	}
	if srcIP == nil {
		return nil, errSrcIP
	}

	srcMAC := iface.HardwareAddr
	if o.srcMAC != nil {
		srcMAC = o.srcMAC
	}

	return &scan.Range{
		Interface: iface,
		DstSubnet: dstSubnet,
		SrcIP:     srcIP.To4(),
		SrcMAC:    srcMAC}, nil
}

func (o *packetScanCmdOpts) getInterface(dstSubnet *net.IPNet) (iface *net.Interface, ifaceIP net.IP, err error) {
	if dstSubnet != nil {
		// try to find directly connected interface
		if iface, ifaceIP, err = o.getLocalSubnetInterface(dstSubnet); err != nil {
			return
		}
		// found local interface
		if iface != nil && ifaceIP != nil {
			return
		}
	}
	if o.iface != nil {
		// try to get first ip address
		ifaceIP, err = ip.GetInterfaceIP(o.iface)
		return o.iface, ifaceIP, err
	}
	// fallback to interface of default gateway
	return ip.GetDefaultInterface()
}

func (o *packetScanCmdOpts) getLocalSubnetInterface(dstSubnet *net.IPNet) (iface *net.Interface, ifaceIP net.IP, err error) {
	if o.iface == nil {
		return ip.GetLocalSubnetInterface(dstSubnet)
	}
	ifaceIP, err = ip.GetLocalSubnetInterfaceIP(o.iface, dstSubnet)
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

type ipScanCmdOpts struct {
	packetScanCmdOpts
	ipFile       string
	arpCacheFile string
	gatewayMAC   net.HardwareAddr
	vpnMode      bool

	logger    log.Logger
	scanRange *scan.Range
	cache     *arp.Cache

	rawGatewayMAC string
}

func (o *ipScanCmdOpts) initCliFlags(cmd *cobra.Command) {
	o.packetScanCmdOpts.initCliFlags(cmd)
	cmd.Flags().StringVar(&o.rawGatewayMAC, "gwmac", "", "set gateway MAC address to send generated packets to")
	cmd.Flags().StringVarP(&o.ipFile, "file", "f", "", "set JSONL file with IPs to scan")
	cmd.Flags().StringVarP(&o.arpCacheFile, "arp-cache", "a", "",
		strings.Join([]string{"set ARP cache file", "reads from stdin by default"}, "\n"))
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
	return
}

func (o *ipScanCmdOpts) parseOptions(scanName string, args []string) (err error) {

	dstSubnet, err := o.parseDstSubnet(args)
	if err != nil {
		return
	}
	if o.scanRange, err = o.getScanRange(dstSubnet); err != nil {
		return
	}
	if o.scanRange.SrcMAC == nil {
		o.vpnMode = true
	}

	if o.logger, err = o.getLogger(scanName, os.Stdout); err != nil {
		return
	}

	// disable arp cache parsing for vpn mode
	if o.vpnMode {
		return
	}
	if err = o.validateARPStdin(); err != nil {
		return
	}

	if o.cache, err = o.parseARPCache(); err != nil {
		return
	}

	if o.gatewayMAC, err = o.getGatewayMAC(o.scanRange.Interface, o.cache); err != nil {
		return
	}
	return
}

func (o *ipScanCmdOpts) validateARPStdin() (err error) {
	if o.isARPCacheFromStdin() && o.ipFile == "-" {
		return errARPStdin
	}
	return
}

func (o *ipScanCmdOpts) parseDstSubnet(args []string) (ipnet *net.IPNet, err error) {
	if len(args) == 0 && len(o.ipFile) == 0 {
		return nil, errNoDstIP
	}
	if len(args) == 0 {
		return
	}
	return ip.ParseIPNet(args[0])
}

func (o *ipScanCmdOpts) parseARPCache() (cache *arp.Cache, err error) {
	var r io.ReadCloser
	if r, err = o.openARPCache(); err != nil {
		return
	}
	defer r.Close()
	cache = arp.NewCache()
	err = arp.FillCache(cache, r)
	return
}

func (o *ipScanCmdOpts) openARPCache() (r io.ReadCloser, err error) {
	if !o.isARPCacheFromStdin() {
		return os.Open(o.arpCacheFile)
	}
	// read from stdin
	var info os.FileInfo
	if info, err = os.Stdin.Stat(); err != nil {
		return
	}
	// only data being piped to stdin is valid
	if (info.Mode() & os.ModeCharDevice) != 0 {
		// stdin from terminal is not valid
		return nil, errARPCacheStdin
	}
	r = io.NopCloser(os.Stdin)
	return
}

func (o *ipScanCmdOpts) isARPCacheFromStdin() bool {
	return len(o.arpCacheFile) == 0 || o.arpCacheFile == "-"
}

func (o *ipScanCmdOpts) getGatewayMAC(iface *net.Interface, cache *arp.Cache) (mac net.HardwareAddr, err error) {
	if o.gatewayMAC != nil {
		return o.gatewayMAC, nil
	}
	var gatewayIP net.IP
	if gatewayIP, err = ip.GetDefaultGatewayIP(iface); err != nil {
		return
	}
	mac = cache.Get(gatewayIP.To4())
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
	dstSubnet, err := o.parseDstSubnet(args)
	r = &scan.Range{
		DstSubnet: dstSubnet,
		Ports:     o.portRanges,
	}
	return
}

func (o *genericScanCmdOpts) parseDstSubnet(args []string) (ipnet *net.IPNet, err error) {
	if len(args) == 0 && len(o.ipFile) == 0 {
		return nil, errNoDstIP
	}
	if len(args) == 0 {
		return
	}
	return ip.ParseIPNet(args[0])
}

func (o *genericScanCmdOpts) getLogger(name string, w io.Writer) (logger log.Logger, err error) {
	opts := []log.LoggerOption{log.FlushInterval(1 * time.Second)}
	if o.json {
		opts = append(opts, log.JSON())
	}
	logger, err = log.NewLogger(w, name, opts...)
	return
}

func (o *genericScanCmdOpts) newScanEngine(ctx context.Context, scanner scan.Scanner) *scan.GenericEngine {
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
		var ipnet *net.IPNet
		if ipnet, err = ip.ParseIPNet(line); err != nil {
			return
		}
		if err = ranger.Insert(cidranger.NewBasicRangerEntry(*ipnet)); err != nil {
			return
		}
	}
	excludeIPs = ranger
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
