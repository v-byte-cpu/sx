package command

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket/routing"
	"github.com/spf13/cobra"
	"github.com/v-byte-cpu/sx/command/log"
	"github.com/v-byte-cpu/sx/pkg/ip"
	"github.com/v-byte-cpu/sx/pkg/packet/afpacket"
	"github.com/v-byte-cpu/sx/pkg/scan"
)

var rootCmd = &cobra.Command{
	Use:     "sx",
	Short:   "Fast, modern, easy-to-use network scanner",
	Version: "0.1.0",
}

var (
	jsonFlag      bool
	interfaceFlag string
	srcIPFlag     string
	srcMACFlag    string
)

var (
	errSrcIP        = errors.New("invalid source IP")
	errSrcMAC       = errors.New("invalid source MAC")
	errSrcInterface = errors.New("invalid source interface")
)

func init() {
	rootCmd.PersistentFlags().BoolVar(&jsonFlag, "json", false, "enable JSON output")
	rootCmd.PersistentFlags().StringVarP(&interfaceFlag, "iface", "i", "", "set interface to send/receive packets")
	rootCmd.PersistentFlags().StringVar(&srcIPFlag, "srcip", "", "set source IP address for generated packets")
	rootCmd.PersistentFlags().StringVar(&srcMACFlag, "srcmac", "", "set source MAC address for generated packets")
}

func Main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func parseScanRange(subnet string) (*scan.Range, error) {
	dstSubnet, err := ip.ParseIPNet(subnet)
	if err != nil {
		return nil, err
	}
	iface, srcSubnet, err := getSubnetInterface(dstSubnet)
	if err != nil {
		return nil, err
	}
	if iface == nil || srcSubnet == nil {
		return nil, errSrcInterface
	}

	srcIP := srcSubnet.IP
	if len(srcIPFlag) > 0 {
		if srcIP = net.ParseIP(srcIPFlag); srcIP == nil {
			return nil, errSrcIP
		}
	}
	if srcIP == nil {
		return nil, errSrcIP
	}

	srcMAC := iface.HardwareAddr
	if len(srcMACFlag) > 0 {
		if srcMAC, err = net.ParseMAC(srcMACFlag); err != nil {
			return nil, err
		}
	}
	if srcMAC == nil {
		return nil, errSrcMAC
	}

	return &scan.Range{
		Interface: iface,
		DstSubnet: dstSubnet,
		SrcSubnet: srcSubnet,
		SrcIP:     srcIP.To4(),
		SrcMAC:    srcMAC}, nil
}

func getSubnetInterface(dstSubnet *net.IPNet) (iface *net.Interface, srcSubnet *net.IPNet, err error) {
	if len(interfaceFlag) == 0 {
		return ip.GetSubnetInterface(dstSubnet)
	}
	if iface, err = net.InterfaceByName(interfaceFlag); err != nil {
		return
	}
	if srcSubnet, err = ip.GetSubnetInterfaceIP(iface, dstSubnet); err != nil {
		return
	}
	return iface, srcSubnet, nil
}

func getLogger(name string, w io.Writer) (logger log.Logger, err error) {
	opts := []log.LoggerOption{log.FlushInterval(1 * time.Second)}
	if jsonFlag {
		opts = append(opts, log.JSON())
	}
	logger, err = log.NewLogger(w, name, opts...)
	return
}

func getGatewayIP(r *scan.Range) (gatewayIP net.IP, err error) {
	var router routing.Router
	if router, err = routing.New(); err != nil {
		return
	}
	if _, gatewayIP, _, err = router.RouteWithSrc(
		r.Interface.HardwareAddr, r.SrcIP, r.DstSubnet.IP); err != nil {
		return
	}
	// if local address then don't need gateway
	if gatewayIP == nil || r.DstSubnet.Contains(gatewayIP) {
		return nil, nil
	}
	gatewayIP = gatewayIP.To4()
	return
}

type engineConfig struct {
	logger     log.Logger
	scanRange  *scan.Range
	scanMethod resultScanMethod
	bpfFilter  func(r *scan.Range) (filter string, maxPacketLength int)
}

type resultScanMethod interface {
	scan.Method
	Results() <-chan scan.Result
}

func startEngine(ctx context.Context, conf *engineConfig) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	r := conf.scanRange
	m := conf.scanMethod
	logger := conf.logger

	// setup network interface to read/write packets
	rw, err := afpacket.NewPacketSource(r.Interface.Name)
	if err != nil {
		return err
	}
	defer rw.Close()
	err = rw.SetBPFFilter(conf.bpfFilter(r))
	if err != nil {
		return err
	}

	// setup result logging
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.LogResults(ctx, m.Results())
	}()

	// start scan
	engine := scan.SetupEngine(rw, m)
	done, errc := engine.Start(ctx, r)
	go func() {
		defer cancel()
		<-done
		<-time.After(300 * time.Millisecond)
	}()

	// error logging
	wg.Add(1)
	go func() {
		defer wg.Done()
		for err := range errc {
			logger.Error(err)
		}
	}()
	wg.Wait()
	return nil
}
