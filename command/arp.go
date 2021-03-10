package command

import (
	"context"
	"errors"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/v-byte-cpu/sx/command/log"
	"github.com/v-byte-cpu/sx/pkg/ip"
	"github.com/v-byte-cpu/sx/pkg/packet/afpacket"
	"github.com/v-byte-cpu/sx/pkg/scan"
	"github.com/v-byte-cpu/sx/pkg/scan/arp"
)

var errSrcIP = errors.New("invalid source IP")

var interfaceFlag string
var srcIPFlag string
var srcMACFlag string

func init() {
	arpCmd.Flags().StringVarP(&interfaceFlag, "iface", "i", "", "set interface to send/receive packets")
	arpCmd.Flags().StringVar(&srcIPFlag, "srcip", "", "set source IP address for generated packets")
	arpCmd.Flags().StringVar(&srcMACFlag, "srcmac", "", "set source MAC address for generated packets")
	rootCmd.AddCommand(arpCmd)
}

var arpCmd = &cobra.Command{
	Use:     "arp [flags] subnet",
	Example: strings.Join([]string{"arp 192.168.0.1/24", "arp 10.0.0.1"}, "\n"),
	Short:   "Perform ARP scan",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return errors.New("requires one ip subnet argument")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		dstSubnet, err := ip.ParseIPNet(args[0])
		if err != nil {
			return err
		}

		var iface *net.Interface
		var srcIP net.IP

		if len(interfaceFlag) > 0 {
			if iface, err = net.InterfaceByName(interfaceFlag); err != nil {
				return err
			}
			if srcIP, err = ip.GetSubnetInterfaceIP(iface, dstSubnet); err != nil {
				return err
			}
		} else {
			if iface, srcIP, err = ip.GetSubnetInterface(dstSubnet); err != nil {
				return err
			}
		}

		if len(srcIPFlag) > 0 {
			if srcIP = net.ParseIP(srcIPFlag); srcIP == nil {
				return errSrcIP
			}
		}

		srcMAC := iface.HardwareAddr
		if len(srcMACFlag) > 0 {
			if srcMAC, err = net.ParseMAC(srcMACFlag); err != nil {
				return err
			}
		}

		var logger log.Logger
		if jsonFlag {
			logger, err = log.NewJSONLogger(os.Stdout, "arp")
		} else {
			logger, err = log.NewPlainLogger(os.Stdout, "arp")
		}
		if err != nil {
			return err
		}

		r := &scan.Range{Subnet: dstSubnet, Interface: iface, SrcIP: srcIP.To4(), SrcMAC: srcMAC}
		return startEngine(logger, r)
	},
}

func startEngine(logger log.Logger, r *scan.Range) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// setup network interface to read/write packets
	rw, err := afpacket.NewPacketSource(r.Interface.Name)
	if err != nil {
		return err
	}
	defer rw.Close()
	err = rw.SetBPFFilter(arp.BPFFilter(r))
	if err != nil {
		return err
	}

	m := arp.NewScanMethod(ctx)

	// setup result logging
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.LogResults(m.Results())
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
