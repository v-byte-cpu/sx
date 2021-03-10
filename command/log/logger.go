package log

import "github.com/v-byte-cpu/sx/pkg/scan/arp"

type Logger interface {
	Error(err error)
	LogResults(results <-chan *arp.ScanResult)
}
