package neighbor

import (
	"encoding/json"
	"fmt"
	"strings"
)

type ScanResult struct {
	IP     string `json:"ip"`
	MAC    string `json:"mac"`
	Vendor string `json:"vendor"`
}

func (r *ScanResult) String() string {
	width := 20
	if strings.ContainsRune(r.IP, ':') {
		width = 40
	}
	return fmt.Sprintf("%-*s %-20s %s", width, r.IP, r.MAC, r.Vendor)
}

func (r *ScanResult) ID() string {
	return r.IP
}

func (r *ScanResult) MarshalJSON() ([]byte, error) {
	type result ScanResult
	return json.Marshal((*result)(r))
}
