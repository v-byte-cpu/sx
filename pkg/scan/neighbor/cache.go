package neighbor

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"

	"github.com/v-byte-cpu/sx/pkg/scan"
)

type Cache struct {
	cache map[netip.Addr]net.HardwareAddr
	mu    sync.RWMutex
}

func NewCache() *Cache {
	return &Cache{cache: make(map[netip.Addr]net.HardwareAddr)}
}

func (c *Cache) Put(ip netip.Addr, mac net.HardwareAddr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[cacheKey(ip)] = mac
}

func (c *Cache) Get(ip netip.Addr) net.HardwareAddr {
	c.mu.RLock()
	defer c.mu.RUnlock()
	key := cacheKey(ip)
	if mac := c.cache[key]; mac != nil {
		return mac
	}
	if key.Zone() != "" {
		return c.cache[key.WithZone("")]
	}
	return nil
}

func (c *Cache) Delete(ip netip.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.cache, cacheKey(ip))
}

func cacheKey(ip netip.Addr) netip.Addr {
	return ip.Unmap()
}

func FillCache(cache *Cache, input io.Reader) error {
	scanner := bufio.NewScanner(input)
	line := 0
	for scanner.Scan() {
		line++
		var entry ScanResult
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return fmt.Errorf("neighbor cache: line %d: %w", line, err)
		}
		ip, err := netip.ParseAddr(entry.IP)
		if err != nil {
			return fmt.Errorf("neighbor cache: line %d: %w", line, errors.New("invalid IP"))
		}
		mac, err := net.ParseMAC(entry.MAC)
		if err != nil {
			return fmt.Errorf("neighbor cache: line %d: %w", line, err)
		}
		cache.Put(ip, mac)
	}
	return scanner.Err()
}

type cacheRequestGenerator struct {
	requestGenerator scan.RequestGenerator
	gatewayMAC       net.HardwareAddr
	cache            *Cache
}

func NewCacheRequestGenerator(
	requestGenerator scan.RequestGenerator,
	gatewayMAC net.HardwareAddr,
	cache *Cache,
) scan.RequestGenerator {
	return &cacheRequestGenerator{
		requestGenerator: requestGenerator,
		gatewayMAC:       gatewayMAC,
		cache:            cache,
	}
}

func (g *cacheRequestGenerator) GenerateRequests(
	ctx context.Context,
	r *scan.Range,
) (<-chan *scan.Request, error) {
	requests, err := g.requestGenerator.GenerateRequests(ctx, r)
	if err != nil {
		return nil, err
	}
	result := make(chan *scan.Request, cap(requests))
	go func() {
		defer close(result)
		for request := range requests {
			mac := g.cache.Get(request.DstIP)
			if mac == nil {
				mac = g.gatewayMAC
			}
			if mac == nil {
				request.Err = fmt.Errorf("no destination MAC address for %s", request.DstIP)
			} else {
				request.DstMAC = mac
			}
			select {
			case <-ctx.Done():
				return
			case result <- request:
			}
		}
	}()
	return result, nil
}
