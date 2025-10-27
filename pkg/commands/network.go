package commands

import (
	"fmt"
	"net"
	"runtime"
	"strings"
	"time"
)

type NetworkScanner struct {
	timeout time.Duration
}

func NewNetworkScanner() *NetworkScanner {
	return &NetworkScanner{timeout: 2 * time.Second}
}

func (ns *NetworkScanner) ScanPort(host string, port int) bool {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, ns.timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (ns *NetworkScanner) ScanPorts(host string, ports []int) map[int]bool {
	results := make(map[int]bool)
	for _, port := range ports {
		results[port] = ns.ScanPort(host, port)
	}
	return results
}

func (ns *NetworkScanner) ScanRange(network string, port int) []string {
	var alive []string

	ip := net.ParseIP(network)
	if ip == nil {
		return alive
	}

	for i := 1; i < 255; i++ {
		testIP := fmt.Sprintf("%s.%d", network[:strings.LastIndex(network, ".")], i)
		if ns.ScanPort(testIP, port) {
			alive = append(alive, testIP)
		}
	}

	return alive
}

func GetNetworkInterfaces() ([]map[string]interface{}, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var result []map[string]interface{}
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		var addresses []string
		for _, addr := range addrs {
			addresses = append(addresses, addr.String())
		}

		info := map[string]interface{}{
			"name":      iface.Name,
			"mac":       iface.HardwareAddr.String(),
			"addresses": addresses,
			"mtu":       iface.MTU,
			"flags":     iface.Flags.String(),
		}
		result = append(result, info)
