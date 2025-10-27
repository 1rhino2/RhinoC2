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
	}

	return result, nil
}

func GetActiveConnections() (string, error) {
	var output string
	var err error

	if runtime.GOOS == "windows" {
		cmd := NewCommander()
		output, err = cmd.Execute("netstat -ano")
	} else {
		cmd := NewCommander()
		output, err = cmd.Execute("netstat -tuln")
	}

	return output, err
}

func GetRoutingTable() (string, error) {
	var output string
	var err error

	if runtime.GOOS == "windows" {
		cmd := NewCommander()
		output, err = cmd.Execute("route print")
	} else {
		cmd := NewCommander()
		output, err = cmd.Execute("route -n")
	}

	return output, err
}

func GetDNSServers() ([]string, error) {
	var servers []string

	if runtime.GOOS == "windows" {
		cmd := NewCommander()
		output, err := cmd.Execute("Get-DnsClientServerAddress | Where-Object {$_.AddressFamily -eq 2} | Select-Object -ExpandProperty ServerAddresses")
		if err != nil {
			return servers, err
		}
		servers = strings.Split(strings.TrimSpace(output), "\n")
	}

	return servers, nil
}

func ResolveDNS(hostname string) ([]string, error) {
	ips, err := net.LookupHost(hostname)
	return ips, err
}

func PingHost(host string) (bool, error) {
	conn, err := net.DialTimeout("ip4:icmp", host, 3*time.Second)
	if err != nil {
		return false, err
	}
	conn.Close()
	return true, nil
}

func GetPublicIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}

func CheckInternetConnection() bool {
	conn, err := net.DialTimeout("tcp", "8.8.8.8:53", 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func GetHostByIP(ip string) (string, error) {
	names, err := net.LookupAddr(ip)
	if err != nil {
		return "", err
	}
	if len(names) == 0 {
		return "", fmt.Errorf("no hostname found")
	}
	return names[0], nil
}

func (ns *NetworkScanner) DiscoverHosts(subnet string) []string {
	var hosts []string
	commonPorts := []int{80, 443, 22, 3389, 445}

	for i := 1; i < 255; i++ {
		ip := fmt.Sprintf("%s.%d", subnet[:strings.LastIndex(subnet, ".")], i)
		for _, port := range commonPorts {
			if ns.ScanPort(ip, port) {
				hosts = append(hosts, ip)
				break
			}
		}
	}

	return hosts
}
