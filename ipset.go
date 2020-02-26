package main

import (
	"bufio"
	"bytes"
	"net"
	"os"
	"sort"
	"strings"
)

type ipset []net.IPNet

var ipsets []ipset

func parseIPsets() {
	ipsets = make([]ipset, len(ipsetFiles))

	for i, filename := range ipsetFiles { // one file per loop
		file, err := os.Open(filename)
		if err != nil {
			logErr.Fatalln(err)
		}

		var ipset ipset
		scanner := bufio.NewScanner(file)

		for scanner.Scan() { // one line per loop
			ipStr := strings.TrimSpace(scanner.Text())

			if 0 == len(ipStr) { // skip empty line
				continue
			}

			if !strings.Contains(ipStr, "/") {
				if strings.Contains(ipStr, ":") {
					ipStr += "/128"
				} else {
					ipStr += "/32"
				}
			} // normalize

			_, ipNet, err := net.ParseCIDR(ipStr)
			if err != nil {
				logErr.Fatalf("Invalid CIDR: %s in file %s", scanner.Text(), filename)
			}

			ipset = append(ipset, *ipNet)
		}
		file.Close()

		ipset.sort()

		ipsets[i] = ipset
	}
}

func (ipset ipset) sort() {
	sort.Slice(ipset, func(i, j int) bool {
		if len(ipset[i].IP) != len(ipset[j].IP) { // ipv4 in front of ipv6
			return len(ipset[i].IP) < len(ipset[j].IP)
		}
		if bytes.Compare(ipset[i].IP, ipset[j].IP) < 0 {
			return true
		}
		return false
	})
}

func (ipset ipset) containsIP(ip net.IP) bool {
	if x := ip.To4(); x != nil {
		ip = x
	}

	cmpIPIPNet := func(ip net.IP, ipNet net.IPNet) int { // based on net.Contains()
		switch a, b := len(ip), len(ipNet.IP); {         // ipv4 in front of ipv6
		case a < b:
			return -1
		case a > b:
			return 1
		}

		for i := 0; i < len(ip); i++ {
			switch a, b := ip[i]&ipNet.Mask[i], ipNet.IP[i]&ipNet.Mask[i]; {
			case a < b:
				return -1
			case a > b:
				return 1
			}
		}
		return 0
	}

	for i, j := 0, len(ipset); i < j; { // based on sort.Search()
		switch k := int(uint(i+j) >> 1); cmpIPIPNet(ip, ipset[k]) { // i <= k < j
		case -1:
			j = k
		case 0:
			return true
		case 1:
			i = k + 1
		}
	}
	return false
}
