package main

import (
	"context"
	"flag"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"gopkg.in/go-ini/ini.v1"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const ( //TODO
	version   = ""
	buildDate = ""
)

var (
	serversStr    entries
	ipsetFiles    entries
	listenAddrStr = flag.String("b", "localhost:5353", "Local binding address and UDP port (e.g. 127.0.0.1:5353 [::1]:5353)")
	configFile    = flag.String("c", "", "Config file containing rules for filtering.")
	timeout       = flag.Duration("t", time.Second, "Waiting timeout per query")
	showVer       = flag.Bool("V", false, "Show version")
	verbose       = flag.Bool("v", false, "Verbose mode")
)

func init() {
	flag.Var(&serversStr, "d", "Nameservers. Use format [IP]:port for IPv6.")
	flag.Var(&ipsetFiles, "l", "ipset files. Can be set multiple times or in comma-separated form")
}

var (
	servers      []*net.UDPAddr
	listenerConn *net.UDPConn
	rules        []*rule
	logStd       = log.New(os.Stdout, "", log.Ldate|log.Lmicroseconds)
	logErr       = log.New(os.Stderr, "", log.Ldate|log.Lmicroseconds)
)

func parseUdpAddr(str string) (*net.UDPAddr, error) {
	_, _, err := net.SplitHostPort(str)
	if err == nil {
		return net.ResolveUDPAddr("udp", str)
	}
	if _, _, err := net.SplitHostPort(str + ":53"); err == nil { // further try
		return net.ResolveUDPAddr("udp", str+":53")
	}
	if _, _, err := net.SplitHostPort("[" + str + "]:53"); err == nil {
		return net.ResolveUDPAddr("udp", "["+str+"]:53")
	}
	return nil, err
}

func lookupServer(addr *net.UDPAddr) (int, bool) {
	for i, server := range servers {
		if server.IP.Equal(addr.IP) && server.Port == addr.Port && server.Zone == addr.Zone {
			return i, true
		}
	}
	return -1, false
}

func parseServers() {
	for _, serverStr := range serversStr {
		addr, err := parseUdpAddr(serverStr)
		if err != nil {
			logErr.Fatalf("Invalid nameserver: %s", serverStr)
		}

		if addr.Zone != "" { // normalize zone to name instead of index
			if zoneid, err := strconv.Atoi(addr.Zone); err == nil {
				if ifi, err := net.InterfaceByIndex(zoneid); err == nil {
					addr.Zone = ifi.Name
				} else {
					logErr.Fatalf("IPv6 zone invalid: %s", serverStr)
				}
			} else if _, err := net.InterfaceByName(addr.Zone); err != nil {
				logErr.Fatalf("IPv6 zone invalid: %s", serverStr)
			}
		}

		if _, exist := lookupServer(addr); !exist {
			servers = append(servers, addr)
			logStd.Printf("Using nameserver %s", addr)
		} else {
			logErr.Fatalf("Nameserver exists: %s", serverStr)
		}
	}
}

func parseConfig() {
	answerTypeValues := map[string]dnsmessage.Type{ // map config strings back to value
		"A":     dnsmessage.TypeA,
		"NS":    dnsmessage.TypeNS,
		"CNAME": dnsmessage.TypeCNAME,
		"SOA":   dnsmessage.TypeSOA,
		"PTR":   dnsmessage.TypePTR,
		"MX":    dnsmessage.TypeMX,
		"TXT":   dnsmessage.TypeTXT,
		"AAAA":  dnsmessage.TypeAAAA,
		"SRV":   dnsmessage.TypeSRV,
		"OPT":   dnsmessage.TypeOPT,
		"WKS":   dnsmessage.TypeWKS,
		"HINFO": dnsmessage.TypeHINFO,
		"MINFO": dnsmessage.TypeMINFO,
		"AXFR":  dnsmessage.TypeAXFR,
		"ALL":   dnsmessage.TypeALL,
	}

	cfg, err := ini.Load(*configFile)
	if err != nil {
		logErr.Fatalln("Failed to load config file:", err)
	}

	ruleSections := cfg.ChildSections("rule")
	rules = make([]*rule, len(ruleSections))

	for i, ruleSection := range ruleSections { //one rule each time
		ruleName := ruleSection.Name()
		var logBuf strings.Builder
		fmt.Fprintf(&logBuf, "%s:", ruleName)

		targetKey, err := ruleSection.GetKey("target")
		if err != nil {
			logErr.Fatalf("%s target must exist in a rule!", ruleName)
		} // target is mandatory

		var rule rule

		if serverKey, err := ruleSection.GetKey("server"); err == nil {
			if server, err := serverKey.Uint(); err == nil && server > 0 && server <= uint(len(servers)) {
				rule.match.server = server
				fmt.Fprintf(&logBuf, " SERVER %d", server)
			} else {
				logErr.Printf("%s invalid server index! Assume matching any", ruleName)
			}
		}

		if ipsetKey, err := ruleSection.GetKey("ipset"); err == nil {
			if ipset, err := ipsetKey.Uint(); err == nil && ipset > 0 && ipset <= uint(len(ipsets)) {
				rule.match.ipset = ipset
				fmt.Fprintf(&logBuf, " IPSET %d", ipset)
			} else {
				logErr.Printf("%s invalid ipset index! Assume matching any", ruleName)
			}
		}

		if answerTypeKey, err := ruleSection.GetKey("type"); err == nil {
			if answerType, ok := answerTypeValues[strings.ToUpper(strings.TrimSpace(answerTypeKey.String()))]; ok {
				rule.match.answerType = answerType
				fmt.Fprintf(&logBuf, " %s", answerType)
			} else {
				logErr.Printf("%s invalid type! Assume matching any", ruleName)
			}
		}

		if nameKey, err := ruleSection.GetKey("name"); err == nil {
			if name := strings.Trim(nameKey.String(), " ."); 0 != len(name) {
				rule.match.name = name
				fmt.Fprintf(&logBuf, " DOMAIN NAME %s", name)
			} else {
				logErr.Printf("%s empty domain name! Assume matching any", ruleName)
			}
		}

		switch target := strings.TrimSpace(targetKey.String()); { //TARGET
		case strings.EqualFold(target, "DROP"):
			rule.delay = -1
			logBuf.WriteString(" [DROP]")

		case strings.EqualFold(target, "ACCEPT"):
			rule.delay = 0
			logBuf.WriteString(" [ACCEPT]")

		case strings.EqualFold(target, "DELAY"):
			if delayKey, err := ruleSection.GetKey("delay"); err == nil {
				if delay, err := delayKey.Duration(); err == nil {
					rule.delay = delay
					fmt.Fprintf(&logBuf, " [DELAY %s]", delay)
				} else {
					rule.delay = 0
					logBuf.WriteString(" [ACCEPT]")
					logErr.Printf("%s delay parse error:[%s] Assume ACCEPT!", ruleName, err)
				}
			} else {
				rule.delay = 0
				logBuf.WriteString(" [ACCEPT]")
				logErr.Printf("%s delay must be specified when target is delay! Assume ACCEPT!", ruleName)
			}

		default:
			logErr.Fatalf("%s unknown target!", ruleName)
		}

		logStd.Println(logBuf.String())

		rules[i] = &rule
	}
}

func main() {
	flag.Parse()

	if *showVer {
		fmt.Printf("dnsfilter version %s (built %s)\n", version, buildDate)
		return
	}

	parseServers()
	parseIPsets()
	parseConfig()

	listenAddr, err := parseUdpAddr(*listenAddrStr)
	if err != nil {
		logErr.Fatalf("Invalid binding address: %s", *listenAddrStr)
	}
	listenerConn, err = net.ListenUDP("udp", listenAddr)
	if err != nil {
		logErr.Fatalln(err)
	}
	defer listenerConn.Close()
	logStd.Printf("Listening on UDP %s", listenAddr)

	for {
		payload := make([]byte, 1500)
		if n, clientAddr, err := listenerConn.ReadFromUDP(payload); err != nil {
			logErr.Println(err)
			continue
		} else {
			go handle(context.WithValue(context.Background(), clientAddrKey, clientAddr), payload[:n])
		}
	}
}
