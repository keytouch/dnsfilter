package main

import (
	"bytes"
	"context"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"strings"
	"sync"
	"time"
)

func handle(ctx context.Context, payload []byte) {
	var parser dnsmessage.Parser
	hdr, err := parser.Start(payload)
	if err != nil {
		logErr.Println(err)
		return
	}

	qs, err := parser.AllQuestions()
	if err != nil {
		logErr.Println(err)
		return
	}

	if *verbose {
		var logBuf strings.Builder
		fmt.Fprintf(&logBuf, "%d %s", hdr.ID, ctx.Value(clientAddrKey).(*net.UDPAddr))
		for _, q := range qs {
			fmt.Fprintf(&logBuf, " Query[%s] %s", q.Type.String()[4:], q.Name.String())
		}
		fmt.Fprintf(&logBuf, " len %d", len(payload))
		logStd.Println(logBuf.String())
	}

	outConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		logErr.Println(err)
		return
	}
	defer outConn.Close() // duplicate close should only return error

	query(ctx, payload, outConn)
}

func query(ctx context.Context, payload []byte, outConn *net.UDPConn) {
	var (
		clientSendTimer *time.Timer
		clientSendTime  time.Time
		clientSendLock  sync.Mutex
	)

	sentTime := time.Now()
	for _, server := range servers {
		if _, err := outConn.WriteToUDP(payload, server); err != nil {
			logErr.Println(err)
			continue
		}
	}

	outConn.SetReadDeadline(sentTime.Add(*timeout))
	for {
		payload := make([]byte, 1500)
		n, addr, err := outConn.ReadFromUDP(payload)
		if err != nil {
			return
		}

		if i, ok := lookupServer(addr); ok {
			go sendBack(ctx, i+1, payload[:n], outConn, &clientSendTimer, &clientSendTime, &clientSendLock)
		}
	}
}

func sendBack(ctx context.Context, serverIndex int, msgIn []byte, outConn *net.UDPConn, clientSendTimer **time.Timer, clientSendTime *time.Time, clientSendLock *sync.Mutex) {
	delay := determine(serverIndex, msgIn)
	if delay < 0 {
		return
	}

	newClientSendTime := time.Now().Add(delay)

	// Lock to prevent race when answers come in simultaneously. Context is not handy for this
	clientSendLock.Lock()

	// if planned send time doesn't exist, go ahead.
	// or if calculated send time is prior to the previously planned one, go ahead.
	if clientSendTime.IsZero() || newClientSendTime.Before(*clientSendTime) {
		// if there's no previous timer or stop is successful, set new planned time
		if *clientSendTimer == nil || (*clientSendTimer).Stop() {
			*clientSendTimer = time.AfterFunc(delay, func() {
				outConn.Close()
				listenerConn.WriteToUDP(msgIn, ctx.Value(clientAddrKey).(*net.UDPAddr))
			})
			*clientSendTime = newClientSendTime
		} // If stop fails, let the previous timer fire
	}

	clientSendLock.Unlock()
}

func determine(serverIndex int, msgIn []byte) (delay time.Duration) {
	delay = -1 // Assume DROP if parse fails

	var logBuf strings.Builder

	var parser dnsmessage.Parser
	hdr, err := parser.Start(msgIn)
	if err != nil {
		logErr.Println(err)
		return
	}

	parser.SkipAllQuestions()
	answers, err := parser.AllAnswers() // parse answers in advance since there are several rules
	if err != nil {
		logErr.Println(err)
		return
	}

	if *verbose {
		fmt.Fprintf(&logBuf, "%d %s Answer len %d", hdr.ID, servers[serverIndex-1], len(msgIn))
		for _, ans := range answers {
			fmt.Fprintf(&logBuf, " %s %s TTL %d %v", ans.Header.Name, ans.Header.Type.String()[4:], ans.Header.TTL, ans.Body)
		}
	}

	for _, rule := range rules { // rule by rule. continue if match failed
		match := rule.match

		if match.server != 0 && match.server != uint(serverIndex) {
			continue
		}

		for _, ans := range answers {
			if match.name != "" {
				name := bytes.Trim(ans.Header.Name.Data[:ans.Header.Name.Length], ".")
				switch ml, l := len(match.name), len(name); {
				case ml > l:
					continue
				case ml < l:
					if dotMName := append([]byte("."), match.name...); !bytes.EqualFold(name[len(name)-len(dotMName):], dotMName) {
						continue
					}
				default: // ml = l
					if !bytes.EqualFold(name, []byte(match.name)) {
						continue
					}
				}
			}

			if match.answerType != 0 && match.answerType != ans.Header.Type {
				continue
			}

			if match.ipset != 0 {
				var ip net.IP
				switch ans.Header.Type {
				case dnsmessage.TypeA:
					res := ans.Body.(*dnsmessage.AResource)
					ip = res.A[:]
				case dnsmessage.TypeAAAA:
					res := ans.Body.(*dnsmessage.AAAAResource)
					ip = res.AAAA[:]
				default: // neither A nor AAAA, not match
					continue
				}
				if !ipsets[match.ipset-1].containsIP(ip) {
					continue
				}
			}

			if *verbose {
				switch d := rule.delay; {
				case d < 0:
					logBuf.WriteString(" [DROP]")
				case d == 0:
					logBuf.WriteString(" [ACCEPT]")
				default:
					fmt.Fprintf(&logBuf, " [DELAY %v]", d)
				}
				logStd.Println(&logBuf)
			}

			return rule.delay // if everything goes smoothly
		}
	}

	if *verbose {
		logBuf.WriteString(" [DROP]")
		logStd.Println(&logBuf)
	}
	return
}
