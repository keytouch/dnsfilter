package main

import (
	"golang.org/x/net/dns/dnsmessage"
	"strings"
	"time"
)

type key int

const (
	clientAddrKey key = iota
)

type entries []string

type match struct {
	server     uint
	ipset      uint
	answerType dnsmessage.Type
	name       string
}

type rule struct {
	match match
	delay time.Duration
}

func (e *entries) String() string {
	var strBuilder strings.Builder
	for i, entry := range *e {
		if i > 0 {
			strBuilder.WriteByte(',')
		}
		strBuilder.WriteString(entry)
	}
	return strBuilder.String()
}

func (e *entries) Set(value string) error {
	for _, entry := range strings.Split(value, ",") {
		*e = append(*e, entry)
	}
	return nil
}
