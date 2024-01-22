package cdn

import (
	"github.com/FateBug403/util"
	"log"
	"testing"
)

func TestCDNChecks(t *testing.T) {
	doamins := util.ReadFile("domains.txt")
	options := &Options{
		DnsOerverFile: "dns.txt",
		OnResult: func(s string) {
			log.Println(s)
		},
	}
	CDNClient := NewCDNClient(options)
	ips,err:=CDNClient.CDNChecks(doamins)
	if err != nil {
		log.Println(err)
		return
	}
	log.Println(ips)
}
