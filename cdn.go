package cdn

import (
	"context"
	"github.com/FateBug403/util"
	"github.com/miekg/dns"
	"github.com/remeh/sizedwaitgroup"
	"strings"
	"sync"
	"time"
)

type CDN struct {
	options *Options
}

// NewCDNClient 创建一个CDN客户端
func NewCDNClient(options *Options) *CDN{
	return &CDN{options: options}
}

// CheckCDN 对某个单独的域名进行CDN检测
func (c *CDN)CheckCDN(domain string)string{
	return c.checkdnsresolve(domain)
}

// CDNChecks 批量获取真实IP，可以输入域名、IP和host
func (c *CDN)CDNChecks(targets []string) ([]string,error) {
	// 解析域名IP地址，并判断是否存在DCN，将不存DCN的地址纳入IPS中
	var ips []string
	for _,targetTmp := range targets{
		// 如果目标是域名-检测CDN，如果是IP直接添加到返回，如果是主机:端口，提取主机
		targetTmp = extractHost(targetTmp)
		if util.IsIP(targetTmp){ // 如果目标是IP，则直接加入到返回
			ips = append(ips,targetTmp)
			continue
		}
		checkInfo :=c.CheckCDN(targetTmp)
		if checkInfo != ""{
			if !util.In(checkInfo,ips){
				ips = append(ips,checkInfo)
			}
		}
	}
	return ips,nil
}

// checkdnsresolve 返回CDN查询结果，如果判断有CDN则返回空，否则返回IP地址
func (c *CDN)checkdnsresolve(domain string)string{
	// 使用各个不同地方的dns服务器模拟多地ping，如果只有一个ip，则判断IP是不是在已知的CDN厂商IP节点中
	var ips []string
	tdns := util.ReadFile(c.options.DnsOerverFile)

	wg := sizedwaitgroup.New(50)//设置请求线程数
	for _,i := range tdns{
		wg.Add()
		go func(i string, wg *sizedwaitgroup.SizedWaitGroup) {
			defer wg.Done()
			ip :=resolve(domain,i)
			if ip == nil{
				return
			}
			if len(ip)>1 || len(ips)>1{ //如果解析的ip大于1或者整体ips大于1则退出线程
				return
			}else if len(ip)==1 {
				if !util.In(ip[0],ips){ // 判断解析的ip是否在ips列表中，不在则添加
					ips = append(ips,ip...)
				}
			}
		}(i,&wg)
	}

	wg.Wait()

	//过滤重复的ip
	ips =util.RemoveDuplicateElement(ips)
	if len(ips)!=1{ //如果无法解析域名的ip地址
		return ""
	}
	c.options.OnResult(ips[0])
	return ips[0]
}

func extractHost(url string) string {
	// 使用 strings.Split 分割字符串
	parts := strings.Split(url, ":")

	// 如果只有一个部分，即没有端口号，则直接返回
	if len(parts) == 1 {
		return parts[0]
	}

	// 如果有多个部分，使用 strings.Index 查找 ":" 的位置
	colonIndex := strings.Index(parts[0], ":")
	if colonIndex != -1 {
		// 如果找到 ":"，则返回 ":" 之前的部分
		return parts[0][:colonIndex]
	}

	// 如果没找到 ":", 则直接返回第一个部分
	return parts[0]
}

var mu  sync.Mutex

//resolve 从指定ns服务器获取域名的解析记录
func resolve(domain string,ns string)[]string{
	timeout := 15 * time.Second // 设置超时时间为10秒
	hostname := domain
	ctx, cancel := context.WithTimeout(context.Background(), timeout) // 创建带有超时时间的上下文
	defer cancel()

	resolver := &dns.Client{ // 创建dns客户端
		Net: "udp",
	}
	m := dns.Msg{}
	//设置查询条件
	m.Question =  []dns.Question{
		{Name: dns.Fqdn(hostname), Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	r,_,err:=resolver.ExchangeContext(ctx,&m,ns)
	if err != nil {
		return nil
	}
	//处理回答
	var dst []string
	for _, ans := range r.Answer {
		record,isType := ans.(*dns.A)
		if isType {
			dst = append(dst, record.A.String())
		}
	}
	return dst
}
