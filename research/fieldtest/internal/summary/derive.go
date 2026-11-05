// Package summary 把探测器的记录和 judge 的记录对起来，并汇总成结论。
//
// 探测器的记录说的是“我以为发生了什么”，judge 的记录说的是“目标站实际看到了什么”。
// 出口地址、请求有没有被改、有没有被重放，这些都只以 judge 的记录为准。
package summary

import (
	"sort"
	"strings"

	"fieldtest/internal/judge"
	"fieldtest/internal/nonce"
	"fieldtest/internal/probe"
	"fieldtest/internal/wire"
)

// 探测器自己发出的请求头。judge 收到的请求里多出来的，都是代理加的。
var sentHeaders = map[string]string{
	"User-Agent":      wire.UA,
	"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"Accept-Language": "en-US,en;q=0.9",
	"Accept-Encoding": "identity",
	"Connection":      "close",
	"Cookie":          "", // 值因请求而异，单独比较
	"X-Probe-Canary":  "",
}

// 这些头说明“我是代理”，但不一定暴露客户端地址。
var proxyHeaders = map[string]bool{
	"Via": true, "X-Forwarded-For": true, "Forwarded": true, "X-Real-Ip": true, "Proxy-Connection": true,
	"X-Forwarded-Proto": true, "X-Forwarded-Host": true, "X-Forwarded-Port": true, "Client-Ip": true,
	"X-Client-Ip": true, "Forwarded-For": true, "X-Proxy-Id": true, "X-Bluecoat-Via": true,
	"Surrogate-Capability": true, "X-Cache": true, "X-Squid-Error": true, "Cdn-Loop": true,
	"Proxy-Authorization": true, "X-Proxy-Connection": true, "Xroxy-Connection": true, "X-Originating-Ip": true,
	"True-Client-Ip": true, "Cf-Connecting-Ip": true, "X-Cluster-Client-Ip": true,
}

// Derived 是把一次尝试与 judge 记录对照后得出的事实。
type Derived struct {
	Seen      bool     `json:"seen"`                 // judge 收到过带这个 nonce 的请求
	Egress    string   `json:"egress,omitempty"`     // judge 看到的对端地址（最早到达的那一份）
	Copies    int      `json:"copies,omitempty"`     // judge 一共收到几份
	CopyIPs   int      `json:"copy_ips,omitempty"`   // 来自几个不同的地址
	LateS     int64    `json:"late_s,omitempty"`     // 最晚的一份到达时，nonce 已签发多少秒
	LeakIP    bool     `json:"leak_ip,omitempty"`    // 请求头里出现了探测器自己的地址
	AddedReq  []string `json:"added_req,omitempty"`  // 代理加进请求的头
	Tamper    []string `json:"tamper,omitempty"`     // 请求被改动的地方
	Anonymity string   `json:"anon,omitempty"`       // transparent / anonymous / elite
	HelloFP   string   `json:"hello_fp,omitempty"`   // judge 看到的 TLS ClientHello 指纹
	AbsTarget bool     `json:"abs_target,omitempty"` // 到达 judge 时请求行仍是绝对 URI
}

// Derive 对照一次尝试和 judge 收到的同 nonce 请求。clientIPs 是探测器自己的地址。
func Derive(a *probe.Attempt, recs []judge.Rec, secret []byte, clientIPs []string) Derived {
	var d Derived
	if len(recs) == 0 {
		return d
	}
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].TS < recs[j].TS })
	first := recs[0]
	d.Seen, d.Egress, d.Copies, d.HelloFP = true, first.Remote, len(recs), first.HelloFP
	ips := map[string]bool{}
	for _, r := range recs {
		ips[r.Remote] = true
		if r.AgeS > d.LateS {
			d.LateS = r.AgeS
		}
	}
	d.CopyIPs = len(ips)
	d.AbsTarget = strings.Contains(first.Target, "://")

	want := nonce.Canary(secret, "req", a.Nonce)
	got := map[string]string{}
	revealed := false
	for _, kv := range first.Headers {
		k, v := kv[0], kv[1]
		got[k] = v
		if k == "Host" {
			continue
		}
		if _, ours := sentHeaders[k]; !ours {
			d.AddedReq = append(d.AddedReq, k)
			if proxyHeaders[k] {
				revealed = true
			}
		}
		for _, ip := range clientIPs {
			if ip != "" && strings.Contains(v, ip) {
				d.LeakIP = true
			}
		}
	}
	switch first.Canary {
	case "missing":
		d.Tamper = append(d.Tamper, "canary_missing")
	case "bad":
		d.Tamper = append(d.Tamper, "canary_changed")
	}
	switch c, ok := got["Cookie"]; {
	case !ok:
		d.Tamper = append(d.Tamper, "cookie_missing")
	case c != "pc="+want:
		d.Tamper = append(d.Tamper, "cookie_changed")
	}
	for k, wantV := range sentHeaders {
		if wantV == "" {
			continue
		}
		v, ok := got[k]
		switch {
		case !ok && k == "Connection":
			// 逐跳的头，代理去掉它是合规的
		case !ok:
			d.Tamper = append(d.Tamper, tamperName(k)+"_missing")
		case v != wantV && k != "Connection":
			d.Tamper = append(d.Tamper, tamperName(k)+"_changed")
		}
	}
	if first.Method != "GET" {
		d.Tamper = append(d.Tamper, "method_changed")
	}
	sort.Strings(d.Tamper)
	sort.Strings(d.AddedReq)
	switch {
	case d.LeakIP:
		d.Anonymity = "transparent"
	case revealed:
		d.Anonymity = "anonymous"
	default:
		d.Anonymity = "elite"
	}
	return d
}

func tamperName(h string) string {
	return strings.ToLower(strings.ReplaceAll(h, "-", "_"))
}
