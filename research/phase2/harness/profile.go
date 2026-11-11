package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// Profile 是 PROTOCOL.md“仪器 / obsproxy”一节定义的配置。
// 字段、默认值和含义以 PROTOCOL.md 为准；这里出现而那里没有的字段一律不允许。
type Profile struct {
	Auth    AuthProfile    `json:"auth"`
	Connect ConnectProfile `json:"connect"`
	Forward ForwardProfile `json:"forward"`
	Conn    ConnProfile    `json:"conn"`
	Tunnel  TunnelProfile  `json:"tunnel"`
	Origin  OriginProfile  `json:"origin"`
	Socks   SocksProfile   `json:"socks"`
}

type AuthProfile struct {
	Mode          string   `json:"mode"`
	Accept        []Pair   `json:"accept"`
	AcceptAnyUser bool     `json:"accept_any_user"`
	Challenge     []string `json:"challenge"`
	On407         string   `json:"on407"`
	RejectStatus  int      `json:"reject_status"`
}

type ConnectProfile struct {
	OKHeaders []Pair    `json:"ok_headers"`
	Fail      *FailSpec `json:"fail"`
	Drop      *DropSpec `json:"drop"`
}

type ForwardProfile struct {
	Fail               *FailSpec `json:"fail"`
	AddResponseHeaders []Pair    `json:"add_response_headers"`
	Send100Continue    bool      `json:"send_100_continue"`
}

type ConnProfile struct {
	IdleCloseMs int       `json:"idle_close_ms"`
	Drop        *DropSpec `json:"drop"`
}

type TunnelProfile struct {
	IdleCloseMs int `json:"idle_close_ms"`
}

type OriginProfile struct {
	H2   bool      `json:"h2"`
	Drop *DropSpec `json:"drop"`
}

type SocksProfile struct {
	Auth           string `json:"auth"`
	AuthFailStatus int    `json:"auth_fail_status"`
	Rep            int    `json:"rep"`
}

// Pair 是 [名, 值] 或 [用户名, 密码]。
type Pair [2]string

func (p *Pair) UnmarshalJSON(b []byte) error {
	var a []string
	if err := json.Unmarshal(b, &a); err != nil {
		return fmt.Errorf("应为两个字符串组成的数组: %w", err)
	}
	if len(a) != 2 {
		return fmt.Errorf("应为两个字符串组成的数组，实际有 %d 项", len(a))
	}
	p[0], p[1] = a[0], a[1]
	return nil
}

// FailSpec 是 connect.fail、forward.fail：不建隧道（不转发），直接回这个响应。
// PROTOCOL.md 没有给它内部的默认值，这里的取法是：status 必填；reason 缺省取该状态码的标准短语；
// headers、hosts 缺省为空；body 缺省为空；close 缺省为 false。
type FailSpec struct {
	Status  int      `json:"status"`
	Reason  string   `json:"reason"`
	Headers []Pair   `json:"headers"`
	Body    string   `json:"body"`
	Close   bool     `json:"close"`
	Hosts   []string `json:"hosts"`
}

func (f *FailSpec) UnmarshalJSON(b []byte) error {
	var v struct {
		Status  *int     `json:"status"`
		Reason  *string  `json:"reason"`
		Headers []Pair   `json:"headers"`
		Body    string   `json:"body"`
		Close   bool     `json:"close"`
		Hosts   []string `json:"hosts"`
	}
	if err := strictDecode(b, &v); err != nil {
		return err
	}
	if v.Status == nil {
		return errors.New("缺少 status")
	}
	f.Status = *v.Status
	if v.Reason != nil {
		f.Reason = *v.Reason
	} else {
		f.Reason = http.StatusText(f.Status)
	}
	f.Headers = v.Headers
	if f.Headers == nil {
		f.Headers = []Pair{}
	}
	f.Body = v.Body
	f.Close = v.Close
	f.Hosts = v.Hosts
	if f.Hosts == nil {
		f.Hosts = []string{}
	}
	return nil
}

// appliesTo 判断这条失败规则对目标主机是否生效：hosts 为空对所有主机生效，否则只对列出的主机（不分大小写）。
func (f *FailSpec) appliesTo(host string) bool {
	if len(f.Hosts) == 0 {
		return true
	}
	for _, h := range f.Hosts {
		if strings.EqualFold(h, host) {
			return true
		}
	}
	return false
}

// DropSpec 是 connect.drop、conn.drop、origin.drop。times 缺省 1，how 缺省 fin，only_if_reused 缺省 false。
type DropSpec struct {
	K            string `json:"k"`
	Times        int    `json:"times"`
	How          string `json:"how"`
	OnlyIfReused bool   `json:"only_if_reused"`
}

func (d *DropSpec) UnmarshalJSON(b []byte) error {
	type plain DropSpec
	v := plain{Times: 1, How: "fin"}
	if err := strictDecode(b, &v); err != nil {
		return err
	}
	*d = DropSpec(v)
	return nil
}

// strictDecode 解码 JSON，遇到不认识的字段或多余的内容就报错。
func strictDecode(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("JSON 之后还有多余的内容")
	}
	return nil
}

// DefaultProfile 返回 PROTOCOL.md 里写明的默认配置。
func DefaultProfile() *Profile {
	return &Profile{
		Auth: AuthProfile{
			Mode:         "none",
			Accept:       []Pair{},
			Challenge:    []string{`Basic realm="kaoju"`},
			On407:        "keepalive",
			RejectStatus: 407,
		},
		Connect: ConnectProfile{OKHeaders: []Pair{}},
		Forward: ForwardProfile{AddResponseHeaders: []Pair{}, Send100Continue: true},
		Origin:  OriginProfile{H2: true},
		Socks:   SocksProfile{Auth: "none", AuthFailStatus: 1},
	}
}

// ParseProfile 解析配置：没写的字段取默认值，不认识的字段报错，取值不合法也报错。
func ParseProfile(data []byte) (*Profile, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, errors.New("配置必须是一个 JSON 对象")
	}
	p := DefaultProfile()
	if err := strictDecode(trimmed, p); err != nil {
		return nil, fmt.Errorf("配置解析失败: %w", err)
	}
	// 显式写成 null 的数组按空数组处理。
	if p.Auth.Accept == nil {
		p.Auth.Accept = []Pair{}
	}
	if p.Auth.Challenge == nil {
		p.Auth.Challenge = []string{}
	}
	if p.Connect.OKHeaders == nil {
		p.Connect.OKHeaders = []Pair{}
	}
	if p.Forward.AddResponseHeaders == nil {
		p.Forward.AddResponseHeaders = []Pair{}
	}
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("配置不合法: %w", err)
	}
	return p, nil
}

// LoadProfile 从文件读配置。
func LoadProfile(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读配置文件失败: %w", err)
	}
	return ParseProfile(data)
}

func (p *Profile) validate() error {
	switch p.Auth.Mode {
	case "none", "basic":
	default:
		return fmt.Errorf("auth.mode 只能是 none 或 basic，实际是 %q", p.Auth.Mode)
	}
	switch p.Auth.On407 {
	case "keepalive", "close":
	default:
		return fmt.Errorf("auth.on407 只能是 keepalive 或 close，实际是 %q", p.Auth.On407)
	}
	if p.Auth.RejectStatus != 407 && p.Auth.RejectStatus != 403 {
		return fmt.Errorf("auth.reject_status 只能是 407 或 403，实际是 %d", p.Auth.RejectStatus)
	}
	if p.Auth.AcceptAnyUser && len(p.Auth.Accept) == 0 {
		return errors.New("auth.accept_any_user 为真时 auth.accept 至少要有一项（密码取 accept[0][1]）")
	}
	for i, c := range p.Auth.Challenge {
		if !validHeaderValue(c) {
			return fmt.Errorf("auth.challenge[%d] 含有不能出现在头里的字符", i)
		}
	}
	if err := validPairs("connect.ok_headers", p.Connect.OKHeaders); err != nil {
		return err
	}
	if err := validPairs("forward.add_response_headers", p.Forward.AddResponseHeaders); err != nil {
		return err
	}
	if err := p.Connect.Fail.validate("connect.fail"); err != nil {
		return err
	}
	if err := p.Forward.Fail.validate("forward.fail"); err != nil {
		return err
	}
	if err := p.Connect.Drop.validate("connect.drop", false); err != nil {
		return err
	}
	if err := p.Conn.Drop.validate("conn.drop", true); err != nil {
		return err
	}
	if err := p.Origin.Drop.validate("origin.drop", true); err != nil {
		return err
	}
	if p.Conn.IdleCloseMs < 0 {
		return errors.New("conn.idle_close_ms 不能是负数")
	}
	if p.Tunnel.IdleCloseMs < 0 {
		return errors.New("tunnel.idle_close_ms 不能是负数")
	}
	switch p.Socks.Auth {
	case "none", "userpass", "reject":
	default:
		return fmt.Errorf("socks.auth 只能是 none、userpass 或 reject，实际是 %q", p.Socks.Auth)
	}
	if p.Socks.AuthFailStatus < 1 || p.Socks.AuthFailStatus > 255 {
		return fmt.Errorf("socks.auth_fail_status 必须在 1 到 255 之间（0 表示成功），实际是 %d", p.Socks.AuthFailStatus)
	}
	if p.Socks.Rep < 0 || p.Socks.Rep > 255 {
		return fmt.Errorf("socks.rep 必须在 0 到 255 之间，实际是 %d", p.Socks.Rep)
	}
	return nil
}

func (f *FailSpec) validate(name string) error {
	if f == nil {
		return nil
	}
	if f.Status < 200 || f.Status > 599 {
		return fmt.Errorf("%s.status 必须在 200 到 599 之间，实际是 %d", name, f.Status)
	}
	if !validHeaderValue(f.Reason) {
		return fmt.Errorf("%s.reason 含有不能出现在状态行里的字符", name)
	}
	return validPairs(name+".headers", f.Headers)
}

func (d *DropSpec) validate(name string, needK bool) error {
	if d == nil {
		return nil
	}
	if d.How != "fin" && d.How != "rst" {
		return fmt.Errorf("%s.how 只能是 fin 或 rst，实际是 %q", name, d.How)
	}
	if d.Times < 0 {
		return fmt.Errorf("%s.times 不能是负数", name)
	}
	if needK && d.K == "" {
		return fmt.Errorf("%s.k 不能为空", name)
	}
	if !needK && (d.K != "" || d.OnlyIfReused) {
		return fmt.Errorf("%s 只支持 times 和 how 两个字段", name)
	}
	return nil
}

func validPairs(name string, ps []Pair) error {
	for i, h := range ps {
		if !isToken(h[0]) {
			return fmt.Errorf("%s[%d] 的头名字 %q 不合法", name, i, h[0])
		}
		if !validHeaderValue(h[1]) {
			return fmt.Errorf("%s[%d] 的头值含有不能出现在头里的字符", name, i)
		}
	}
	return nil
}

// validHeaderValue 检查配置里要写进响应的文字：不许有控制字符（HTAB 除外），防止配置把响应写坏。
func validHeaderValue(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 0x20 && c != '\t') || c == 0x7f {
			return false
		}
	}
	return true
}

// credsOK 按字节判定用户名和密码。accept_any_user 为真时只比密码（与 accept[0][1] 比）。
// SOCKS5 的用户名密码认证用它：那里用户名和密码各有长度字节，分界是确定的。
// HTTP 的 Basic 分不清用户名里的冒号，用下面的 basicOK。
func (p *Profile) credsOK(user, pass []byte) bool {
	if p.Auth.AcceptAnyUser {
		return len(p.Auth.Accept) > 0 && string(pass) == p.Auth.Accept[0][1]
	}
	for _, a := range p.Auth.Accept {
		if string(user) == a[0] && string(pass) == a[1] {
			return true
		}
	}
	return false
}

// basicOK 判定 Basic 凭据。decoded 是 base64 解开以后的全部字节（user-pass）。
// Basic 的线上格式只有“用户名:密码”这一串，用户名里带冒号时接收方分不出界线在哪
// （RFC 7617 第 2 节不许用户名带冒号，但用例 D11 要测的正是客户端这样发时到达的字节）。
// 所以这里不拆，直接比整串：与某一项的“用户名:密码”逐字节相同就接受；
// accept_any_user 为真时，以“:密码”（密码取 accept[0][1]）结尾就接受。
// 用户名不带冒号时，这与“按第一个冒号拆开再分别比”的结果相同。
func (p *Profile) basicOK(decoded []byte) bool {
	if p.Auth.AcceptAnyUser {
		return len(p.Auth.Accept) > 0 && bytes.HasSuffix(decoded, []byte(":"+p.Auth.Accept[0][1]))
	}
	for _, a := range p.Auth.Accept {
		if string(decoded) == a[0]+":"+a[1] {
			return true
		}
	}
	return false
}
