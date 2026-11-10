// certcheck：离线校验 fieldtest 留下的证书链证据（evidence/<前两位>/<哈希>.der，一个文件里是对端出示的
// 证书链的 DER 串接，叶子在前；见 internal/wire/wire.go TLS() 和 internal/rec/rec.go Evidence.Put）。
//
// 给 research/phase1b/m_mitm.py 的“中间人”细分（PROTOCOL 第 1.2 版）用：
//   - 被送到别的网站：证书链用公共根证书、按尝试发生的时刻校验、不看主机名，校验通过；
//   - 去向不明：校验不过（自签、过期、签发者不认识、对方没发中间证书）。
//
// 只用 Go 标准库；不联网补全中间证书（crypto/x509 本来就不会去取 AIA）；根证书只来自 -roots 指定的 PEM 文件。
//
// 用法：
//
//	certcheck [-roots PEM] [-at RFC3339] 文件...     每个文件都按 -at 指定的时刻校验（默认现在）
//	certcheck [-roots PEM] -stdin                    从标准输入逐行读 "文件<TAB>RFC3339 时刻[<TAB>noleaf]"，每行校验一次；
//	                                                 第三列为 noleaf 时不输出叶子的描述（同一文件只需要描述一次，m_mitm.py 第二次起都带它）
//	certcheck -gen 目录 [-at RFC3339] [-host 主机名]  自检用：在目录下生成合成根证书 roots.pem 和几条证书链，
//	                                                 布局与 evidence/ 相同；只给 m_mitm.py --selftest 用
//
// 输出是 JSON 行：第一行 {"k":"roots",...} 说明用的根证书文件（sha256、证书数、Go 版本），
// 之后每个输入一行 {"k":"cert",...}：文件哈希、证书数、叶子的 SAN/CN/组织名/签发者/是否自签/有效期、
// 文件里全部证书的有效期边界（bounds）、校验结果和错误类别；校验通过时还给出所建的全部链上（含根证书库里的根）
// 最早的 NotAfter（verify.chains_not_after）。Python 侧靠这两样判断“按最早一次尝试的时刻校验的结果能不能代表这个文件的全部尝试”。
// -gen 模式输出一行 {"k":"gen",...}，列出每条链的哈希和含义。
//
// 校验口径（verify() 的注释里逐条对应）：
//
//	x509.Certificate.Verify，Roots = -roots 的全部证书，Intermediates = 文件里叶子之后的证书，
//	CurrentTime = 给定时刻，DNSName 为空（不看主机名），KeyUsages 取默认（ExtKeyUsageServerAuth）。
//	错误类别：ok / expired / not_yet_valid / expired_intermediate / self_signed / unknown_authority_leaf_only /
//	unknown_authority / invalid_<原因名> / parse_error / read_error / other。
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// rootsInfo 是第一行输出：根证书文件的身份。报告里要写明用的是哪一版 Mozilla 根库，
// 版本号由 Python 侧从包管理器取，这里给出文件哈希和证书数供对照。
type rootsInfo struct {
	K         string `json:"k"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Certs     int    `json:"certs"`
	GoVersion string `json:"go_version"`
	// 这一版支持的输出与输入：m_mitm.py 靠它拒绝旧版二进制（旧版不认第三列 noleaf，也不给 bounds，会把结果悄悄算错）
	Features []string `json:"features"`
	Err      string   `json:"err,omitempty"`
}

// features 是 rootsInfo.Features 的值。
var features = []string{"noleaf", "bounds", "chains_not_after"}

// leafInfo 是叶子证书（文件里的第一张）的描述。
type leafInfo struct {
	SHA256      string   `json:"sha256"`
	CN          string   `json:"cn"`
	SANDNS      []string `json:"san_dns"`
	SANIP       []string `json:"san_ip"`
	SubjectOrg  []string `json:"subject_org"`
	IssuerCN    string   `json:"issuer_cn"`
	IssuerOrg   []string `json:"issuer_org"`
	SelfSigned  bool     `json:"self_signed"` // RawSubject == RawIssuer，与 wire.go describe() 同口径
	IsCA        bool     `json:"is_ca"`
	NotBefore   string   `json:"not_before"`
	NotAfter    string   `json:"not_after"`
	SigAlg      string   `json:"sig_alg"`
	PublicKey   string   `json:"public_key"`
	SerialBytes int      `json:"serial_bytes"`
}

// verifyInfo 是一次校验的结果。
type verifyInfo struct {
	OK       bool   `json:"ok"`
	ErrClass string `json:"err_class"`
	Err      string `json:"err,omitempty"` // Go 错误原文，最多 200 字符；只给 Python 看，不进输出
	ChainLen int    `json:"chain_len,omitempty"`
	RootCN   string `json:"root_cn,omitempty"`  // 校验通过时链末尾那张根证书的 CN（来自公共根库，可公开）
	RootOrg  string `json:"root_org,omitempty"` // 同上，组织名
	// 校验通过时，Verify 返回的全部链上全部证书（含根证书库里的根）NotAfter 的最小值。
	// 返回的链在给定时刻都有效（NotBefore 都不晚于它），所以“通过”这个结果至少保持到这一刻；
	// 根证书库里的根不在 bounds 里，靠这一项补上。
	ChainsNotAfter string `json:"chains_not_after,omitempty"`
}

// certLine 是每个输入一行的输出。
type certLine struct {
	K              string    `json:"k"`
	File           string    `json:"file"`
	At             string    `json:"at"`
	FileSHA256     string    `json:"file_sha256,omitempty"`
	Bytes          int       `json:"bytes"`
	NCerts         int       `json:"n_certs"`
	ParseError     string    `json:"parse_error,omitempty"`
	ReadError      string    `json:"read_error,omitempty"`
	Leaf           *leafInfo `json:"leaf,omitempty"`
	ChainNotBefore string    `json:"chain_not_before,omitempty"` // 文件里全部证书 NotBefore 的最大值
	ChainNotAfter  string    `json:"chain_not_after,omitempty"`  // 文件里全部证书 NotAfter 的最小值
	// 文件里全部证书的 NotBefore 和 NotAfter（去重、升序，RFC 3339）。x509 校验结果只通过有效期随时刻变化，
	// 所以两个时刻之间没有任何边界、两端结果又相同时，中间任一时刻的结果都相同。
	Bounds []string    `json:"bounds,omitempty"`
	Verify *verifyInfo `json:"verify,omitempty"`
}

var invalidReasonNames = map[x509.InvalidReason]string{
	x509.NotAuthorizedToSign:           "NotAuthorizedToSign",
	x509.Expired:                       "Expired",
	x509.CANotAuthorizedForThisName:    "CANotAuthorizedForThisName",
	x509.TooManyIntermediates:          "TooManyIntermediates",
	x509.IncompatibleUsage:             "IncompatibleUsage",
	x509.NameMismatch:                  "NameMismatch",
	x509.NameConstraintsWithoutSANs:    "NameConstraintsWithoutSANs",
	x509.UnconstrainedName:             "UnconstrainedName",
	x509.TooManyConstraints:            "TooManyConstraints",
	x509.CANotAuthorizedForExtKeyUsage: "CANotAuthorizedForExtKeyUsage",
	x509.NoValidChains:                 "NoValidChains",
}

func main() {
	rootsPath := flag.String("roots", "/etc/ssl/certs/ca-certificates.crt", "公共根证书的 PEM 文件（Debian/Ubuntu 的 ca-certificates 包，Mozilla 根库的打包）")
	atStr := flag.String("at", "", "校验时刻，RFC 3339；空表示现在。-stdin 模式下每行自带时刻，这个值只作缺省")
	useStdin := flag.Bool("stdin", false, "从标准输入读 \"文件<TAB>时刻\" 行")
	genDir := flag.String("gen", "", "自检：在该目录生成合成根证书与证书链，然后退出")
	genHost := flag.String("host", "judge.selftest.invalid", "-gen 用：合成的“judge 主机名”")
	flag.Parse()

	at := time.Now().UTC()
	if *atStr != "" {
		t, err := time.Parse(time.RFC3339Nano, *atStr)
		if err != nil {
			fatal("解析 -at 失败: %v", err)
		}
		at = t.UTC()
	}
	if *genDir != "" {
		if err := gen(*genDir, *genHost, at); err != nil {
			fatal("生成失败: %v", err)
		}
		return
	}

	roots, info := loadRoots(*rootsPath)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(info)
	if roots == nil {
		os.Exit(2)
	}

	if *useStdin {
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			line := strings.TrimRight(sc.Text(), "\r\n")
			if line == "" {
				continue
			}
			fields := strings.Split(line, "\t")
			path, when, noLeaf := fields[0], at, false
			if len(fields) > 1 {
				if ts := strings.TrimSpace(fields[1]); ts != "" {
					t, err := time.Parse(time.RFC3339Nano, ts)
					if err != nil {
						_ = enc.Encode(certLine{K: "cert", File: path, At: ts, ReadError: "bad time: " + err.Error()})
						continue
					}
					when = t.UTC()
				}
			}
			if len(fields) > 2 && strings.TrimSpace(fields[2]) == "noleaf" {
				noLeaf = true
			}
			cl := check(path, when, roots)
			if noLeaf {
				cl.Leaf = nil
			}
			_ = enc.Encode(cl)
		}
		if err := sc.Err(); err != nil {
			fatal("读标准输入失败: %v", err)
		}
		return
	}
	for _, p := range flag.Args() {
		_ = enc.Encode(check(p, at, roots))
	}
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(2)
}

// loadRoots 读 PEM 文件里的全部证书作为根。文件哈希和证书数写进第一行输出。
func loadRoots(path string) (*x509.CertPool, rootsInfo) {
	info := rootsInfo{K: "roots", Path: path, GoVersion: runtime.Version(), Features: features}
	data, err := os.ReadFile(path)
	if err != nil {
		info.Err = err.Error()
		return nil, info
	}
	sum := sha256.Sum256(data)
	info.SHA256 = hex.EncodeToString(sum[:])
	pool := x509.NewCertPool()
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue // 根库里偶有解析不了的旧证书，跳过并少计一张
		}
		pool.AddCert(c)
		info.Certs++
	}
	if info.Certs == 0 {
		info.Err = "no certificates in roots file"
		return nil, info
	}
	return pool, info
}

// check 读一个 DER 串接文件，描述叶子，并按给定时刻校验。
func check(path string, at time.Time, roots *x509.CertPool) certLine {
	line := certLine{K: "cert", File: path, At: at.Format(time.RFC3339Nano)}
	data, err := os.ReadFile(path)
	if err != nil {
		line.ReadError = err.Error()
		return line
	}
	sum := sha256.Sum256(data)
	line.FileSHA256 = hex.EncodeToString(sum[:])
	line.Bytes = len(data)
	certs, perr := x509.ParseCertificates(data)
	line.NCerts = len(certs)
	if perr != nil {
		// Put() 最多存 32 KB（attempt.go：e.Ev.Put(a.Cand, "der", chain, 32<<10)），超长的链会被截断，
		// 这时前面完整的证书仍能解析，最后一张解析失败。能解析出叶子就继续，并记下错误。
		line.ParseError = trim(perr.Error(), 200)
		if len(certs) == 0 {
			// ParseCertificates 遇到错误时不返回已解析的部分，这里自己按张切
			certs = parsePrefix(data)
			line.NCerts = len(certs)
		}
	}
	if len(certs) == 0 {
		return line
	}
	leaf := certs[0]
	line.Leaf = describe(leaf)
	nb, na := leaf.NotBefore, leaf.NotAfter
	for _, c := range certs[1:] {
		if c.NotBefore.After(nb) {
			nb = c.NotBefore
		}
		if c.NotAfter.Before(na) {
			na = c.NotAfter
		}
	}
	line.ChainNotBefore = nb.UTC().Format(time.RFC3339)
	line.ChainNotAfter = na.UTC().Format(time.RFC3339)
	line.Bounds = bounds(certs)
	line.Verify = verify(leaf, certs[1:], roots, at)
	return line
}

// bounds 返回证书的全部有效期边界（NotBefore、NotAfter），去重、升序。
func bounds(certs []*x509.Certificate) []string {
	var ts []time.Time
	for _, c := range certs {
		ts = append(ts, c.NotBefore.UTC(), c.NotAfter.UTC())
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
	var out []string
	for i, t := range ts {
		if i > 0 && t.Equal(ts[i-1]) {
			continue
		}
		out = append(out, t.Format(time.RFC3339Nano))
	}
	return out
}

// parsePrefix 逐张解析 DER 串接，遇到解析不了的就停：截断的文件只取完整的前几张。
func parsePrefix(data []byte) []*x509.Certificate {
	var out []*x509.Certificate
	for len(data) > 0 {
		n := derLen(data)
		if n <= 0 || n > len(data) {
			break
		}
		c, err := x509.ParseCertificate(data[:n])
		if err != nil {
			break
		}
		out = append(out, c)
		data = data[n:]
	}
	return out
}

// derLen 返回开头那个 DER SEQUENCE 的总长度（含头），解析不了返回 0。
func derLen(b []byte) int {
	if len(b) < 2 || b[0] != 0x30 {
		return 0
	}
	l := int(b[1])
	if l < 0x80 {
		return 2 + l
	}
	k := l & 0x7f
	if k == 0 || k > 4 || len(b) < 2+k {
		return 0
	}
	n := 0
	for i := 0; i < k; i++ {
		n = n<<8 | int(b[2+i])
	}
	return 2 + k + n
}

func describe(c *x509.Certificate) *leafInfo {
	sum := sha256.Sum256(c.Raw)
	li := &leafInfo{
		SHA256:      hex.EncodeToString(sum[:]),
		CN:          c.Subject.CommonName,
		SANDNS:      c.DNSNames,
		SubjectOrg:  c.Subject.Organization,
		IssuerCN:    c.Issuer.CommonName,
		IssuerOrg:   c.Issuer.Organization,
		SelfSigned:  string(c.RawSubject) == string(c.RawIssuer),
		IsCA:        c.IsCA,
		NotBefore:   c.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:    c.NotAfter.UTC().Format(time.RFC3339),
		SigAlg:      c.SignatureAlgorithm.String(),
		PublicKey:   keyDesc(c),
		SerialBytes: len(c.SerialNumber.Bytes()),
	}
	for _, ip := range c.IPAddresses {
		li.SANIP = append(li.SANIP, ip.String())
	}
	if li.SANDNS == nil {
		li.SANDNS = []string{}
	}
	if li.SANIP == nil {
		li.SANIP = []string{}
	}
	if li.SubjectOrg == nil {
		li.SubjectOrg = []string{}
	}
	if li.IssuerOrg == nil {
		li.IssuerOrg = []string{}
	}
	return li
}

func keyDesc(c *x509.Certificate) string {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA-" + k.Curve.Params().Name
	default:
		return c.PublicKeyAlgorithm.String()
	}
}

// verify 按 PROTOCOL 1.2“被送到别的网站”的口径校验：公共根证书、给定时刻、不看主机名。
// 错误类别只用来给“去向不明”再分一层，不改变校验结果本身。
func verify(leaf *x509.Certificate, rest []*x509.Certificate, roots *x509.CertPool, at time.Time) *verifyInfo {
	inter := x509.NewCertPool()
	for _, c := range rest {
		inter.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: at})
	v := &verifyInfo{}
	if err == nil {
		v.OK, v.ErrClass = true, "ok"
		if len(chains) > 0 {
			ch := chains[0]
			v.ChainLen = len(ch)
			root := ch[len(ch)-1]
			v.RootCN = root.Subject.CommonName
			v.RootOrg = strings.Join(root.Subject.Organization, " / ")
			var minNA time.Time
			for _, c := range chains {
				for _, x := range c {
					if minNA.IsZero() || x.NotAfter.Before(minNA) {
						minNA = x.NotAfter
					}
				}
			}
			v.ChainsNotAfter = minNA.UTC().Format(time.RFC3339Nano)
		}
		return v
	}
	v.Err = trim(err.Error(), 200)
	var ie x509.CertificateInvalidError
	var ua x509.UnknownAuthorityError
	switch {
	case errors.As(err, &ie):
		switch ie.Reason {
		case x509.Expired:
			switch {
			case ie.Cert != nil && string(ie.Cert.Raw) != string(leaf.Raw):
				v.ErrClass = "expired_intermediate" // 叶子在有效期内，链上别的证书不在
			case at.Before(leaf.NotBefore):
				v.ErrClass = "not_yet_valid"
			default:
				v.ErrClass = "expired"
			}
		default:
			name := invalidReasonNames[ie.Reason]
			if name == "" {
				name = fmt.Sprintf("%d", int(ie.Reason))
			}
			v.ErrClass = "invalid_" + name
		}
	case errors.As(err, &ua):
		switch {
		case string(leaf.RawSubject) == string(leaf.RawIssuer):
			v.ErrClass = "self_signed" // 自签：签发者就是自己，公共根库里自然没有
		case len(rest) == 0:
			v.ErrClass = "unknown_authority_leaf_only" // 只发了叶子：可能是私有 CA，也可能是没发中间证书，离线分不出
		default:
			v.ErrClass = "unknown_authority" // 发了链，但链顶不在公共根库里
		}
	default:
		v.ErrClass = "other"
	}
	return v
}

func trim(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ---------------------------------------------------------------- 自检用的合成证书

// gen 在 dir 下生成 roots.pem（一张合成根）和若干证书链文件（evidence/<前两位>/<sha256>.der），
// 覆盖 m_mitm.py 三层细分的各条路径。有效期以 at 为基准，这样自检的时间点可以固定。
// 输出一行 JSON：{"k":"gen","host":...,"at":...,"roots":"...","chains":{名字:{"hash":..., "meaning":...}}}。
func gen(dir, host string, at time.Time) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	day := 24 * time.Hour
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic Test Root", Organization: []string{"Synthetic Roots"}},
		NotBefore: at.Add(-365 * day), NotAfter: at.Add(365 * day), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return err
	}
	rootCert, _ := x509.ParseCertificate(rootDER)
	rootsPath := filepath.Join(dir, "roots.pem")
	if err := os.WriteFile(rootsPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0o644); err != nil {
		return err
	}

	interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	interTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Synthetic Test Intermediate", Organization: []string{"Synthetic Roots"}},
		NotBefore: at.Add(-300 * day), NotAfter: at.Add(300 * day), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTpl, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		return err
	}
	interCert, _ := x509.ParseCertificate(interDER)

	type spec struct {
		name    string
		meaning string
		cn      string
		dns     []string
		org     string
		nb, na  time.Time
		signer  *x509.Certificate // nil = 自签
		skey    any
		include []byte // 附在叶子后面的中间证书
	}
	specs := []spec{
		{name: "judge_selfsigned", meaning: "自签、SAN 是 judge 主机名、在有效期内：detail=unknown_authority → 冒充 judge；公共根校验不过（self_signed）",
			cn: host, dns: []string{host}, org: "Synthetic MITM", nb: at.Add(-day), na: at.Add(day)},
		{name: "judge_expired", meaning: "自签、SAN 是 judge 主机名、已过期：detail=invalid_1，靠存下的叶子 SAN 判为冒充 judge",
			cn: host, dns: []string{host}, org: "Synthetic MITM", nb: at.Add(-10 * day), na: at.Add(-5 * day)},
		{name: "wildcard_expired", meaning: "自签、SAN 是通配符且覆盖 judge 主机名、已过期：靠通配符匹配判为冒充 judge",
			cn: "*." + parentDomain(host), dns: []string{"*." + parentDomain(host)}, org: "Synthetic MITM", nb: at.Add(-10 * day), na: at.Add(-5 * day)},
		{name: "other_valid_chain", meaning: "别的网站的证书，由合成中间证书签发，文件含中间证书，在有效期内：校验通过 → 被送到别的网站",
			cn: "other.example", dns: []string{"other.example", "www.other.example"}, org: "Other Site Ltd", nb: at.Add(-day), na: at.Add(day),
			signer: interCert, skey: interKey, include: interDER},
		{name: "other_selfsigned", meaning: "别的名字、自签：校验不过（self_signed）→ 去向不明",
			cn: "other2.example", dns: []string{"other2.example"}, org: "Other2", nb: at.Add(-day), na: at.Add(day)},
		{name: "other_expired_then_valid", meaning: "别的名字、根直接签发、有效期 [at-2d, at-1d]：在 at 校验过期（去向不明），在 at-36h 校验通过（别的网站）；用来测按时刻校验",
			cn: "other3.example", dns: []string{"other3.example"}, org: "Other3", nb: at.Add(-2 * day), na: at.Add(-day),
			signer: rootCert, skey: rootKey},
		{name: "other_leaf_only", meaning: "别的名字、由中间证书签发但文件里没有中间证书：unknown_authority_leaf_only → 去向不明",
			cn: "other4.example", dns: []string{"other4.example"}, org: "Other4", nb: at.Add(-day), na: at.Add(day),
			signer: interCert, skey: interKey},
		{name: "other_no_san", meaning: "别的名字、没有 SAN 只有 CN、自签：名字看 CN → 去向不明",
			cn: "other5.example", org: "Other5", nb: at.Add(-day), na: at.Add(day)},
	}
	chains := map[string]map[string]string{}
	for i, s := range specs {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(int64(100 + i)), Subject: pkix.Name{CommonName: s.cn, Organization: []string{s.org}},
			DNSNames: s.dns, NotBefore: s.nb, NotAfter: s.na,
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		parent, skey := tpl, any(key)
		if s.signer != nil {
			parent, skey = s.signer, s.skey
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, skey)
		if err != nil {
			return err
		}
		file := append(append([]byte{}, der...), s.include...)
		sum := sha256.Sum256(file)
		h := hex.EncodeToString(sum[:])
		sub := filepath.Join(dir, "evidence", h[:2])
		if err := os.MkdirAll(sub, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(sub, h+".der"), file, 0o644); err != nil {
			return err
		}
		leafSum := sha256.Sum256(der)
		chains[s.name] = map[string]string{"hash": h, "leaf": hex.EncodeToString(leafSum[:]), "meaning": s.meaning,
			"path": filepath.Join("evidence", h[:2], h+".der")}
	}
	// 一个解析不了的文件：覆盖 parse_error 路径
	junk := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	js := sha256.Sum256(junk)
	jh := hex.EncodeToString(js[:])
	if err := os.MkdirAll(filepath.Join(dir, "evidence", jh[:2]), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "evidence", jh[:2], jh+".der"), junk, 0o644); err != nil {
		return err
	}
	chains["junk"] = map[string]string{"hash": jh, "meaning": "不是证书的字节：parse_error", "path": filepath.Join("evidence", jh[:2], jh+".der")}

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	return enc.Encode(map[string]any{"k": "gen", "host": host, "at": at.Format(time.RFC3339), "roots": rootsPath, "chains": chains})
}

func parentDomain(host string) string {
	if i := strings.IndexByte(host, '.'); i >= 0 {
		return host[i+1:]
	}
	return host
}
