// Package payload 定义 judge 返回的固定载荷。
//
// 载荷只由 judge 的主机名决定，所以探测器不联网就知道期望的 SHA-256，第三方也能自己算出来核对。
// 每次请求的 URL 不同（带 nonce），内容相同；缓存代理因此不会命中，内容被改也一定能发现。
package payload

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
)

// Kind 是 URL 里的一个字母：h = HTML，j = JavaScript，b = 二进制。
type Kind string

const (
	HTML Kind = "h"
	JS   Kind = "j"
	Bin  Kind = "b"
)

type Payload struct {
	Kind        Kind
	ContentType string
	Body        []byte
	SHA256      string
}

type Set struct {
	Host string
	m    map[Kind]*Payload
}

// Build 生成针对某个 judge 主机名的全部载荷。
func Build(host string) *Set {
	s := &Set{Host: host, m: map[Kind]*Payload{}}
	add := func(k Kind, ct string, body []byte) {
		sum := sha256.Sum256(body)
		s.m[k] = &Payload{Kind: k, ContentType: ct, Body: body, SHA256: hex.EncodeToString(sum[:])}
	}
	add(HTML, "text/html; charset=utf-8", []byte(strings.ReplaceAll(htmlTemplate, "{{HOST}}", host)))
	add(JS, "application/javascript; charset=utf-8", []byte(jsBody))
	add(Bin, "application/octet-stream", binBody(32*1024))
	return s
}

func (s *Set) Get(k Kind) *Payload { return s.m[k] }

// Kinds 返回全部种类，顺序固定。
func Kinds() []Kind { return []Kind{HTML, JS, Bin} }

// binBody 用 SHA-256 计数器模式从固定种子生成伪随机字节：不可压缩，任何截断或转码都会改变哈希。
func binBody(n int) []byte {
	out := make([]byte, 0, n+32)
	var ctr [8]byte
	for i := uint64(0); len(out) < n; i++ {
		binary.BigEndian.PutUint64(ctr[:], i)
		h := sha256.Sum256(append([]byte("fieldtest-bin-v1:"), ctr[:]...))
		out = append(out, h[:]...)
	}
	return out[:n]
}

// htmlTemplate 是一张诱饵页面。结构参照 Tsirantonakis 等（NDSS 2018）的 honeysite：
// 普通的页面骨架、脚本、表单、iframe，以及仿照常见广告网络写法、发布者 ID 无效的广告位。
// 注入脚本的代理通常找 </head> 或 </body>，换广告 ID 的代理找 ca-pub- 这类标记。
// 页面里有 8 个指向 judge 自己的 https 链接，用来发现把 https 改写成 http 的代理（SSL 剥离）。
const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Harbor Notes: Weekly Reading List</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="A short weekly list of long reads about ports, ships and the people who work on them.">
<link rel="stylesheet" href="https://{{HOST}}/s/site.css">
<script src="https://{{HOST}}/s/app.js" defer></script>
</head>
<body>
<header>
<h1>Harbor Notes</h1>
<nav>
<a href="https://{{HOST}}/">Home</a>
<a href="https://{{HOST}}/archive">Archive</a>
<a href="https://{{HOST}}/about">About</a>
<a href="https://{{HOST}}/subscribe">Subscribe</a>
<a href="https://{{HOST}}/account">Account</a>
<a href="https://{{HOST}}/contact">Contact</a>
</nav>
</header>
<main>
<article>
<h2>This week: tides, cranes and paperwork</h2>
<p>Every container that crosses a quay is counted at least four times: once by the ship, once by the crane,
once by the gate and once by customs. The counts rarely agree on the first try. This week's reading list is
about the people who reconcile them.</p>
<p>Start with the harbour pilot who has guided ships through the same channel for thirty-one years and still
checks the tide table by hand. Then read about the clerk who found a missing shipment by comparing two
ledgers nobody else had thought to put side by side.</p>
<ul>
<li>The pilot and the tide table</li>
<li>Two ledgers, one missing shipment</li>
<li>Why the night shift trusts the old crane</li>
<li>A short history of the bill of lading</li>
</ul>
<p>If you only have ten minutes, read the second one. It is a good reminder that a record is only as useful as
the second record you can check it against.</p>
</article>
<aside>
<h3>Members</h3>
<form action="https://{{HOST}}/account/login" method="post">
<label>Email <input type="email" name="email" autocomplete="username"></label>
<label>Password <input type="password" name="password" autocomplete="current-password"></label>
<button type="submit">Sign in</button>
</form>
<ins class="adsbygoogle" style="display:block" data-ad-client="ca-pub-0000000000000000" data-ad-slot="0000000000" data-ad-format="auto"></ins>
<script>(adsbygoogle = window.adsbygoogle || []).push({});</script>
<div id="bsa-zone_0000000000000-0_123456"></div>
<script id="mNCC" language="javascript">
medianet_width = "300";
medianet_height = "250";
medianet_crid = "000000000";
medianet_versionId = "3111299";
</script>
<iframe src="https://{{HOST}}/s/frame.html" width="300" height="250" title="notice"></iframe>
</aside>
</main>
<footer>
<p>Harbor Notes is a measurement decoy. It carries no advertising and sets no tracking cookies.</p>
</footer>
</body>
</html>
`

const jsBody = `/* Harbor Notes: small page helpers */
(function () {
  "use strict";

  function ready(fn) {
    if (document.readyState !== "loading") {
      fn();
    } else {
      document.addEventListener("DOMContentLoaded", fn);
    }
  }

  function formatDate(d) {
    var months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    return d.getDate() + " " + months[d.getMonth()] + " " + d.getFullYear();
  }

  function markCurrent(nav) {
    var links = nav.querySelectorAll("a");
    for (var i = 0; i < links.length; i++) {
      if (links[i].href === window.location.href) {
        links[i].setAttribute("aria-current", "page");
      }
    }
  }

  function validate(form) {
    form.addEventListener("submit", function (ev) {
      var email = form.querySelector("input[type=email]");
      if (!email || email.value.indexOf("@") < 1) {
        ev.preventDefault();
        email.focus();
      }
    });
  }

  ready(function () {
    var nav = document.querySelector("nav");
    if (nav) {
      markCurrent(nav);
    }
    var form = document.querySelector("form");
    if (form) {
      validate(form);
    }
    var foot = document.querySelector("footer p");
    if (foot) {
      foot.setAttribute("data-rendered", formatDate(new Date()));
    }
  });
})();
`

// 以下是页面引用的静态子资源，只有真人用浏览器打开 judge 时才会被请求。
const (
	StaticCSS   = "body{font-family:system-ui,sans-serif;max-width:46rem;margin:2rem auto;padding:0 1rem;line-height:1.6}nav a{margin-right:1rem}aside{border-top:1px solid #ccc;margin-top:2rem;padding-top:1rem}\n"
	StaticFrame = "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>notice</title></head><body><p>No advertising here.</p></body></html>\n"
)

// StaticJS 返回 /s/app.js 的内容，与 JS 载荷相同。
func StaticJS() string { return jsBody }
