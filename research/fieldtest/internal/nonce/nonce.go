// Package nonce 生成和校验探测用的一次性标识。
//
// 每次探测请求的 URL 里带一个 nonce。judge 不保存状态也能判断它是不是探测器发出的，
// 并从中读出签发时间，于是日志里可以区分三类请求：探测请求、迟到或重复的探测请求（重放）、无关的扫描流量。
//
// 结构：4 字节签发时间（Unix 秒）+ 4 字节随机数 + 4 字节 HMAC-SHA256 截断，base32 小写编码成 20 个字符。
package nonce

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"time"
)

const Len = 20

var enc = base32.StdEncoding.WithPadding(base32.NoPadding)

// New 签发一个 nonce。
func New(secret []byte, now time.Time) string {
	var b [12]byte
	binary.BigEndian.PutUint32(b[0:4], uint32(now.Unix()))
	if _, err := rand.Read(b[4:8]); err != nil {
		panic(err) // 系统随机源不可用时无法继续
	}
	copy(b[8:12], mac(secret, b[0:8])[:4])
	return strings.ToLower(enc.EncodeToString(b[:]))
}

// Verify 校验 nonce，返回签发时间。
func Verify(secret []byte, s string) (time.Time, bool) {
	if len(s) != Len {
		return time.Time{}, false
	}
	b, err := enc.DecodeString(strings.ToUpper(s))
	if err != nil || len(b) != 12 {
		return time.Time{}, false
	}
	if !hmac.Equal(b[8:12], mac(secret, b[0:8])[:4]) {
		return time.Time{}, false
	}
	return time.Unix(int64(binary.BigEndian.Uint32(b[0:4])), 0).UTC(), true
}

// Canary 由 nonce 派生一个 16 位十六进制值。dir 区分方向："req" 是探测器放进请求头的，
// "resp" 是 judge 放进响应头的。两边各自算出期望值，对不上就说明头被改过，或者响应不是这次请求的。
func Canary(secret []byte, dir, n string) string {
	return hex.EncodeToString(mac(secret, []byte(dir+":"+n))[:8])
}

func mac(secret, msg []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write(msg)
	return h.Sum(nil)
}

// NewSecret 生成共享密钥。
func NewSecret() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
