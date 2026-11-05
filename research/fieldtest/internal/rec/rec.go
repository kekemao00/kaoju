// Package rec 负责原始记录落盘：按小时轮转的 JSONL 文件，只追加不修改；关闭的文件压缩成 gzip。
// 另有一个按内容寻址的证据库，存被篡改的响应体、伪造的证书链之类。
package rec

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Writer 是一个按 UTC 小时轮转的 JSONL 写入器，可以并发使用。
type Writer struct {
	dir, prefix string
	mu          sync.Mutex
	f           *os.File
	bw          *bufio.Writer
	hour        string
	stop        chan struct{}
	done        chan struct{}
	Now         func() time.Time
	Compress    bool
	n           int64
}

func NewWriter(dir, prefix string) (*Writer, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	w := &Writer{dir: dir, prefix: prefix, stop: make(chan struct{}), done: make(chan struct{}),
		Now: time.Now, Compress: true}
	go w.flusher()
	go w.compressStale()
	return w, nil
}

// compressStale 压缩以前的运行留下的、早于当前小时的未压缩文件。
func (w *Writer) compressStale() {
	cur := w.path(w.Now().UTC().Format("20060102-15"))
	m, _ := filepath.Glob(filepath.Join(w.dir, w.prefix+"-*.jsonl"))
	for _, p := range m {
		if p < cur {
			gzipFile(p)
		}
	}
}

func (w *Writer) flusher() {
	defer close(w.done)
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			w.Flush()
		case <-w.stop:
			return
		}
	}
}

func (w *Writer) path(hour string) string {
	return filepath.Join(w.dir, w.prefix+"-"+hour+".jsonl")
}

// Write 追加一条记录。
func (w *Writer) Write(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	hour := w.Now().UTC().Format("20060102-15")
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil || hour != w.hour {
		if err := w.rotateLocked(hour); err != nil {
			return err
		}
	}
	w.n++
	if _, err := w.bw.Write(b); err != nil {
		return err
	}
	return w.bw.WriteByte('\n')
}

func (w *Writer) rotateLocked(hour string) error {
	old := ""
	if w.f != nil {
		w.bw.Flush()
		w.f.Close()
		old = w.path(w.hour)
	}
	f, err := os.OpenFile(w.path(hour), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		w.f = nil
		return err
	}
	w.f, w.bw, w.hour = f, bufio.NewWriterSize(f, 256<<10), hour
	if old != "" && w.Compress {
		go gzipFile(old)
	}
	return nil
}

// Count 返回已写入的记录数。
func (w *Writer) Count() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.n
}

func (w *Writer) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.bw != nil {
		w.bw.Flush()
	}
}

func (w *Writer) Close() {
	select {
	case <-w.stop:
	default:
		close(w.stop)
		<-w.done
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f != nil {
		w.bw.Flush()
		w.f.Close()
		w.f = nil
	}
}

func gzipFile(path string) {
	in, err := os.Open(path)
	if err != nil {
		return
	}
	defer in.Close()
	tmp := path + ".gz.tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return
	}
	zw, _ := gzip.NewWriterLevel(out, gzip.BestCompression)
	_, err = io.Copy(zw, in)
	if e := zw.Close(); err == nil {
		err = e
	}
	if e := out.Close(); err == nil {
		err = e
	}
	if err != nil {
		os.Remove(tmp)
		return
	}
	if os.Rename(tmp, path+".gz") == nil {
		os.Remove(path)
	}
}

// Files 返回某个前缀的全部记录文件，按时间顺序。
// 同一个小时的文件在压缩完成的瞬间会同时有两份（.jsonl 和 .jsonl.gz），只取未压缩的那份，避免重复计数。
func Files(dir, prefix string) []string {
	plain, _ := filepath.Glob(filepath.Join(dir, prefix+"-*.jsonl"))
	zipped, _ := filepath.Glob(filepath.Join(dir, prefix+"-*.jsonl.gz"))
	have := map[string]bool{}
	out := append([]string{}, plain...)
	for _, p := range plain {
		have[p] = true
	}
	for _, z := range zipped {
		if !have[strings.TrimSuffix(z, ".gz")] {
			out = append(out, z)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.TrimSuffix(out[i], ".gz") < strings.TrimSuffix(out[j], ".gz")
	})
	return out
}

// Each 逐行读取某个前缀的全部记录。行可以很长（列表的首次快照），所以不用 bufio.Scanner。
func Each(dir, prefix string, fn func(line []byte)) error {
	for _, p := range Files(dir, prefix) {
		if err := eachFile(p, fn); err != nil {
			return err
		}
	}
	return nil
}

func eachFile(path string, fn func(line []byte)) error {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // 读取期间文件被压缩改名
		}
		return err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer zr.Close()
		r = zr
	}
	br := bufio.NewReaderSize(r, 1<<20)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 1 && line[len(line)-1] == '\n' {
			fn(line[:len(line)-1])
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil // 末尾没写完的一行直接丢弃
			}
			return err
		}
	}
}

// Evidence 是按内容寻址的证据库。同样的内容只存一份。
//
// 有两道上限，防止个别对端用每次都不同的垃圾内容把磁盘写满：每个来源（一个代理或节点）最多留 MaxPerOwner 份，
// 整个库最多 MaxBytes 字节。超限后哈希照常返回并记进日志，只是内容不再保存。
type Evidence struct {
	dir         string
	mu          sync.Mutex
	seen        map[string]bool
	perOwner    map[string]int
	bytes       int64
	MaxPerOwner int
	MaxBytes    int64
	Skipped     int64 // 因超限没有保存的份数
}

func NewEvidence(dir string) *Evidence {
	e := &Evidence{dir: dir, seen: map[string]bool{}, perOwner: map[string]int{}, MaxPerOwner: 12, MaxBytes: 1 << 30}
	// 以前的运行留下的证据也算在总量里
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			e.bytes += info.Size()
			e.seen[strings.SplitN(info.Name(), ".", 2)[0]] = true
		}
		return nil
	})
	return e
}

// Put 保存一份证据，返回它的 SHA-256。超过 max 字节的部分截掉，哈希按截断后的内容计算。
// owner 是这份证据来自哪个代理或节点。
func (e *Evidence) Put(owner, ext string, data []byte, max int) string {
	if e == nil || len(data) == 0 {
		return ""
	}
	if max > 0 && len(data) > max {
		data = data[:max]
	}
	sum := sha256.Sum256(data)
	h := hex.EncodeToString(sum[:])
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.seen[h] {
		return h
	}
	if e.perOwner[owner] >= e.MaxPerOwner || e.bytes+int64(len(data)) > e.MaxBytes {
		e.Skipped++
		return h
	}
	e.perOwner[owner]++
	e.bytes += int64(len(data))
	e.seen[h] = true
	dir := filepath.Join(e.dir, h[:2])
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return h
	}
	p := filepath.Join(dir, h+"."+ext)
	if _, err := os.Stat(p); err == nil {
		return h
	}
	_ = os.WriteFile(p, data, 0o644)
	return h
}

// TS 把时间格式化成记录里统一使用的形式（UTC，毫秒）。
func TS(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }
