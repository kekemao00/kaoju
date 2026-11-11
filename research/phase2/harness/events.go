package main

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"sync"
	"time"
)

// kv 是事件里的一个字段。事件用有序的字段列表而不是 map，
// 这样写出来的 JSON 字段顺序固定（t、ev、conn 在前），人读和 diff 都方便。
type kv struct {
	K string
	V any
}

// obj 是保持字段顺序的 JSON 对象。
type obj []kv

// MarshalJSON 按字段出现的顺序输出；值不做 HTML 转义（& < > 原样），方便直接读。
func (o obj) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, f := range o {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, err := marshalPlain(f.K)
		if err != nil {
			return nil, err
		}
		b.Write(kb)
		b.WriteByte(':')
		vb, err := marshalPlain(f.V)
		if err != nil {
			return nil, err
		}
		b.Write(vb)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// marshalPlain 是不做 HTML 转义的 json.Marshal。
func marshalPlain(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}

// eventLog 把事件写成 JSONL。每个事件一次 Write 写完整行，写完即落到文件描述符上（不经用户态缓冲）。
type eventLog struct {
	mu     sync.Mutex
	w      io.Writer
	start  time.Time
	n      int64
	closed bool
	err    error
}

func newEventLog(w io.Writer) *eventLog {
	return &eventLog{w: w, start: time.Now()}
}

// now 返回启动以来的毫秒数，保留到微秒。
func (l *eventLog) now() float64 {
	return math.Round(float64(time.Since(l.start).Microseconds())) / 1000
}

// emit 写一个事件。t 在持锁时取，所以文件里的 t 单调不减。
func (l *eventLog) emit(ev string, fields ...kv) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.emitLocked(ev, fields)
}

func (l *eventLog) emitLocked(ev string, fields []kv) {
	if l.closed {
		return
	}
	o := make(obj, 0, len(fields)+2)
	o = append(o, kv{"t", l.now()}, kv{"ev", ev})
	o = append(o, fields...)
	b, err := marshalPlain(o)
	if err != nil {
		// 不应该发生；发生了也要留下痕迹，不能悄悄丢事件。
		b, _ = marshalPlain(obj{{"t", l.now()}, {"ev", "log_error"}, {"of", ev}, {"error", err.Error()}})
	}
	b = append(b, '\n')
	if _, err := l.w.Write(b); err != nil && l.err == nil {
		l.err = err
	}
	l.n++
}

// finish 写最后一个事件并封口：之后的 emit 一律丢弃，保证 end 是文件的最后一行。
// count 字段由 finish 填入（含 end 自己）。
func (l *eventLog) finish(ev string, fields ...kv) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	fields = append(fields, kv{"events", l.n + 1})
	l.emitLocked(ev, fields)
	l.closed = true
}

func (l *eventLog) writeErr() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.err
}
