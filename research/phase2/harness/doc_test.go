package main

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
)

// EVENTS.md 与代码对得上：每种事件都有一节、节里提到了它的每一个字段、至少有一个例子，
// 例子是合法的事件（字段恰好是 eventFields 里的那些）。
func TestEventsDoc(t *testing.T) {
	data, err := os.ReadFile("EVENTS.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(data)
	sections := map[string]string{}
	parts := regexp.MustCompile(`(?m)^## `).Split(doc, -1)
	for _, p := range parts[1:] {
		title, body, _ := strings.Cut(p, "\n")
		sections[strings.TrimSpace(title)] = body
	}
	examples := map[string]int{}
	for name, fields := range eventFields {
		body, ok := sections[name]
		if !ok {
			t.Errorf("EVENTS.md 没有 %q 这一节", name)
			continue
		}
		for _, f := range fields {
			if !strings.Contains(body, "`"+f+"`") {
				t.Errorf("EVENTS.md 的 %s 一节没有提到字段 %q", name, f)
			}
		}
		var sub []string
		switch name {
		case "http_request":
			sub = authFields
		case "tunnel_first_bytes":
			sub = tlsFields
		}
		for _, f := range sub {
			if !strings.Contains(body, "`"+f+"`") {
				t.Errorf("EVENTS.md 的 %s 一节没有提到嵌套字段 %q", name, f)
			}
		}
		for _, m := range regexp.MustCompile("(?s)```json\n(.*?)\n```").FindAllStringSubmatch(body, -1) {
			var ev event
			if err := json.Unmarshal([]byte(m[1]), &ev); err != nil {
				t.Errorf("EVENTS.md 的 %s 一节里的例子不是合法的 JSON: %v", name, err)
				continue
			}
			if ev.str("ev") != name {
				t.Errorf("EVENTS.md 的 %s 一节里有一个 %q 的例子", name, ev.str("ev"))
			}
			checkFields(t, "EVENTS.md 的例子", ev)
			examples[name]++
		}
		if examples[name] == 0 {
			t.Errorf("EVENTS.md 的 %s 一节没有例子", name)
		}
	}
	for name := range knownEvents {
		if _, ok := eventFields[name]; !ok {
			t.Errorf("eventFields 里没有 %q", name)
		}
	}
}
