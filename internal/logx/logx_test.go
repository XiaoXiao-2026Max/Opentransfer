package logx

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

func captureLogs(t *testing.T, run func()) string {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "logs-*")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	mu.Lock()
	previousOut, previousLevel := out, minLevel
	out, minLevel = file, LevelInfo
	mu.Unlock()
	defer func() {
		mu.Lock()
		out, minLevel = previousOut, previousLevel
		mu.Unlock()
	}()

	run()
	data, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestLogFormat(t *testing.T) {
	before := time.Now().Truncate(time.Second)
	output := captureLogs(t, func() {
		SetLevel("debug")
		logger := New("transfer")
		logger.Debugf("调试")
		logger.Infof("用户%d加入房间，转服准备就绪", 313413415)
		logger.Warnf("警告")
		logger.Errorf("失败")
	})
	after := time.Now().Truncate(time.Second)
	lines := strings.Split(strings.TrimSuffix(output, "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("got %d lines: %q", len(lines), output)
	}

	pattern := regexp.MustCompile(`^\[(DEBUG|INFO|WARN|ERROR) (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] (.*)$`)
	wantTags := []string{"DEBUG", "INFO", "WARN", "ERROR"}
	wantMessages := []string{"调试", "用户313413415加入房间，转服准备就绪", "警告", "失败"}
	for i, line := range lines {
		parts := pattern.FindStringSubmatch(line)
		if parts == nil {
			t.Fatalf("unexpected log format: %q", line)
		}
		if parts[1] != wantTags[i] || parts[3] != wantMessages[i] {
			t.Errorf("unexpected log line: %q", line)
		}
		stamp, err := time.ParseInLocation("2006-01-02 15:04:05", parts[2], time.Local)
		if err != nil || stamp.Before(before) || stamp.After(after) {
			t.Errorf("timestamp %q is outside the runtime interval", parts[2])
		}
	}
}

func TestSetLevelFiltersMessages(t *testing.T) {
	for _, tc := range []struct {
		name string
		want []string
	}{
		{" DEBUG ", []string{"DEBUG", "INFO", "WARN", "ERROR"}},
		{"info", []string{"INFO", "WARN", "ERROR"}},
		{"warn", []string{"WARN", "ERROR"}},
		{"warning", []string{"WARN", "ERROR"}},
		{"error", []string{"ERROR"}},
		{"unknown", []string{"INFO", "WARN", "ERROR"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := captureLogs(t, func() {
				SetLevel(tc.name)
				logger := New("test")
				logger.Debugf("debug")
				logger.Infof("info")
				logger.Warnf("warn")
				logger.Errorf("error")
			})
			lines := strings.Split(strings.TrimSuffix(output, "\n"), "\n")
			if len(lines) != len(tc.want) {
				t.Fatalf("got %d lines, want %d: %q", len(lines), len(tc.want), output)
			}
			for i, tag := range tc.want {
				if !strings.HasPrefix(lines[i], "["+tag+" ") {
					t.Errorf("line %d has wrong level: %q", i, lines[i])
				}
			}
		})
	}
}
