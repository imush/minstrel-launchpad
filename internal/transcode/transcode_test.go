package transcode

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLossless(t *testing.T) {
	for ct, want := range map[string]bool{
		"audio/x-flac": true, "audio/flac": true, "audio/wav": true, "audio/x-aiff": true, "audio/x-dsf": true,
		"audio/mpeg": false, "audio/mp4": false, "audio/aac": false, "audio/ogg": false, "audio/L16;rate=44100": false,
		"text/xml": false, "": false,
	} {
		if Lossless(ct) != want {
			t.Errorf("Lossless(%q) != %v", ct, want)
		}
	}
	if kbps, ok := Bitrate("aac-256"); !ok || kbps != 256 {
		t.Errorf("Bitrate(aac-256) = %d %v", kbps, ok)
	}
	for _, bad := range []string{"aac-1000", "mp3-192", "aac", ""} {
		if _, ok := Bitrate(bad); ok {
			t.Errorf("Bitrate(%q) accepted", bad)
		}
	}
}

func TestTrimKeepsRecentWithinSize(t *testing.T) {
	dir := t.TempDir()
	tr := &Transcoder{dir: dir, log: slog.New(slog.DiscardHandler), MaxBytes: 25, MaxAge: time.Hour}
	now := time.Now()
	write := func(name string, size int, age time.Duration) {
		p := filepath.Join(dir, name)
		_ = os.WriteFile(p, make([]byte, size), 0o600)
		_ = os.Chtimes(p, now.Add(-age), now.Add(-age))
	}
	write("old.aac", 10, 2*time.Hour)   // too old
	write("a.aac", 10, 30*time.Minute)  // least recently used: over the size
	write("b.aac", 10, 20*time.Minute)  // kept
	write("c.aac", 10, time.Minute)     // kept
	write("partial-1", 10, 2*time.Hour) // left by a crash
	write("partial-2", 10, time.Minute) // in progress
	tr.trim()
	var left []string
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		left = append(left, e.Name())
	}
	want := []string{"b.aac", "c.aac", "partial-2"}
	if len(left) != len(want) || left[0] != want[0] || left[1] != want[1] || left[2] != want[2] {
		t.Errorf("left %v, want %v", left, want)
	}
}
