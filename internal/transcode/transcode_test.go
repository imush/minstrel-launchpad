package transcode

import (
	"bytes"
	"errors"
	"io"
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

// fakeFFmpeg passes its input through, which is all these tests need.
func fakeFFmpeg(t *testing.T) *Transcoder {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "ffmpeg")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexec cat\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	tr := New(bin, filepath.Join(t.TempDir(), "cache"), 2, 1<<20, slog.New(slog.DiscardHandler))
	if tr == nil {
		t.Fatal("no transcoder")
	}
	return tr
}

// source yields data, then fails with err (nil: ends normally).
type source struct {
	r   io.Reader
	err error
}

func (s *source) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if err == io.EOF && s.err != nil {
		return n, s.err
	}
	return n, err
}

func (s *source) Close() error { return nil }

func waitCached(t *testing.T, tr *Transcoder, key string) []byte {
	t.Helper()
	for range 200 {
		if f, ok := tr.Cached(key); ok {
			defer f.Close()
			b, _ := io.ReadAll(f)
			return b
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil
}

func TestConversionCompletes(t *testing.T) {
	tr := fakeFFmpeg(t)
	data := bytes.Repeat([]byte("music "), 50000)
	out, ok := tr.Start(&source{r: bytes.NewReader(data)}, "aac-256", "k1")
	if !ok {
		t.Fatal("not started")
	}
	got, err := io.ReadAll(out)
	out.Close()
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("read %d bytes, err %v; want %d", len(got), err, len(data))
	}
	if c := waitCached(t, tr, "k1"); !bytes.Equal(c, data) {
		t.Errorf("cached %d bytes, want %d", len(c), len(data))
	}
}

// A media server that hangs up mid-file must not produce a shorter track
// that plays as if complete, nor one kept in the cache.
func TestSourceBreakingOffFails(t *testing.T) {
	tr := fakeFFmpeg(t)
	data := bytes.Repeat([]byte("music "), 50000)
	out, ok := tr.Start(&source{r: bytes.NewReader(data[:100000]), err: errors.New("connection reset")}, "aac-256", "k2")
	if !ok {
		t.Fatal("not started")
	}
	_, err := io.ReadAll(out)
	out.Close()
	if err == nil {
		t.Fatal("a cut-short source read to a clean end")
	}
	time.Sleep(100 * time.Millisecond)
	if _, ok := tr.Cached("k2"); ok {
		t.Error("cut-short conversion was cached")
	}
}

// A listener that drops out (mobile data) leaves the conversion running, so
// coming back finds it complete in the cache.
func TestConversionOutlivesListener(t *testing.T) {
	tr := fakeFFmpeg(t)
	data := bytes.Repeat([]byte("music "), 50000)
	out, ok := tr.Start(&source{r: bytes.NewReader(data)}, "aac-256", "k3")
	if !ok {
		t.Fatal("not started")
	}
	buf := make([]byte, 1000)
	if _, err := io.ReadFull(out, buf); err != nil {
		t.Fatal(err)
	}
	out.Close()
	if c := waitCached(t, tr, "k3"); !bytes.Equal(c, data) {
		t.Errorf("cached %d bytes, want %d", len(c), len(data))
	}
}

// A phone that comes back while the conversion is still running follows it
// from the start instead of starting a second one.
func TestRunningJoinsConversion(t *testing.T) {
	tr := fakeFFmpeg(t)
	data := bytes.Repeat([]byte("music "), 50000)
	pr, pw := io.Pipe()
	out, ok := tr.Start(pr, "aac-256", "k4")
	if !ok {
		t.Fatal("not started")
	}
	_, _ = pw.Write(data[:100000])
	out.Close() // the first listener drops out
	again, ok := tr.Running("k4")
	if !ok {
		t.Fatal("conversion not found running")
	}
	go func() {
		_, _ = pw.Write(data[100000:])
		pw.Close()
	}()
	got, err := io.ReadAll(again)
	again.Close()
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("read %d bytes, err %v; want %d", len(got), err, len(data))
	}
	if c := waitCached(t, tr, "k4"); !bytes.Equal(c, data) {
		t.Errorf("cached %d bytes, want %d", len(c), len(data))
	}
	if _, ok := tr.Running("k4"); ok {
		t.Error("still listed as running when done")
	}
}
