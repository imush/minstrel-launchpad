// Package transcode turns lossless audio into AAC for listening over mobile
// data, with ffmpeg. The app asks for it per request; lossy files and
// anything else pass through untouched.
//
// Output is an ADTS stream, so playback starts while ffmpeg is still
// working. Each finished conversion is kept for a while, so a replay, a
// resume or a seek is served from disk, with ranges.
package transcode

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Header is the request header the app sets to ask for a profile.
const Header = "X-Minstrel-Transcode"

// Profiles are what the app can ask for: AAC at a bitrate in kbit/s.
var Profiles = []string{"aac-128", "aac-192", "aac-256", "aac-320"}

// ContentType is what transcoded responses are served as.
const ContentType = "audio/aac"

// Bitrate returns the kbit/s of a profile, or false if it isn't one.
func Bitrate(profile string) (int, bool) {
	if !slices.Contains(Profiles, profile) {
		return 0, false
	}
	kbps, err := strconv.Atoi(strings.TrimPrefix(profile, "aac-"))
	return kbps, err == nil
}

// Lossless reports whether a media type is one worth converting: lossless
// formats ffmpeg can read from a pipe. Lossy files are already small, and
// MP4 (ALAC) can't be read from a pipe when its index is at the end.
func Lossless(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	switch mt {
	case "audio/flac", "audio/x-flac",
		"audio/wav", "audio/x-wav", "audio/wave", "audio/vnd.wave",
		"audio/aiff", "audio/x-aiff",
		"audio/dsf", "audio/x-dsf", "audio/dsd", "audio/x-dsd",
		"audio/ape", "audio/x-ape", "audio/x-monkeys-audio",
		"audio/wavpack", "audio/x-wavpack":
		return true
	}
	return false
}

// Transcoder runs ffmpeg and keeps what it made.
type Transcoder struct {
	ffmpeg string
	dir    string
	log    *slog.Logger
	// MaxBytes and MaxAge bound the kept conversions.
	// Zero MaxBytes keeps nothing.
	MaxBytes int64
	MaxAge   time.Duration

	slots chan struct{}
	mu    sync.Mutex
}

// New finds ffmpeg (a path, or a name looked up in PATH) and keeps up to
// cacheBytes of conversions in dir. At most parallel conversions run at
// once. It returns nil when there is no ffmpeg.
func New(ffmpeg, dir string, parallel int, cacheBytes int64, log *slog.Logger) *Transcoder {
	path, err := exec.LookPath(ffmpeg)
	if err != nil {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Error("transcode cache", "err", err)
		return nil
	}
	t := &Transcoder{
		ffmpeg: path, dir: dir, log: log,
		MaxBytes: cacheBytes, MaxAge: 7 * 24 * time.Hour,
		slots: make(chan struct{}, max(parallel, 1)),
	}
	t.trim()
	return t
}

// Path is the ffmpeg in use.
func (t *Transcoder) Path() string { return t.ffmpeg }

// Key names the conversion of the file at source to profile.
func Key(source, profile string) string {
	sum := sha256.Sum256([]byte(profile + " " + source))
	return hex.EncodeToString(sum[:16])
}

// Cached returns the finished conversion for key, if kept.
func (t *Transcoder) Cached(key string) (*os.File, bool) {
	f, err := os.Open(filepath.Join(t.dir, key+".aac"))
	if err != nil {
		return nil, false
	}
	now := time.Now()
	_ = os.Chtimes(f.Name(), now, now) // recently used: trimmed last
	return f, true
}

// Start converts src to profile, returning the output as it is produced.
// It returns false when all conversion slots are busy; the caller then
// serves the original. The conversion carries on to the end when the
// reader is closed early, so the result can be kept; src is closed when
// it's done.
func (t *Transcoder) Start(src io.ReadCloser, profile, key string) (io.ReadCloser, bool) {
	kbps, ok := Bitrate(profile)
	if !ok {
		return nil, false
	}
	select {
	case t.slots <- struct{}{}:
	default:
		return nil, false
	}
	tmp, err := os.CreateTemp(t.dir, "partial-*")
	if err != nil {
		<-t.slots
		t.log.Error("transcode cache", "err", err)
		return nil, false
	}
	// A track takes minutes at most; this only stops a stuck ffmpeg.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	cmd := exec.CommandContext(ctx, t.ffmpeg,
		"-hide_banner", "-loglevel", "error", "-nostdin",
		// At most 4 times playback speed: well ahead of the listener, without
		// taking a whole core of a small router or NAS for seconds at a time.
		"-readrate", "4",
		"-i", "pipe:0", "-map", "0:a:0", "-vn",
		// AAC tops out at 96 kHz and the phone needs no more than 48.
		"-af", "aformat=sample_fmts=fltp:sample_rates=44100|48000",
		"-c:a", "aac", "-b:a", strconv.Itoa(kbps)+"k", "-ac", "2",
		"-f", "adts", "pipe:1")
	stdin, err := cmd.StdinPipe()
	if err == nil {
		var out io.ReadCloser
		if out, err = cmd.StdoutPipe(); err == nil {
			var stderr strings.Builder
			cmd.Stderr = &stderr
			if err = cmd.Start(); err == nil {
				lowPriority(cmd.Process.Pid)
				pr, pw := io.Pipe()
				go func() {
					// Feed ffmpeg; it stops reading on errors.
					_, _ = io.Copy(stdin, src)
					stdin.Close()
					src.Close()
				}()
				go t.collect(cmd, cancel, out, tmp, pw, key, &stderr)
				return pr, true
			}
		}
	}
	cancel()
	tmp.Close()
	os.Remove(tmp.Name())
	<-t.slots
	t.log.Error("starting ffmpeg", "err", err)
	return nil, false
}

// collect copies ffmpeg's output to the client, while there is one, and to
// the cache file; a complete conversion is kept under key.
func (t *Transcoder) collect(cmd *exec.Cmd, cancel context.CancelFunc, out io.Reader, tmp *os.File, client *io.PipeWriter, key string, stderr *strings.Builder) {
	defer func() { <-t.slots }()
	defer cancel()
	buf := make([]byte, 64<<10)
	gone := false
	var werr error
	for {
		n, err := out.Read(buf)
		if n > 0 {
			if werr == nil {
				_, werr = tmp.Write(buf[:n])
			}
			if !gone {
				if _, err := client.Write(buf[:n]); err != nil {
					gone = true // the listener left; finish for the cache
				}
			}
		}
		if err != nil {
			break
		}
	}
	err := cmd.Wait()
	tmp.Close()
	if err == nil && werr == nil {
		if err := os.Rename(tmp.Name(), filepath.Join(t.dir, key+".aac")); err == nil {
			t.trim()
			client.Close()
			return
		}
	}
	os.Remove(tmp.Name())
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		t.log.Warn("transcoding failed", "err", err, "ffmpeg", msg)
		client.CloseWithError(errors.New("transcoding failed"))
		return
	}
	client.Close()
}

// trim drops conversions past MaxAge, then the least recently used until
// the rest fit in MaxBytes. Partial files left by a crash go too.
func (t *Transcoder) trim() {
	t.mu.Lock()
	defer t.mu.Unlock()
	entries, err := os.ReadDir(t.dir)
	if err != nil {
		return
	}
	type kept struct {
		path string
		size int64
		used time.Time
	}
	var files []kept
	var total int64
	now := time.Now()
	for _, e := range entries {
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		path := filepath.Join(t.dir, e.Name())
		partial := strings.HasPrefix(e.Name(), "partial-")
		if (partial && now.Sub(info.ModTime()) > time.Hour) || (!partial && now.Sub(info.ModTime()) > t.MaxAge) {
			os.Remove(path)
			continue
		}
		if !partial {
			files = append(files, kept{path, info.Size(), info.ModTime()})
			total += info.Size()
		}
	}
	slices.SortFunc(files, func(a, b kept) int { return a.used.Compare(b.used) })
	for _, f := range files {
		if total <= t.MaxBytes {
			break
		}
		if err := os.Remove(f.path); err == nil || errors.Is(err, fs.ErrNotExist) {
			total -= f.size
		}
	}
}
